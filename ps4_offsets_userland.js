// WebKit (userland) RVAs only — no kernel gadgets, stubs, or patch metadata.
// Copied from webkit/ps4_offsets.js. Kernel half of the full chain is omitted.

export const PS4 = {
    "13.00": {
        fw_status: "userland-only — proven on hardware (full chain)",
        wk_expm1_builtin:                 0x2586880,
        wk_JSFunction_m_function:         0x28,
        wk___imp___error:                 0x3cb8cc8,
        k__error:                         0x26420,
        wk_ArrayBuffer_m_impl:            0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
    },
    "12.50": {
        fw_status: "userland-only — UNTESTED; webkit RVAs from 12.50 module dump",
        wk_expm1_builtin:                 0x2585110,
        wk_JSFunction_m_function:         0x28,
        wk___imp___error:                 0x3cb4c48,
        k__error:                         0xd9d0,
        wk_ArrayBuffer_m_impl:            0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
    },
    "12.00": {
        fw_status: "userland-only — UNTESTED",
        wk_expm1_builtin:                 0x2585090,
        wk_JSFunction_m_function:         0x28,
        wk___imp___error:                 0x3cb4c48,
        k__error:                         0xd9d0,
        wk_ArrayBuffer_m_impl:            0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
    },
    "11.50": {
        fw_status: "userland-only — UNTESTED",
        wk_expm1_builtin:                 0x2587bd0,
        wk_JSFunction_m_function:         0x28,
        wk___imp___error:                 0x36e1c68,
        k__error:                         0x3370,
        wk_ArrayBuffer_m_impl:            0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
    },
    "11.00": {
        fw_status: "userland-only — UNTESTED",
        wk_expm1_builtin:                 0x2193f30,
        wk_JSFunction_m_function:         0x28,
        wk___imp___error:                 0x36e1c68,
        k__error:                         0x3370,
        wk_ArrayBuffer_m_impl:            0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
    },
};

PS4["12.02"] = Object.assign({}, PS4["12.00"], {
    alias_of: "12.00",
    fw_status: "userland-only — shares 12.00 webkit RVAs",
});
PS4["12.52"] = Object.assign({}, PS4["12.50"], {
    alias_of: "12.50",
    fw_status: "userland-only — shares 12.50 webkit RVAs (no 12.52 dump)",
});

// 13.52: add wk_* from your libSceNKWebKit.sprx dump before running BASES check.
// PS4["13.52"] = { ... };

export function offsetsFor(uaString) {
    const m = (uaString || "").match(/PlayStation\s+4[\/ ](\d+)\.(\d+)/);
    if (!m) return { key: null, off: null };

    const key = m[1] + "." + parseInt(m[2], 16).toString(16).padStart(2, "0");
    return { key, off: PS4[key] || null };
}

export function offsetsForKey(key) {
    return { key, off: PS4[key] || null };
}
