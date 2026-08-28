// WebKit (userland) RVAs only — no kernel gadgets, stubs, or patch metadata.
// 13.50 pop RVAs inlined from webkit_gadgets_1350.js (no extra import — PS4 browser).

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
    "13.50": {
        fw_status: "pop gadgets from webkit_gadgets_1350.js (radare2); "
            + "anchor/imp assumed 13.00 — run calibrate on 13.52 hardware",
        wk_expm1_builtin:                 0x2586880,
        wk_JSFunction_m_function:         0x28,
        wk___imp___error:                 0x3cb8cc8,
        k__error:                         0x26420,
        wk_ArrayBuffer_m_impl:            0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
        wk_POP_RDI_RET:                     0x5c480,
        wk_POP_RSI_RET:                     0x6e45e,
        wk_POP_RDX_RET:                     0x12c5ba,
        wk_POP_RCX_RET:                     0x1bade,
        wk_POP_RAX_RET:                     0x10504,
        wk_POP_R8_RET:                      0x5c47f,
        wk_POP_R9_RET:                      0x9db883,
        wk_LEAVE_RET:                       0x182f7,
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

// 13.52 retail: expm1 + pop gadgets HW-confirmed.
// libkernel IAT/stubs from 13.00 (verify on HW). Pivot RVAs NOT baked — scan or paste after verify.
const LIBKERNEL_1300 = {
    wk___imp___error:                   0x3cb8cc8,
    k__error:                           0x26420,
    k_scan_stage1:                      0x40000,
    k_stubs: {
        20: 0x2cb70,
        24: 0x2d5e0,
    },
};

PS4["13.52"] = Object.assign({}, PS4["13.50"], LIBKERNEL_1300, {
    fw_status: "13.52 HW pop + pivot G0-G5 (7/7)",
    wk_expm1_builtin:                 0xeb6350,
    wk_POP_RDI_RET:                     0x4be55,
    wk_POP_RSI_RET:                     0x7acb3,
    wk_POP_RDX_RET:                     0x30b1e9,
    wk_POP_RCX_RET:                     0xeaf246,
    wk_POP_RAX_RET:                     0x3424a,
    wk_POP_R8_RET:                      0x5d185,
    wk_POP_R9_RET:                      0x9b288b,
    wk_LEAVE_RET:                       0xf195b,
    wk_MOV_QWORD_PTR_RDI_RAX_RET:       0x1f9bb,
    wk_MOV_RDI_RSI_30_CALL:             0xe3e4a,
    wk_POP_RAX_MOV_RAX_JMP_18:          0x4b330,
    wk_PUSH_RBP_MOV_RBP_RSP_10:         0x1ff70,
    wk_MOV_RDI_RAX_8_CALL_20:           0x16e02,
    wk_MOV_RDX_RAX_18_CALL_10:          0x589c1,
    wk_PUSH_RDX_POP_RSP_RET:            0x13ec77a,
    pivot_view_sp:                      0x38,
    k_jmp_rsi: 0x4d6d0,
    k_kl_lock: 0xe6c60,
});

PS4["13.04"] = Object.assign({}, PS4["13.50"], {
    alias_of: "13.50",
    fw_status: "userland-only — shares 13.50 webkit (BinDiff to 13.04 if gadgets moved)",
});

export function offsetsFor(uaString) {
    const m = (uaString || "").match(/PlayStation\s+4[\/ ](\d+)\.(\d+)/);
    if (!m) return { key: null, off: null };

    const key = m[1] + "." + parseInt(m[2], 10).toString(10).padStart(2, "0");
    return { key, off: PS4[key] || null };
}

export function offsetsForKey(key) {
    return { key, off: PS4[key] || null };
}
