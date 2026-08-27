// WebKit ROP gadgets — PS4 FW 13.50
// Source: libSceNKWebKit.sprx.decrypted (68 MB), radare2 6.1.9
// Imported from user-supplied webkit_gadgets_1350.js
//
// Pop-gadget RVAs verified by byte search. Does NOT include Poops anchor
// (wk_expm1_builtin), IAT (wk___imp___error), or chain-specific call gadgets —
// use calibrate (step 3) or BinDiff from 13.00 for those.

export const webkit_gadgets_1350 = {
    wk_RET:          0x3cbc51b,
    wk_LEAVE_RET:    0x182f7,
    wk_POP_RAX_RET:  0x10504,
    wk_POP_RBX_RET:  0x79e8,
    wk_POP_RCX_RET:  0x1bade,
    wk_POP_RDI_RET:  0x5c480,
    wk_POP_RDX_RET:  0x12c5ba,
    wk_POP_RSI_RET:  0x6e45e,
    wk_POP_RBP_RET:  0x3ccc7a2,
    wk_POP_RSP_RET:  0x3cbc51a,
    wk_POP_R8_RET:   0x5c47f,
    wk_POP_R9_RET:   0x9db883,
    wk_POP_R10_RET:  0x2dbf3b5,
    wk_POP_R11_RET:  0x1989ba,
    wk_POP_R12_RET:  0x2426b15,
    wk_POP_R13_RET:  0x5c47b,
    wk_POP_R14_RET:  0xa5e91,
    wk_POP_R15_RET:  0x5c47f,
};

// Kernel (midohar36 dump, same row as 13.00–13.04 per source notes):
//   PRISON0   0x111fa18
//   ROOTVNODE 0x2136e90
