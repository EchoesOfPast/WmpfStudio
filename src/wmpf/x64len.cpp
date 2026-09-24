#include "x64len.h"

#include <stdio.h>
#include <string.h>

typedef signed char s8;

enum {
    IMM_NONE = 0,
    IMM_8 = 1,
    IMM_16 = 2,
    IMM_32 = 4,
    IMM_64 = 8,
    IMM_REL8 = -1,
    IMM_REL32 = -2,
    IMM_MOFFS = -3,    /* 8-byte absolute address in 64-bit mode */
    IMM_ENTER = -4,    /* enter: imm16 + imm8 */
    IMM_64OR32 = -5,   /* REX.W ? imm64 : imm32 */
    IMM_GRP3_8 = -6,   /* F6 /0 /1 with imm8 */
    IMM_GRP3_32 = -7,  /* F7 /0 /1 with imm32 */
    IMM_INVALID = -8,
    IMM_UNSUPPORTED = -9
};

typedef struct {
    unsigned char modrm;
    s8 imm;
} OpInfo;

#define OP_M(k) {1, (k)}
#define OP_N(k) {0, (k)}

static const OpInfo kTable1[256] = {
    /* 00-07 */ OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE),
                OP_N(IMM_8),    OP_N(IMM_32),   OP_N(IMM_INVALID), OP_N(IMM_INVALID),
    /* 08-0F */ OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE),
                OP_N(IMM_8),    OP_N(IMM_32),   OP_N(IMM_INVALID), OP_N(IMM_UNSUPPORTED),
    /* 10-17 */ OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE),
                OP_N(IMM_8),    OP_N(IMM_32),   OP_N(IMM_INVALID), OP_N(IMM_INVALID),
    /* 18-1F */ OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE),
                OP_N(IMM_8),    OP_N(IMM_32),   OP_N(IMM_UNSUPPORTED), OP_N(IMM_INVALID),
    /* 20-27 */ OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE),
                OP_N(IMM_8),    OP_N(IMM_32),   OP_N(IMM_UNSUPPORTED), OP_N(IMM_INVALID),
    /* 28-2F */ OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE),
                OP_N(IMM_8),    OP_N(IMM_32),   OP_N(IMM_UNSUPPORTED), OP_N(IMM_INVALID),
    /* 30-37 */ OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE),
                OP_N(IMM_8),    OP_N(IMM_32),   OP_N(IMM_UNSUPPORTED), OP_N(IMM_INVALID),
    /* 38-3F */ OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE),
                OP_N(IMM_8),    OP_N(IMM_32),   OP_N(IMM_UNSUPPORTED), OP_N(IMM_INVALID),
    /* 40-47 REX */ OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED),
                     OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED),
    /* 48-4F REX */ OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED),
                     OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED),
    /* 50-57 push r64 */ OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE),
                          OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE),
    /* 58-5F pop r64 */  OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE),
                          OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE),
    /* 60-67 */ OP_N(IMM_INVALID), OP_N(IMM_INVALID), OP_N(IMM_UNSUPPORTED), OP_M(IMM_NONE),
                OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED),
    /* 68-6F */ OP_N(IMM_32), OP_M(IMM_32), OP_N(IMM_8), OP_M(IMM_8),
                OP_N(IMM_INVALID), OP_N(IMM_INVALID), OP_N(IMM_INVALID), OP_N(IMM_INVALID),
    /* 70-77 jcc rel8 */ OP_N(IMM_REL8), OP_N(IMM_REL8), OP_N(IMM_REL8), OP_N(IMM_REL8),
                          OP_N(IMM_REL8), OP_N(IMM_REL8), OP_N(IMM_REL8), OP_N(IMM_REL8),
    /* 78-7F */ OP_N(IMM_REL8), OP_N(IMM_REL8), OP_N(IMM_REL8), OP_N(IMM_REL8),
                OP_N(IMM_REL8), OP_N(IMM_REL8), OP_N(IMM_REL8), OP_N(IMM_REL8),
    /* 80-87 */ OP_M(IMM_8), OP_M(IMM_32), OP_N(IMM_INVALID), OP_M(IMM_8),
                OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE),
    /* 88-8F */ OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE),
                OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE),
    /* 90-97 */ OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE),
                OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE),
    /* 98-9F */ OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE),
                OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE),
    /* A0-A7 */ OP_N(IMM_MOFFS), OP_N(IMM_MOFFS), OP_N(IMM_MOFFS), OP_N(IMM_MOFFS),
                OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE),
    /* A8-AF */ OP_N(IMM_8), OP_N(IMM_32), OP_N(IMM_NONE), OP_N(IMM_NONE),
                OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE),
    /* B0-B7 mov r8,imm8 */ OP_N(IMM_8), OP_N(IMM_8), OP_N(IMM_8), OP_N(IMM_8),
                            OP_N(IMM_8), OP_N(IMM_8), OP_N(IMM_8), OP_N(IMM_8),
    /* B8-BF mov r,imm */   OP_N(IMM_64OR32), OP_N(IMM_64OR32), OP_N(IMM_64OR32), OP_N(IMM_64OR32),
                            OP_N(IMM_64OR32), OP_N(IMM_64OR32), OP_N(IMM_64OR32), OP_N(IMM_64OR32),
    /* C0-C7 */ OP_M(IMM_8), OP_M(IMM_8), OP_N(IMM_16), OP_N(IMM_NONE),
                OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED), OP_M(IMM_8), OP_M(IMM_32),
    /* C8-CF */ OP_N(IMM_ENTER), OP_N(IMM_NONE), OP_N(IMM_16), OP_N(IMM_NONE),
                OP_N(IMM_NONE), OP_N(IMM_8), OP_N(IMM_INVALID), OP_N(IMM_NONE),
    /* D0-D7 */ OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE),
                OP_N(IMM_INVALID), OP_N(IMM_INVALID), OP_N(IMM_INVALID), OP_N(IMM_NONE),
    /* D8-DF x87 */ OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE),
                    OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE),
    /* E0-E7 */ OP_N(IMM_REL8), OP_N(IMM_REL8), OP_N(IMM_REL8), OP_N(IMM_REL8),
                OP_N(IMM_8), OP_N(IMM_8), OP_N(IMM_8), OP_N(IMM_8),
    /* E8-EF */ OP_N(IMM_REL32), OP_N(IMM_REL32), OP_N(IMM_INVALID), OP_N(IMM_REL8),
                OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE),
    /* F0-F7 */ OP_N(IMM_UNSUPPORTED), OP_N(IMM_NONE), OP_N(IMM_UNSUPPORTED), OP_N(IMM_UNSUPPORTED),
                OP_N(IMM_NONE), OP_N(IMM_NONE), OP_M(IMM_GRP3_8), OP_M(IMM_GRP3_32),
    /* F8-FF */ OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE), OP_N(IMM_NONE),
                OP_N(IMM_NONE), OP_N(IMM_NONE), OP_M(IMM_NONE), OP_M(IMM_NONE)
};

static OpInfo table2(unsigned char op2) {
    switch (op2) {
        case 0x05: case 0x06: case 0x07: case 0x08: case 0x09: case 0x0B:
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35:
        case 0x37: case 0x77: case 0xA0: case 0xA1: case 0xA2: case 0xA8:
        case 0xA9: case 0xAA:
            return (OpInfo)OP_N(IMM_NONE);
        default:
            break;
    }
    if (op2 >= 0xC8 && op2 <= 0xCF)
        return (OpInfo)OP_N(IMM_NONE); /* bswap */
    if (op2 >= 0x80 && op2 <= 0x8F)
        return (OpInfo)OP_N(IMM_REL32); /* jcc rel32 */
    if (op2 == 0x38 || op2 == 0x3A)
        return (OpInfo)OP_N(IMM_UNSUPPORTED); /* three-byte map, conservatively reject */
    switch (op2) {
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0xA4: case 0xAC:
        case 0xBA:
        case 0xC2: case 0xC4: case 0xC5: case 0xC6:
            return (OpInfo)OP_M(IMM_8);
        default:
            break;
    }
    if ((op2 >= 0x10 && op2 <= 0x1F) || (op2 >= 0x28 && op2 <= 0x2F) ||
        (op2 >= 0x40 && op2 <= 0x6F) || (op2 >= 0x74 && op2 <= 0x76) ||
        (op2 >= 0x78 && op2 <= 0x79) || (op2 >= 0x7C && op2 <= 0x7F) ||
        (op2 >= 0x90 && op2 <= 0x9F) || op2 == 0xA3 || op2 == 0xA5 ||
        (op2 >= 0xAB && op2 <= 0xAF) || (op2 >= 0xB0 && op2 <= 0xB9) ||
        (op2 >= 0xBB && op2 <= 0xC1) || op2 == 0xC3 || op2 == 0xC7 ||
        (op2 >= 0xD0 && op2 <= 0xFF))
        return (OpInfo)OP_M(IMM_NONE);
    return (OpInfo)OP_N(IMM_UNSUPPORTED);
}

/* Parse ModRM(/SIB/disp), return the byte count of this part; also report whether it contains RIP-relative addressing */
static int modrm_extra(const unsigned char *p, int avail, int *rip_rel, int *bad) {
    int mod, rm, len = 1;
    *rip_rel = 0;
    *bad = 0;
    if (avail < 1) {
        *bad = 1;
        return 0;
    }
    mod = p[0] >> 6;
    rm = p[0] & 7;
    if (mod == 3)
        return len;
    if (rm == 4) { /* has SIB */
        if (avail < 2) {
            *bad = 1;
            return len;
        }
        len += 1;
        if ((p[1] & 7) == 5 && mod == 0)
            len += 4; /* no base -> disp32 absolute addressing */
    }
    if (mod == 0) {
        if (rm == 5) {
            *rip_rel = 1; /* in 64-bit: mod=00,rm=101 = RIP+disp32 */
            len += 4;
        }
    } else if (mod == 1) {
        len += 1;
    } else {
        len += 4;
    }
    return len;
}

const char *x64_reason_text(X64Reason r) {
    switch (r) {
        case X64_OK: return "OK";
        case X64_BAD_OPCODE: return "操作码在 64 位模式下无效";
        case X64_UNSUPPORTED_OPCODE: return "操作码未支持（VEX/EVEX 或三字节 map）";
        case X64_TRUNCATED: return "指令字节被截断";
        case X64_RIP_RELATIVE: return "含 RIP 相对寻址，搬移后必须修正位移";
        case X64_REL_BRANCH: return "含 rel8/rel32 相对跳转或调用，搬移后目标会错";
        case X64_PREFIX_67: return "含 0x67 地址长度前缀";
        case X64_PREFIX_66: return "含 0x66 操作数长度前缀，立即数宽度不确定";
        case X64_TOO_LONG: return "指令条数异常";
        default: return "未知原因";
    }
}

int x64_decode(const unsigned char *p, int max_len, X64Insn *out) {
    int i = 0, saw66 = 0, saw67 = 0, rexW = 0, modrm_off = -1, imm_len = 0;
    unsigned char op;
    OpInfo info;

    out->length = 0;
    out->has_modrm = 0;
    out->reason = X64_OK;
    if (max_len < 1)
        return 0;

    for (;;) {
        unsigned char b;
        if (i >= max_len) {
            out->reason = X64_TRUNCATED;
            return 0;
        }
        b = p[i];
        if (b == 0x66) {
            saw66 = 1;
            ++i;
        } else if (b == 0x67) {
            saw67 = 1;
            ++i;
        } else if (b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 ||
                   b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) {
            ++i;
        } else {
            break;
        }
    }
    if (saw67) {
        out->reason = X64_PREFIX_67;
        return 0;
    }
    if (saw66) {
        out->reason = X64_PREFIX_66;
        return 0;
    }
    if (i < max_len && p[i] >= 0x40 && p[i] <= 0x4F) {
        rexW = (p[i] & 0x08) != 0;
        ++i;
    }
    if (i >= max_len) {
        out->reason = X64_TRUNCATED;
        return 0;
    }
    op = p[i];
    ++i;

    if (op == 0x0F) {
        if (i >= max_len) {
            out->reason = X64_TRUNCATED;
            return 0;
        }
        info = table2(p[i]);
        ++i;
    } else {
        info = kTable1[op];
    }

    if (info.imm == IMM_INVALID) {
        out->reason = X64_BAD_OPCODE;
        return 0;
    }
    if (info.imm == IMM_UNSUPPORTED) {
        out->reason = X64_UNSUPPORTED_OPCODE;
        return 0;
    }

    if (info.modrm) {
        int rip = 0, bad = 0, extra;
        modrm_off = i;
        extra = modrm_extra(p + i, max_len - i, &rip, &bad);
        if (bad) {
            out->reason = X64_TRUNCATED;
            return 0;
        }
        if (rip) {
            out->reason = X64_RIP_RELATIVE;
            return 0;
        }
        i += extra;
        out->has_modrm = 1;
    }

    switch (info.imm) {
        case IMM_NONE: imm_len = 0; break;
        case IMM_8: imm_len = 1; break;
        case IMM_16: imm_len = 2; break;
        case IMM_32: imm_len = 4; break;
        case IMM_64: imm_len = 8; break;
        case IMM_MOFFS: imm_len = 8; break;
        case IMM_ENTER: imm_len = 3; break;
        case IMM_64OR32: imm_len = rexW ? 8 : 4; break;
        case IMM_GRP3_8:
            imm_len = (modrm_off >= 0 && ((p[modrm_off] >> 3) & 7) <= 1) ? 1 : 0;
            break;
        case IMM_GRP3_32:
            imm_len = (modrm_off >= 0 && ((p[modrm_off] >> 3) & 7) <= 1) ? 4 : 0;
            break;
        case IMM_REL8:
        case IMM_REL32:
            out->reason = X64_REL_BRANCH;
            return 0;
        default: imm_len = 0; break;
    }
    i += imm_len;

    if (i > max_len) {
        out->reason = X64_TRUNCATED;
        return 0;
    }
    out->length = i;
    return 1;
}

int x64_measure_displacement(const unsigned char *p, int max_len, int need, int *displaced_len,
                             int *count, char *why, int why_len) {
    int total = 0, n = 0;
    while (total < need) {
        X64Insn ins;
        if (!x64_decode(p + total, max_len - total, &ins)) {
            if (why && why_len > 0)
                snprintf(why, (size_t)why_len, "偏移 +%d 处：%s", total,
                         x64_reason_text(ins.reason));
            return 0;
        }
        total += ins.length;
        ++n;
        if (n > 16) {
            if (why && why_len > 0)
                snprintf(why, (size_t)why_len, "%s", x64_reason_text(X64_TOO_LONG));
            return 0;
        }
    }
    if (displaced_len)
        *displaced_len = total;
    if (count)
        *count = n;
    return 1;
}
