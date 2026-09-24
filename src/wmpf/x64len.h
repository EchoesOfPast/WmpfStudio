/* x64len.h -- x86-64 instruction length decoder (pure C, no Qt / stdlib container dependency)
 *
 * Used by both the main program and the injected hook DLL, so it must remain zero-dependency:
 * the hook DLL runs inside the WeChat process, where there is no Qt6Core.dll.
 *
 * Design principle: fail-closed. Instructions with RIP-relative addressing, rel8/rel32
 * relative branches, 0x66/0x67 prefixes, VEX/EVEX, or three-byte map opcodes are all
 * judged as non-displaceable — never guess. The cost of a wrong guess is a WeChat crash.
 */
#ifndef FZWY_X64LEN_H
#define FZWY_X64LEN_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum X64Reason {
    X64_OK = 0,
    X64_BAD_OPCODE,         /* opcode invalid in 64-bit mode */
    X64_UNSUPPORTED_OPCODE, /* VEX/EVEX or three-byte map etc. not supported */
    X64_TRUNCATED,          /* instruction bytes truncated */
    X64_RIP_RELATIVE,       /* contains RIP-relative addressing */
    X64_REL_BRANCH,         /* contains rel8/rel32 relative jump or call */
    X64_PREFIX_67,          /* address-size prefix */
    X64_PREFIX_66,          /* operand-size prefix */
    X64_TOO_LONG            /* abnormal instruction count */
} X64Reason;

typedef struct X64Insn {
    int length;         /* total instruction byte count; 0 means decode failure */
    int has_modrm;
    X64Reason reason;   /* failure reason (X64_OK means success) */
} X64Insn;

/* Decode one instruction at p, reading at most max_len bytes. Returns 1 on success / 0 on failure */
int x64_decode(const unsigned char *p, int max_len, X64Insn *out);

/* Decode instructions starting at p until the cumulative length >= need.
 * Returns 1 on success; *displaced_len is the number of bytes to displace (>= need),
 * *count is the instruction count.
 * Returns 0 on failure; reason is written to why (why_len is the buffer size). */
int x64_measure_displacement(const unsigned char *p, int max_len, int need, int *displaced_len,
                             int *count, char *why, int why_len);

const char *x64_reason_text(X64Reason r);

#ifdef __cplusplus
}
#endif

#endif /* FZWY_X64LEN_H */
