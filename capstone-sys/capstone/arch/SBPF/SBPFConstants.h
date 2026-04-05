/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3 */

#ifndef CS_SBPF_CONSTANTS_H
#define CS_SBPF_CONSTANTS_H

#define SBPF_CLASS(code) ((code) & 0x07)

#define SBPF_CLASS_LD 0x00
#define SBPF_CLASS_LDX 0x01
#define SBPF_CLASS_ST 0x02
#define SBPF_CLASS_STX 0x03
#define SBPF_CLASS_ALU32 0x04
#define SBPF_CLASS_JMP 0x05
#define SBPF_CLASS_ALU64 0x07

#define SBPF_OP(code) ((code) & 0xf0)

#define SBPF_ALU_ADD 0x00
#define SBPF_ALU_SUB 0x10
#define SBPF_ALU_MUL 0x20
#define SBPF_ALU_DIV 0x30
#define SBPF_ALU_OR 0x40
#define SBPF_ALU_AND 0x50
#define SBPF_ALU_LSH 0x60
#define SBPF_ALU_RSH 0x70
#define SBPF_ALU_NEG 0x80
#define SBPF_ALU_MOD 0x90
#define SBPF_ALU_XOR 0xa0
#define SBPF_ALU_MOV 0xb0
#define SBPF_ALU_ARSH 0xc0
#define SBPF_ALU_END 0xd0

#define SBPF_JUMP_JA 0x00
#define SBPF_JUMP_JEQ 0x10
#define SBPF_JUMP_JGT 0x20
#define SBPF_JUMP_JGE 0x30
#define SBPF_JUMP_JSET 0x40
#define SBPF_JUMP_JNE 0x50
#define SBPF_JUMP_JSGT 0x60
#define SBPF_JUMP_JSGE 0x70
#define SBPF_JUMP_CALL 0x80
#define SBPF_JUMP_EXIT 0x90
#define SBPF_JUMP_JLT 0xa0
#define SBPF_JUMP_JLE 0xb0
#define SBPF_JUMP_JSLT 0xc0
#define SBPF_JUMP_JSLE 0xd0

#define SBPF_SRC(code) ((code) & 0x08)
#define SBPF_SRC_K 0x00
#define SBPF_SRC_X 0x08

#define SBPF_SRC_LITTLE SBPF_SRC_K
#define SBPF_SRC_BIG SBPF_SRC_X

#define SBPF_SIZE(code) ((code) & 0x18)
#define SBPF_SIZE_W 0x00
#define SBPF_SIZE_H 0x08
#define SBPF_SIZE_B 0x10
#define SBPF_SIZE_DW 0x18

#define SBPF_MODE(code) ((code) & 0xe0)
#define SBPF_MODE_IMM 0x00
#define SBPF_MODE_MEM 0x60

#define SBPF_OP_LDDW 0x18

#define SBPF_OP_LDXW 0x61
#define SBPF_OP_LDXH 0x69
#define SBPF_OP_LDXB 0x71
#define SBPF_OP_LDXDW 0x79

#define SBPF_OP_STW 0x62
#define SBPF_OP_STH 0x6a
#define SBPF_OP_STB 0x72
#define SBPF_OP_STDW 0x7a

#define SBPF_OP_STXW 0x63
#define SBPF_OP_STXH 0x6b
#define SBPF_OP_STXB 0x73
#define SBPF_OP_STXDW 0x7b

#define SBPF_OP_JA 0x05
#define SBPF_OP_JEQ_IMM 0x15
#define SBPF_OP_JEQ_REG 0x1d
#define SBPF_OP_JGT_IMM 0x25
#define SBPF_OP_JGT_REG 0x2d
#define SBPF_OP_JGE_IMM 0x35
#define SBPF_OP_JGE_REG 0x3d
#define SBPF_OP_JSET_IMM 0x45
#define SBPF_OP_JSET_REG 0x4d
#define SBPF_OP_JNE_IMM 0x55
#define SBPF_OP_JNE_REG 0x5d
#define SBPF_OP_JSGT_IMM 0x65
#define SBPF_OP_JSGT_REG 0x6d
#define SBPF_OP_JSGE_IMM 0x75
#define SBPF_OP_JSGE_REG 0x7d
#define SBPF_OP_JLT_IMM 0xa5
#define SBPF_OP_JLT_REG 0xad
#define SBPF_OP_JLE_IMM 0xb5
#define SBPF_OP_JLE_REG 0xbd
#define SBPF_OP_JSLT_IMM 0xc5
#define SBPF_OP_JSLT_REG 0xcd
#define SBPF_OP_JSLE_IMM 0xd5
#define SBPF_OP_JSLE_REG 0xdd
#define SBPF_OP_CALL 0x85
#define SBPF_OP_EXIT 0x95

#define SBPF_OP_LE 0xd4
#define SBPF_OP_BE 0xdc

#define SBPF_OP_ADD32_IMM 0x04
#define SBPF_OP_ADD32_REG 0x0c
#define SBPF_OP_SUB32_IMM 0x14
#define SBPF_OP_SUB32_REG 0x1c
#define SBPF_OP_MUL32_IMM 0x24
#define SBPF_OP_MUL32_REG 0x2c
#define SBPF_OP_DIV32_IMM 0x34
#define SBPF_OP_DIV32_REG 0x3c
#define SBPF_OP_OR32_IMM 0x44
#define SBPF_OP_OR32_REG 0x4c
#define SBPF_OP_AND32_IMM 0x54
#define SBPF_OP_AND32_REG 0x5c
#define SBPF_OP_LSH32_IMM 0x64
#define SBPF_OP_LSH32_REG 0x6c
#define SBPF_OP_RSH32_IMM 0x74
#define SBPF_OP_RSH32_REG 0x7c
#define SBPF_OP_NEG32 0x84
#define SBPF_OP_MOD32_IMM 0x94
#define SBPF_OP_MOD32_REG 0x9c
#define SBPF_OP_XOR32_IMM 0xa4
#define SBPF_OP_XOR32_REG 0xac
#define SBPF_OP_MOV32_IMM 0xb4
#define SBPF_OP_MOV32_REG 0xbc
#define SBPF_OP_ARSH32_IMM 0xc4
#define SBPF_OP_ARSH32_REG 0xcc

#define SBPF_OP_ADD64_IMM 0x07
#define SBPF_OP_ADD64_REG 0x0f
#define SBPF_OP_SUB64_IMM 0x17
#define SBPF_OP_SUB64_REG 0x1f
#define SBPF_OP_MUL64_IMM 0x27
#define SBPF_OP_MUL64_REG 0x2f
#define SBPF_OP_DIV64_IMM 0x37
#define SBPF_OP_DIV64_REG 0x3f
#define SBPF_OP_OR64_IMM 0x47
#define SBPF_OP_OR64_REG 0x4f
#define SBPF_OP_AND64_IMM 0x57
#define SBPF_OP_AND64_REG 0x5f
#define SBPF_OP_LSH64_IMM 0x67
#define SBPF_OP_LSH64_REG 0x6f
#define SBPF_OP_RSH64_IMM 0x77
#define SBPF_OP_RSH64_REG 0x7f
#define SBPF_OP_NEG64 0x87
#define SBPF_OP_MOD64_IMM 0x97
#define SBPF_OP_MOD64_REG 0x9f
#define SBPF_OP_XOR64_IMM 0xa7
#define SBPF_OP_XOR64_REG 0xaf
#define SBPF_OP_MOV64_IMM 0xb7
#define SBPF_OP_MOV64_REG 0xbf
#define SBPF_OP_ARSH64_IMM 0xc7
#define SBPF_OP_ARSH64_REG 0xcf

#endif
