/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3 */

#ifndef CAPSTONE_SBPF_H
#define CAPSTONE_SBPF_H

#ifdef __cplusplus
extern "C" {
#endif

#include "platform.h"

#ifdef _MSC_VER
#pragma warning(disable : 4201)
#endif

#define NUM_SBPF_OPS 3

typedef enum sbpf_op_type {
	SBPF_OP_INVALID = 0,
	SBPF_OP_REG = 1,
	SBPF_OP_IMM = 2,
	SBPF_OP_OFF = 0x10,
	SBPF_OP_MEM = 0x80,
} sbpf_op_type;

typedef enum sbpf_reg {
	SBPF_REG_INVALID = 0,

	SBPF_REG_R0,
	SBPF_REG_R1,
	SBPF_REG_R2,
	SBPF_REG_R3,
	SBPF_REG_R4,
	SBPF_REG_R5,
	SBPF_REG_R6,
	SBPF_REG_R7,
	SBPF_REG_R8,
	SBPF_REG_R9,
	SBPF_REG_R10,

	SBPF_REG_ENDING,
} sbpf_reg;

typedef struct sbpf_op_mem {
	sbpf_reg base;
	int32_t disp;
} sbpf_op_mem;

typedef struct cs_sbpf_op {
	sbpf_op_type type;
	union {
		uint8_t reg;
		int64_t imm;
		int32_t off;
		sbpf_op_mem mem;
	};

	bool is_signed;
	uint8_t access;
} cs_sbpf_op;

typedef struct cs_sbpf {
	uint8_t op_count;
	cs_sbpf_op operands[4];
} cs_sbpf;

typedef enum sbpf_insn {
	SBPF_INS_INVALID = 0,

	SBPF_INS_ADD32,
	SBPF_INS_SUB32,
	SBPF_INS_MUL32,
	SBPF_INS_DIV32,
	SBPF_INS_OR32,
	SBPF_INS_AND32,
	SBPF_INS_LSH32,
	SBPF_INS_RSH32,
	SBPF_INS_NEG32,
	SBPF_INS_MOD32,
	SBPF_INS_XOR32,
	SBPF_INS_MOV32,
	SBPF_INS_ARSH32,

	SBPF_INS_ADD64,
	SBPF_INS_SUB64,
	SBPF_INS_MUL64,
	SBPF_INS_DIV64,
	SBPF_INS_OR64,
	SBPF_INS_AND64,
	SBPF_INS_LSH64,
	SBPF_INS_RSH64,
	SBPF_INS_NEG64,
	SBPF_INS_MOD64,
	SBPF_INS_XOR64,
	SBPF_INS_MOV64,
	SBPF_INS_ARSH64,

	SBPF_INS_LE16,
	SBPF_INS_LE32,
	SBPF_INS_LE64,
	SBPF_INS_BE16,
	SBPF_INS_BE32,
	SBPF_INS_BE64,

	SBPF_INS_LDDW,
	SBPF_INS_LDXB,
	SBPF_INS_LDXH,
	SBPF_INS_LDXW,
	SBPF_INS_LDXDW,

	SBPF_INS_STB,
	SBPF_INS_STH,
	SBPF_INS_STW,
	SBPF_INS_STDW,
	SBPF_INS_STXB,
	SBPF_INS_STXH,
	SBPF_INS_STXW,
	SBPF_INS_STXDW,

	SBPF_INS_JA,
	SBPF_INS_JEQ,
	SBPF_INS_JGT,
	SBPF_INS_JGE,
	SBPF_INS_JSET,
	SBPF_INS_JNE,
	SBPF_INS_JSGT,
	SBPF_INS_JSGE,
	SBPF_INS_JLT,
	SBPF_INS_JLE,
	SBPF_INS_JSLT,
	SBPF_INS_JSLE,
	SBPF_INS_CALL,
	SBPF_INS_EXIT,

	SBPF_INS_ENDING,
} sbpf_insn;

typedef enum sbpf_insn_group {
	SBPF_GRP_INVALID = 0,

	SBPF_GRP_LOAD,
	SBPF_GRP_STORE,
	SBPF_GRP_ALU,
	SBPF_GRP_JUMP,
	SBPF_GRP_CALL,
	SBPF_GRP_RETURN,

	SBPF_GRP_ENDING,
} sbpf_insn_group;

#ifdef __cplusplus
}
#endif

#endif
