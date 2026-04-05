/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3 */

#ifndef CS_SBPF_DISASSEMBLER_H
#define CS_SBPF_DISASSEMBLER_H

#include "../../MCInst.h"

typedef struct sbpf_internal {
	uint16_t op;
	int64_t imm;
	uint8_t dst;
	uint8_t src;
	int16_t offset;
	uint8_t insn_size;
} sbpf_internal;

bool SBPF_getInstruction(csh ud, const uint8_t *code, size_t code_len,
			 MCInst *instr, uint16_t *size, uint64_t address,
			 void *info);

#endif
