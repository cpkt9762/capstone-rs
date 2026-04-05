/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3 */

#include <string.h>

#include "SBPFConstants.h"
#include "SBPFMapping.h"
#include "../../Mapping.h"
#include "../../utils.h"

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	{ SBPF_GRP_INVALID, NULL },
	{ SBPF_GRP_LOAD, "load" },
	{ SBPF_GRP_STORE, "store" },
	{ SBPF_GRP_ALU, "alu" },
	{ SBPF_GRP_JUMP, "jump" },
	{ SBPF_GRP_CALL, "call" },
	{ SBPF_GRP_RETURN, "return" },
};
#endif

const char *SBPF_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map insn_name_maps[SBPF_INS_ENDING] = {
	{ SBPF_INS_INVALID, NULL },

	{ SBPF_INS_ADD32, "add32" },
	{ SBPF_INS_SUB32, "sub32" },
	{ SBPF_INS_MUL32, "mul32" },
	{ SBPF_INS_DIV32, "div32" },
	{ SBPF_INS_OR32, "or32" },
	{ SBPF_INS_AND32, "and32" },
	{ SBPF_INS_LSH32, "lsh32" },
	{ SBPF_INS_RSH32, "rsh32" },
	{ SBPF_INS_NEG32, "neg32" },
	{ SBPF_INS_MOD32, "mod32" },
	{ SBPF_INS_XOR32, "xor32" },
	{ SBPF_INS_MOV32, "mov32" },
	{ SBPF_INS_ARSH32, "arsh32" },

	{ SBPF_INS_ADD64, "add64" },
	{ SBPF_INS_SUB64, "sub64" },
	{ SBPF_INS_MUL64, "mul64" },
	{ SBPF_INS_DIV64, "div64" },
	{ SBPF_INS_OR64, "or64" },
	{ SBPF_INS_AND64, "and64" },
	{ SBPF_INS_LSH64, "lsh64" },
	{ SBPF_INS_RSH64, "rsh64" },
	{ SBPF_INS_NEG64, "neg64" },
	{ SBPF_INS_MOD64, "mod64" },
	{ SBPF_INS_XOR64, "xor64" },
	{ SBPF_INS_MOV64, "mov64" },
	{ SBPF_INS_ARSH64, "arsh64" },

	{ SBPF_INS_LE16, "le16" },
	{ SBPF_INS_LE32, "le32" },
	{ SBPF_INS_LE64, "le64" },
	{ SBPF_INS_BE16, "be16" },
	{ SBPF_INS_BE32, "be32" },
	{ SBPF_INS_BE64, "be64" },

	{ SBPF_INS_LDDW, "lddw" },
	{ SBPF_INS_LDXB, "ldxb" },
	{ SBPF_INS_LDXH, "ldxh" },
	{ SBPF_INS_LDXW, "ldxw" },
	{ SBPF_INS_LDXDW, "ldxdw" },

	{ SBPF_INS_STB, "stb" },
	{ SBPF_INS_STH, "sth" },
	{ SBPF_INS_STW, "stw" },
	{ SBPF_INS_STDW, "stdw" },
	{ SBPF_INS_STXB, "stxb" },
	{ SBPF_INS_STXH, "stxh" },
	{ SBPF_INS_STXW, "stxw" },
	{ SBPF_INS_STXDW, "stxdw" },

	{ SBPF_INS_JA, "ja" },
	{ SBPF_INS_JEQ, "jeq" },
	{ SBPF_INS_JGT, "jgt" },
	{ SBPF_INS_JGE, "jge" },
	{ SBPF_INS_JSET, "jset" },
	{ SBPF_INS_JNE, "jne" },
	{ SBPF_INS_JSGT, "jsgt" },
	{ SBPF_INS_JSGE, "jsge" },
	{ SBPF_INS_JLT, "jlt" },
	{ SBPF_INS_JLE, "jle" },
	{ SBPF_INS_JSLT, "jslt" },
	{ SBPF_INS_JSLE, "jsle" },
	{ SBPF_INS_CALL, "call" },
	{ SBPF_INS_EXIT, "exit" },
};
#endif

bool SBPF_getFeature(const cs_mode mode, const cs_mode feature)
{
	return (mode & feature);
}

const char *SBPF_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(insn_name_maps, ARR_SIZE(insn_name_maps), id);
#else
	return NULL;
#endif
}

const char *SBPF_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	if (reg < SBPF_REG_R0 || reg > SBPF_REG_R10)
		return NULL;

	static const char reg_names[11][4] = {
		"r0", "r1", "r2", "r3", "r4", "r5",
		"r6", "r7", "r8", "r9", "r10",
	};

	return reg_names[reg - SBPF_REG_R0];
#else
	return NULL;
#endif
}

void SBPF_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	// Not used by SBPF. Information is set after disassembly.
}

static void sort_and_uniq(cs_regs arr, uint8_t n, uint8_t *new_n)
{
	size_t i_min;
	size_t tmp;

	for (size_t j = 0; j < n; j++) {
		i_min = j;
		for (size_t i = j + 1; i < n; i++) {
			if (arr[i] < arr[i_min])
				i_min = i;
		}

		if (j != 0 && arr[i_min] == arr[j - 1]) {
			arr[i_min] = arr[n - 1];
			--n;
		} else {
			tmp = arr[i_min];
			arr[i_min] = arr[j];
			arr[j] = tmp;
		}
	}

	*new_n = n;
}

void SBPF_reg_access(const cs_insn *insn, cs_regs regs_read,
		     uint8_t *regs_read_count, cs_regs regs_write,
		     uint8_t *regs_write_count)
{
	unsigned i;
	uint8_t read_count;
	uint8_t write_count;
	const cs_sbpf *sbpf = &insn->detail->sbpf;

	read_count = insn->detail->regs_read_count;
	write_count = insn->detail->regs_write_count;

	memcpy(regs_read, insn->detail->regs_read,
	       read_count * sizeof(insn->detail->regs_read[0]));
	memcpy(regs_write, insn->detail->regs_write,
	       write_count * sizeof(insn->detail->regs_write[0]));

	for (i = 0; i < sbpf->op_count; i++) {
		const cs_sbpf_op *op = &sbpf->operands[i];
		switch (op->type) {
		default:
			break;
		case SBPF_OP_REG:
			if (op->access & CS_AC_READ) {
				regs_read[read_count] = op->reg;
				read_count++;
			}
			if (op->access & CS_AC_WRITE) {
				regs_write[write_count] = op->reg;
				write_count++;
			}
			break;
		case SBPF_OP_MEM:
			if (op->mem.base != SBPF_REG_INVALID) {
				regs_read[read_count] = op->mem.base;
				read_count++;
			}
			break;
		}
	}

	sort_and_uniq(regs_read, read_count, regs_read_count);
	sort_and_uniq(regs_write, write_count, regs_write_count);
}
