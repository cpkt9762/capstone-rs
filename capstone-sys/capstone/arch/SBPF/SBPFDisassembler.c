/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3 */

#ifdef CAPSTONE_HAS_SBPF

#include <stddef.h>
#include <string.h>

#include "SBPFConstants.h"
#include "SBPFDisassembler.h"
#include "SBPFMapping.h"
#include "../../Mapping.h"
#include "../../cs_priv.h"
#include "../../utils.h"

static sbpf_internal *alloc_sbpf_internal(const size_t code_len)
{
	sbpf_internal *sbpf;

	if (code_len < 8)
		return NULL;

	sbpf = (sbpf_internal *)cs_mem_malloc(sizeof(sbpf_internal));
	if (sbpf == NULL)
		return NULL;

	sbpf->insn_size = 8;
	return sbpf;
}

static sbpf_internal *fetch_sbpf(MCInst *instr, const uint8_t *code,
			 const size_t code_len)
{
	sbpf_internal *sbpf;

	sbpf = alloc_sbpf_internal(code_len);
	if (sbpf == NULL)
		return NULL;

	sbpf->op = (uint16_t)code[0];
	sbpf->dst = code[1] & 0xf;
	sbpf->src = (code[1] & 0xf0) >> 4;

	if (sbpf->op == SBPF_OP_LDDW) {
		uint64_t imm_lo;
		uint64_t imm_hi;

		if (code_len < 16 || code[8] != 0x00) {
			cs_mem_free(sbpf);
			return NULL;
		}

		imm_lo = (uint32_t)readBytes32(instr, code + 4);
		imm_hi = (uint32_t)readBytes32(instr, code + 12);
		sbpf->imm = (int64_t)((imm_hi << 32) | imm_lo);
		sbpf->insn_size = 16;
	} else {
		sbpf->offset = (int16_t)readBytes16(instr, code + 2);
		sbpf->imm = (int32_t)readBytes32(instr, code + 4);
	}

	return sbpf;
}

#define CHECK_READABLE_REG(reg) \
	do { \
		if (!((reg) >= SBPF_REG_R0 && (reg) <= SBPF_REG_R10)) \
			return false; \
	} while (0)

#define CHECK_WRITEABLE_REG(reg) \
	do { \
		if (!((reg) >= SBPF_REG_R0 && (reg) < SBPF_REG_R10)) \
			return false; \
	} while (0)

#define CHECK_READABLE_AND_PUSH(MI, r) \
	do { \
		CHECK_READABLE_REG((r) + SBPF_REG_R0); \
		MCOperand_CreateReg0(MI, (r) + SBPF_REG_R0); \
	} while (0)

#define CHECK_WRITABLE_AND_PUSH(MI, r) \
	do { \
		CHECK_WRITEABLE_REG((r) + SBPF_REG_R0); \
		MCOperand_CreateReg0(MI, (r) + SBPF_REG_R0); \
	} while (0)

static bool decodeLoad(MCInst *MI, sbpf_internal *sbpf)
{
	if (sbpf->op == SBPF_OP_LDDW) {
		CHECK_WRITABLE_AND_PUSH(MI, sbpf->dst);
		MCOperand_CreateImm0(MI, sbpf->imm);
		return true;
	}

	if (SBPF_CLASS(sbpf->op) != SBPF_CLASS_LDX ||
	    SBPF_MODE(sbpf->op) != SBPF_MODE_MEM)
		return false;

	CHECK_WRITABLE_AND_PUSH(MI, sbpf->dst);
	CHECK_READABLE_AND_PUSH(MI, sbpf->src);
	MCOperand_CreateImm0(MI, sbpf->offset);
	return true;
}

static bool decodeStore(MCInst *MI, sbpf_internal *sbpf)
{
	if (SBPF_MODE(sbpf->op) != SBPF_MODE_MEM)
		return false;

	if (SBPF_CLASS(sbpf->op) != SBPF_CLASS_ST &&
	    SBPF_CLASS(sbpf->op) != SBPF_CLASS_STX)
		return false;

	CHECK_READABLE_AND_PUSH(MI, sbpf->dst);
	MCOperand_CreateImm0(MI, sbpf->offset);

	if (SBPF_CLASS(sbpf->op) == SBPF_CLASS_ST)
		MCOperand_CreateImm0(MI, sbpf->imm);
	else
		CHECK_READABLE_AND_PUSH(MI, sbpf->src);

	return true;
}

static bool decodeALU(MCInst *MI, sbpf_internal *sbpf)
{
	if (SBPF_CLASS(sbpf->op) != SBPF_CLASS_ALU32 &&
	    SBPF_CLASS(sbpf->op) != SBPF_CLASS_ALU64)
		return false;

	if (SBPF_OP(sbpf->op) > SBPF_ALU_END)
		return false;

	CHECK_WRITABLE_AND_PUSH(MI, sbpf->dst);

	if (SBPF_OP(sbpf->op) == SBPF_ALU_NEG)
		return true;

	if (SBPF_OP(sbpf->op) == SBPF_ALU_END) {
		if (SBPF_CLASS(sbpf->op) != SBPF_CLASS_ALU32)
			return false;
		if (sbpf->imm != 16 && sbpf->imm != 32 && sbpf->imm != 64)
			return false;

		sbpf->op |= ((uint16_t)sbpf->imm << 4);
		return true;
	}

	if (SBPF_SRC(sbpf->op) == SBPF_SRC_K)
		MCOperand_CreateImm0(MI, sbpf->imm);
	else
		CHECK_READABLE_AND_PUSH(MI, sbpf->src);

	return true;
}

static bool decodeJump(MCInst *MI, sbpf_internal *sbpf)
{
	if (SBPF_CLASS(sbpf->op) != SBPF_CLASS_JMP)
		return false;

	if (SBPF_OP(sbpf->op) > SBPF_JUMP_JSLE)
		return false;

	if (SBPF_OP(sbpf->op) == SBPF_JUMP_EXIT)
		return sbpf->op == SBPF_OP_EXIT;

	if (SBPF_OP(sbpf->op) == SBPF_JUMP_CALL) {
		if (sbpf->op != SBPF_OP_CALL)
			return false;
		MCOperand_CreateImm0(MI, sbpf->imm);
		return true;
	}

	if (SBPF_OP(sbpf->op) == SBPF_JUMP_JA) {
		if (SBPF_SRC(sbpf->op) != SBPF_SRC_K)
			return false;
		MCOperand_CreateImm0(MI, sbpf->offset);
		return true;
	}

	CHECK_READABLE_AND_PUSH(MI, sbpf->dst);
	if (SBPF_SRC(sbpf->op) == SBPF_SRC_K)
		MCOperand_CreateImm0(MI, sbpf->imm);
	else
		CHECK_READABLE_AND_PUSH(MI, sbpf->src);
	MCOperand_CreateImm0(MI, sbpf->offset);
	return true;
}

static bool getInstruction(MCInst *MI, sbpf_internal *sbpf)
{
	cs_detail *detail;

	detail = MI->flat_insn->detail;
	if (detail)
		memset(detail, 0, offsetof(cs_detail, sbpf) + sizeof(cs_sbpf));

	MCInst_clear(MI);

	switch (SBPF_CLASS(sbpf->op)) {
	default:
		return false;
	case SBPF_CLASS_LD:
	case SBPF_CLASS_LDX:
		return decodeLoad(MI, sbpf);
	case SBPF_CLASS_ST:
	case SBPF_CLASS_STX:
		return decodeStore(MI, sbpf);
	case SBPF_CLASS_ALU32:
	case SBPF_CLASS_ALU64:
		return decodeALU(MI, sbpf);
	case SBPF_CLASS_JMP:
		return decodeJump(MI, sbpf);
	}
}

static sbpf_insn op2insn_ld(unsigned opcode)
{
	switch (opcode) {
	case SBPF_OP_LDDW:
		return SBPF_INS_LDDW;
	case SBPF_OP_LDXB:
		return SBPF_INS_LDXB;
	case SBPF_OP_LDXH:
		return SBPF_INS_LDXH;
	case SBPF_OP_LDXW:
		return SBPF_INS_LDXW;
	case SBPF_OP_LDXDW:
		return SBPF_INS_LDXDW;
	default:
		return SBPF_INS_INVALID;
	}
}

static sbpf_insn op2insn_st(unsigned opcode)
{
	switch (opcode) {
	case SBPF_OP_STB:
		return SBPF_INS_STB;
	case SBPF_OP_STH:
		return SBPF_INS_STH;
	case SBPF_OP_STW:
		return SBPF_INS_STW;
	case SBPF_OP_STDW:
		return SBPF_INS_STDW;
	case SBPF_OP_STXB:
		return SBPF_INS_STXB;
	case SBPF_OP_STXH:
		return SBPF_INS_STXH;
	case SBPF_OP_STXW:
		return SBPF_INS_STXW;
	case SBPF_OP_STXDW:
		return SBPF_INS_STXDW;
	default:
		return SBPF_INS_INVALID;
	}
}

#define SBPF_ALU_CASE(op, insn32, insn64) \
	case SBPF_ALU_##op: \
		if (SBPF_CLASS(opcode) == SBPF_CLASS_ALU32) \
			return insn32; \
		else \
			return insn64

static sbpf_insn op2insn_alu(unsigned opcode)
{
	if (SBPF_OP(opcode) == SBPF_ALU_END) {
		if (SBPF_CLASS(opcode) != SBPF_CLASS_ALU32)
			return SBPF_INS_INVALID;

		switch (opcode ^ SBPF_CLASS_ALU32 ^ SBPF_ALU_END) {
		case SBPF_SRC_LITTLE | (16 << 4):
			return SBPF_INS_LE16;
		case SBPF_SRC_LITTLE | (32 << 4):
			return SBPF_INS_LE32;
		case SBPF_SRC_LITTLE | (64 << 4):
			return SBPF_INS_LE64;
		case SBPF_SRC_BIG | (16 << 4):
			return SBPF_INS_BE16;
		case SBPF_SRC_BIG | (32 << 4):
			return SBPF_INS_BE32;
		case SBPF_SRC_BIG | (64 << 4):
			return SBPF_INS_BE64;
		default:
			return SBPF_INS_INVALID;
		}
	}

	switch (SBPF_OP(opcode)) {
		SBPF_ALU_CASE(ADD, SBPF_INS_ADD32, SBPF_INS_ADD64);
		SBPF_ALU_CASE(SUB, SBPF_INS_SUB32, SBPF_INS_SUB64);
		SBPF_ALU_CASE(MUL, SBPF_INS_MUL32, SBPF_INS_MUL64);
		SBPF_ALU_CASE(DIV, SBPF_INS_DIV32, SBPF_INS_DIV64);
		SBPF_ALU_CASE(OR, SBPF_INS_OR32, SBPF_INS_OR64);
		SBPF_ALU_CASE(AND, SBPF_INS_AND32, SBPF_INS_AND64);
		SBPF_ALU_CASE(LSH, SBPF_INS_LSH32, SBPF_INS_LSH64);
		SBPF_ALU_CASE(RSH, SBPF_INS_RSH32, SBPF_INS_RSH64);
		SBPF_ALU_CASE(NEG, SBPF_INS_NEG32, SBPF_INS_NEG64);
		SBPF_ALU_CASE(MOD, SBPF_INS_MOD32, SBPF_INS_MOD64);
		SBPF_ALU_CASE(XOR, SBPF_INS_XOR32, SBPF_INS_XOR64);
		SBPF_ALU_CASE(MOV, SBPF_INS_MOV32, SBPF_INS_MOV64);
		SBPF_ALU_CASE(ARSH, SBPF_INS_ARSH32, SBPF_INS_ARSH64);
	default:
		return SBPF_INS_INVALID;
	}
}
#undef SBPF_ALU_CASE

static sbpf_insn op2insn_jmp(unsigned opcode)
{
	switch (SBPF_OP(opcode)) {
	case SBPF_JUMP_JA:
		return (opcode == SBPF_OP_JA) ? SBPF_INS_JA : SBPF_INS_INVALID;
	case SBPF_JUMP_JEQ:
		return SBPF_INS_JEQ;
	case SBPF_JUMP_JGT:
		return SBPF_INS_JGT;
	case SBPF_JUMP_JGE:
		return SBPF_INS_JGE;
	case SBPF_JUMP_JSET:
		return SBPF_INS_JSET;
	case SBPF_JUMP_JNE:
		return SBPF_INS_JNE;
	case SBPF_JUMP_JSGT:
		return SBPF_INS_JSGT;
	case SBPF_JUMP_JSGE:
		return SBPF_INS_JSGE;
	case SBPF_JUMP_CALL:
		return (opcode == SBPF_OP_CALL) ? SBPF_INS_CALL : SBPF_INS_INVALID;
	case SBPF_JUMP_EXIT:
		return (opcode == SBPF_OP_EXIT) ? SBPF_INS_EXIT : SBPF_INS_INVALID;
	case SBPF_JUMP_JLT:
		return SBPF_INS_JLT;
	case SBPF_JUMP_JLE:
		return SBPF_INS_JLE;
	case SBPF_JUMP_JSLT:
		return SBPF_INS_JSLT;
	case SBPF_JUMP_JSLE:
		return SBPF_INS_JSLE;
	default:
		return SBPF_INS_INVALID;
	}
}

#ifndef CAPSTONE_DIET
static void add_group(MCInst *MI, uint8_t group)
{
	cs_detail *detail = MI->flat_insn->detail;

	if (detail == NULL || detail->groups_count >= MAX_NUM_GROUPS)
		return;

	detail->groups[detail->groups_count++] = group;
}
#endif

static bool setFinalOpcode(MCInst *MI, const sbpf_internal *sbpf)
{
	sbpf_insn id = SBPF_INS_INVALID;

	switch (SBPF_CLASS(sbpf->op)) {
	default:
		break;
	case SBPF_CLASS_LD:
	case SBPF_CLASS_LDX:
		id = op2insn_ld(sbpf->op);
		add_group(MI, SBPF_GRP_LOAD);
		break;
	case SBPF_CLASS_ST:
	case SBPF_CLASS_STX:
		id = op2insn_st(sbpf->op);
		add_group(MI, SBPF_GRP_STORE);
		break;
	case SBPF_CLASS_ALU32:
	case SBPF_CLASS_ALU64:
		id = op2insn_alu(sbpf->op);
		add_group(MI, SBPF_GRP_ALU);
		break;
	case SBPF_CLASS_JMP:
		id = op2insn_jmp(sbpf->op);
#ifndef CAPSTONE_DIET
		if (id == SBPF_INS_CALL)
			add_group(MI, SBPF_GRP_CALL);
		else if (id == SBPF_INS_EXIT)
			add_group(MI, SBPF_GRP_RETURN);
		else
			add_group(MI, SBPF_GRP_JUMP);
#endif
		break;
	}

	if (id == SBPF_INS_INVALID)
		return false;

	MCInst_setOpcodePub(MI, id);
	return true;
}

bool SBPF_getInstruction(csh ud, const uint8_t *code, size_t code_len,
			 MCInst *instr, uint16_t *size, uint64_t address,
			 void *info)
{
	sbpf_internal *sbpf;

	sbpf = fetch_sbpf(instr, code, code_len);
	if (sbpf == NULL)
		return false;

	if (!getInstruction(instr, sbpf) || !setFinalOpcode(instr, sbpf)) {
		cs_mem_free(sbpf);
		return false;
	}

	MCInst_setOpcode(instr, sbpf->op);
	*size = sbpf->insn_size;
	cs_mem_free(sbpf);

	return true;
}

#endif
