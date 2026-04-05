/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3 */

#include <assert.h>
#include <inttypes.h>

#include <capstone/platform.h>

#include "SBPFConstants.h"
#include "SBPFInstPrinter.h"
#include "SBPFMapping.h"
#include "../../Mapping.h"

static cs_sbpf_op *expand_sbpf_operands(cs_sbpf *sbpf)
{
	assert(sbpf->op_count < 4);
	return &sbpf->operands[sbpf->op_count++];
}

static void push_op_reg(cs_sbpf *sbpf, sbpf_reg reg, cs_ac_type access)
{
	cs_sbpf_op *op = expand_sbpf_operands(sbpf);

	op->type = SBPF_OP_REG;
	op->reg = reg;
	op->access = access;
}

static void push_op_imm(cs_sbpf *sbpf, int64_t imm, bool is_signed)
{
	cs_sbpf_op *op = expand_sbpf_operands(sbpf);

	op->type = SBPF_OP_IMM;
	op->imm = imm;
	op->is_signed = is_signed;
}

static void push_op_off(cs_sbpf *sbpf, int32_t off)
{
	cs_sbpf_op *op = expand_sbpf_operands(sbpf);

	op->type = SBPF_OP_OFF;
	op->off = off;
	op->is_signed = true;
}

static void push_op_mem(cs_sbpf *sbpf, sbpf_reg base, int32_t disp)
{
	cs_sbpf_op *op = expand_sbpf_operands(sbpf);

	op->type = SBPF_OP_MEM;
	op->mem.base = base;
	op->mem.disp = disp;
	op->is_signed = true;
}

static void convert_operands(MCInst *MI, cs_sbpf *sbpf)
{
	unsigned opcode = MCInst_getOpcode(MI);
	unsigned mc_op_count = MCInst_getNumOperands(MI);
	MCOperand *op;
	MCOperand *op2;

	sbpf->op_count = 0;

	if (SBPF_CLASS(opcode) == SBPF_CLASS_LD ||
	    SBPF_CLASS(opcode) == SBPF_CLASS_LDX) {
		if (opcode == SBPF_OP_LDDW) {
			push_op_reg(sbpf,
				    (sbpf_reg)MCOperand_getReg(MCInst_getOperand(MI, 0)),
				    (cs_ac_type)CS_AC_WRITE);
			push_op_imm(sbpf, MCOperand_getImm(MCInst_getOperand(MI, 1)),
				    false);
			return;
		}

		push_op_reg(sbpf,
			    (sbpf_reg)MCOperand_getReg(MCInst_getOperand(MI, 0)),
			    (cs_ac_type)CS_AC_WRITE);
		op = MCInst_getOperand(MI, 1);
		op2 = MCInst_getOperand(MI, 2);
		push_op_mem(sbpf, (sbpf_reg)MCOperand_getReg(op),
			    (int32_t)MCOperand_getImm(op2));
		return;
	}

	if (SBPF_CLASS(opcode) == SBPF_CLASS_ST ||
	    SBPF_CLASS(opcode) == SBPF_CLASS_STX) {
		op = MCInst_getOperand(MI, 0);
		op2 = MCInst_getOperand(MI, 1);
		push_op_mem(sbpf, (sbpf_reg)MCOperand_getReg(op),
			    (int32_t)MCOperand_getImm(op2));

		op = MCInst_getOperand(MI, 2);
		if (MCOperand_isImm(op))
			push_op_imm(sbpf, MCOperand_getImm(op), true);
		else if (MCOperand_isReg(op))
			push_op_reg(sbpf, (sbpf_reg)MCOperand_getReg(op),
				    (cs_ac_type)CS_AC_READ);
		return;
	}

	if (SBPF_CLASS(opcode) == SBPF_CLASS_JMP) {
		if (opcode == SBPF_OP_EXIT)
			return;

		if (opcode == SBPF_OP_CALL) {
			push_op_imm(sbpf, MCOperand_getImm(MCInst_getOperand(MI, 0)),
				    false);
			return;
		}

		if (opcode == SBPF_OP_JA) {
			push_op_off(sbpf,
				    (int32_t)MCOperand_getImm(MCInst_getOperand(MI, 0)));
			return;
		}

		for (size_t i = 0; i < mc_op_count; i++) {
			op = MCInst_getOperand(MI, i);
			if (MCOperand_isReg(op)) {
				push_op_reg(sbpf, (sbpf_reg)MCOperand_getReg(op),
					    (cs_ac_type)CS_AC_READ);
			} else if (MCOperand_isImm(op)) {
				if (i == mc_op_count - 1)
					push_op_off(sbpf, (int32_t)MCOperand_getImm(op));
				else
					push_op_imm(sbpf, MCOperand_getImm(op), true);
			}
		}
		return;
	}

	if (SBPF_CLASS(opcode) == SBPF_CLASS_ALU32 ||
	    SBPF_CLASS(opcode) == SBPF_CLASS_ALU64) {
		if (mc_op_count == 0)
			return;

		op = MCInst_getOperand(MI, 0);
		push_op_reg(sbpf, (sbpf_reg)MCOperand_getReg(op),
			    (cs_ac_type)(CS_AC_READ | CS_AC_WRITE));

		if (mc_op_count == 1)
			return;

		op = MCInst_getOperand(MI, 1);
		if (MCOperand_isImm(op))
			push_op_imm(sbpf, MCOperand_getImm(op), true);
		else if (MCOperand_isReg(op))
			push_op_reg(sbpf, (sbpf_reg)MCOperand_getReg(op),
				    (cs_ac_type)CS_AC_READ);
	}
}

static void print_operand(MCInst *MI, struct SStream *O, const cs_sbpf_op *op)
{
	switch (op->type) {
	default:
		SStream_concat0(O, "invalid");
		break;
	case SBPF_OP_REG:
		SStream_concat0(O, SBPF_reg_name((csh)MI->csh, op->reg));
		break;
	case SBPF_OP_IMM:
		if (op->is_signed)
			SStream_concat(O, "%" PRId64, op->imm);
		else
			SStream_concat(O, "0x%" PRIx64, (uint64_t)op->imm);
		break;
	case SBPF_OP_OFF:
		SStream_concat(O, "%+" PRId32, op->off);
		break;
	case SBPF_OP_MEM:
		SStream_concat0(O, "[");
		SStream_concat0(O, SBPF_reg_name((csh)MI->csh, op->mem.base));
		if (op->mem.disp > 0)
			SStream_concat(O, "+%" PRId32, op->mem.disp);
		else if (op->mem.disp < 0)
			SStream_concat(O, "%" PRId32, op->mem.disp);
		SStream_concat0(O, "]");
		break;
	}
}

void SBPF_printInst(MCInst *MI, struct SStream *O, void *PrinterInfo)
{
	cs_sbpf sbpf = { 0 };

	SStream_concat0(O,
			SBPF_insn_name((csh)MI->csh, MCInst_getOpcodePub(MI)));
	convert_operands(MI, &sbpf);

	for (size_t i = 0; i < sbpf.op_count; i++) {
		if (i == 0)
			SStream_concat0(O, "\t");
		else
			SStream_concat0(O, ", ");
		print_operand(MI, O, &sbpf.operands[i]);
	}

#ifndef CAPSTONE_DIET
	if (detail_is_set(MI))
		MI->flat_insn->detail->sbpf = sbpf;
#endif
}
