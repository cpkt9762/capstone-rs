/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3 */

#ifdef CAPSTONE_HAS_SBPF

#include "SBPFDisassembler.h"
#include "SBPFInstPrinter.h"
#include "SBPFMapping.h"
#include "SBPFModule.h"

cs_err SBPF_global_init(cs_struct *ud)
{
	ud->printer = SBPF_printInst;
	ud->reg_name = SBPF_reg_name;
	ud->insn_id = SBPF_get_insn_id;
	ud->insn_name = SBPF_insn_name;
	ud->group_name = SBPF_group_name;
#ifndef CAPSTONE_DIET
	ud->reg_access = SBPF_reg_access;
#endif
	ud->disasm = SBPF_getInstruction;

	return CS_ERR_OK;
}

cs_err SBPF_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	if (type == CS_OPT_MODE)
		handle->mode = (cs_mode)value;

	return CS_ERR_OK;
}

#endif
