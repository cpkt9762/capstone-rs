/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3 */

#ifndef CS_SBPF_MAPPING_H
#define CS_SBPF_MAPPING_H

#include <capstone/capstone.h>

#include "../../cs_priv.h"

bool SBPF_getFeature(const cs_mode mode, const cs_mode feature);

const char *SBPF_group_name(csh handle, unsigned int id);
const char *SBPF_insn_name(csh handle, unsigned int id);
const char *SBPF_reg_name(csh handle, unsigned int reg);
void SBPF_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);
void SBPF_reg_access(const cs_insn *insn, cs_regs regs_read,
		     uint8_t *regs_read_count, cs_regs regs_write,
		     uint8_t *regs_write_count);

#endif
