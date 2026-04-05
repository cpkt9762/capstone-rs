/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3 */

#ifndef CS_SBPF_MODULE_H
#define CS_SBPF_MODULE_H

#include "../../utils.h"

cs_err SBPF_global_init(cs_struct *ud);
cs_err SBPF_option(cs_struct *handle, cs_opt_type type, size_t value);

#endif
