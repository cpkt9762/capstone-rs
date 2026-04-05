/* Capstone Disassembly Engine */
/* SPDX-License-Identifier: BSD-3 */

#ifndef CS_SBPF_INSTPRINTER_H
#define CS_SBPF_INSTPRINTER_H

#include <capstone/capstone.h>

#include "../../MCInst.h"
#include "../../SStream.h"

struct SStream;

void SBPF_printInst(MCInst *MI, struct SStream *O, void *Info);

#endif
