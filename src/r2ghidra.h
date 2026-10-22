// SPDX-FileCopyrightText: 2019-2026 thestr4ng3r, pancake
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef R2GHIDRA_H
#define R2GHIDRA_H

#undef R_LOG_ORIGIN
#define R_LOG_ORIGIN "r2ghidra"

#include <r_core.h>
#include <r_lib.h>

#if !defined(R2_ABIVERSION) || R2_ABIVERSION < 158
#error r2ghidra requires radare2 ABI 158 or newer and the current semantic type APIs
#endif

R_API RCodeMeta *r2ghidra_decompile_annotated_code(RCore *core, ut64 addr);

#endif //R2GHIDRA_H
