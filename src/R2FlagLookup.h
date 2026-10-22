// SPDX-FileCopyrightText: 2026 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef R2GHIDRA_R2FLAGLOOKUP_H
#define R2GHIDRA_R2FLAGLOOKUP_H

#include <r_flag.h>

template<typename Predicate>
static RFlagItem *r2ghidra_flag_find_at(RFlag *flags, ut64 addr, const Predicate &predicate) {
	const RVecFlagItemPtr *items = r_flag_get_vec (flags, addr);
	RFlagItem **iter;
	RFlagItem *item;
	r_flag_item_vec_foreach (items, iter, item) {
		if (predicate (item)) {
			return item;
		}
	}
	return nullptr;
}

#endif // R2GHIDRA_R2FLAGLOOKUP_H
