// SPDX-FileCopyrightText: 2019-2026 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#include "R2Architecture.h"
#include "R2LoadImage.h"
#include "R2Utils.h"

#include <cstring>
#include <limits>

R2LoadImage::R2LoadImage(RCoreMutex *coreMutex, AddrSpaceManager *addr_space_manager) : LoadImage("radare2_program"),
	coreMutex(coreMutex),
	addr_space_manager(addr_space_manager)
{
	// nothing to do
}

void R2LoadImage::loadFill(uint1 *ptr, int4 size, const Address &addr) {
	RCoreLock core (coreMutex);
	r_io_read_at (core->io, addr.getOffset(), ptr, size);
}

bool R2LoadImage::getInstructionField(const InstructionField &field, InstructionFieldUse use, Address &target) const {
	RCoreLock core (coreMutex);
	RBinFile *file = r_bin_cur (core->bin);
	RBinObject *object = file ? file->bo : nullptr;
	RBinInfo *info = object ? object->info : nullptr;
	AddrSpace *space = addr_space_manager->getDefaultCodeSpace ();
	if (!info || !info->rclass || strcmp (info->rclass, "ne") || !info->os || strcmp (info->os, "Windows") ||
		space->getAddrSize () != 6 || field.source.getSpace () != space || field.size <= 0 || !object->relocs) {
		return false;
	}

	const ut64 source = field.source.getOffset ();
	const ut64 end = source + field.size;
	// Windows NE fields are at most four bytes; include a pointer starting before this token.
	const ut64 begin = source > 3 ? source - 3 : 0;
	if (end - begin > std::numeric_limits<int>::max ()) {
		throw LowlevelError ("Unrepresentable Windows NE instruction field span");
	}
	RBinReloc *reloc = r_bin_reloc_at (object->relocs, begin, end - begin);
	const RBinReloc *limit = R_VEC_END_ITER (object->relocs);
	for (; reloc && reloc < limit && reloc->vaddr < end; ++reloc) {
		const unsigned type = reloc->ntype & 7;
		const bool pointer = type == 3;
		const bool selector = type == 2;
		if (!pointer && !selector && !reloc->import) {
			continue;
		}
		const int width = reloc->type / 8;
		const ut64 unknown = reloc->vaddr + (pointer && !reloc->import ? 2 : 0);
		const ut64 relocEnd = reloc->vaddr + width;
		if (source >= relocEnd || end <= unknown) {
			continue;
		}
		const bool whole = source == reloc->vaddr && field.size == width;
		const bool component = pointer && field.size == 2 && (source == reloc->vaddr + 2 || (reloc->import && source == reloc->vaddr));
		const bool expectedWidth = (type == 0 && width == 1) || ((selector || type == 5) && width == 2) || (pointer && width == 4);
		if (!expectedWidth || (!whole && !component) || field.bigEndian || field.bitOffset != 0 || field.bitSize != field.size * 8) {
			throw LowlevelError ("Unrepresentable Windows NE relocated instruction field");
		}
		if (use == machine_value) {
			return true;
		}
		if (pointer && whole && !reloc->additive) {
			const ut64 address = reloc->import ? reloc->laddr : reloc->addend;
			if (address == UT64_MAX || address > space->getHighest ()) {
				throw LowlevelError ("Unrepresentable Windows NE relocated code target");
			}
			target = Address (space, address);
			return true;
		}
		return false;
	}
	return false;
}

string R2LoadImage::getArchType() const {
	return "radare2";
}

void R2LoadImage::adjustVma(long adjust) {
	throw LowlevelError("Cannot adjust radare2 virtual memory");
}
static bool isptr(const ut8 *p, size_t remain) {
	if (remain < sizeof(ut32)) {
		return false;
	}
	ut32 ptr = 0;
	memcpy (&ptr, p, sizeof(ptr));
	if (ptr < 0x1000) {
		return false;
	}
	return ptr != UT32_MAX;
}

static void addRangesWithPointers(RCoreLock &core, RangeList &list, AddrSpace *space) {
	RIOMapRef *mapref;
	RIO *io = core->io;
	RIOBank *bank = r_io_bank_get (io, io->bank);
	r_list_foreach_cpp<RIOMapRef>(bank->maprefs, [&](RIOMapRef *mapref) {
		RIOMap *map = r_io_map_get (io, mapref->id);
		ut64 begin = r_io_map_begin (map);
		ut64 end = r_io_map_end (map);
		if (map->perm & R_PERM_W) {
			return;
		}
		ut64 fin = end - begin;
		if (fin > 0xffffff) {
			list.insertRange(space, begin, end);
			return;
		}
		ut8 *buf = (ut8 *)malloc (fin);
		if (!buf) {
			list.insertRange(space, begin, end);
			return;
		}
		r_io_read_at (io, begin, buf, fin);
		ut64 base = begin;
		ut64 basefin = begin;
		ut8 *data = buf;
		bool hasdata = false;
		int inc = (core->rasm->config->bits == 64)? 8: 4;
		for (ut64 i = 0; i < fin; i += inc) {
			basefin = begin + i;
			if (isptr (data + i, fin - i)) {
				// eprintf ("valid %llx\n", data[i]);
				hasdata = true;
			} else {
				if (hasdata) {
					// eprintf ("0 append %llx %llx because of 0x%llx\n", base, basefin, *((ut64*)(data +i)));
					if (base > 0) {
						list.insertRange(space, base, basefin); // begin, end);
					}
					hasdata = false;
					base = basefin;
				}
			}
		}
		free (buf);
		if (hasdata) {
			// eprintf ("1 append %llx %llx\n", base, basefin);
			list.insertRange(space, base, basefin);
		}
	});
}

// the loader fills relocation targets in at runtime, so their on-disk bytes are not constants
static void removeRelocRanges(RCoreLock &core, RangeList &list, AddrSpace *space) {
	RVecRBinReloc *relocs = r_bin_get_relocs (core->bin);
	if (!relocs) {
		return;
	}
	const ut64 width = (core->rasm->config->bits == 64)? 8: 4;
	auto removeRelocRange = [&list, space, width](const RBinReloc *reloc) {
		const ut64 at = reloc->vaddr;
		if (at && at != UT64_MAX) {
			list.removeRange (space, at, at + width - 1);
		}
	};
	RBinReloc *reloc;
	R_VEC_FOREACH (relocs, reloc) {
		removeRelocRange (reloc);
	}
}

void R2LoadImage::getReadonly(RangeList &list) const {
	RCoreLock core(coreMutex);
	int roprop = r_config_get_i (core->config, "r2ghidra.roprop");
	if (roprop > 0) {
		auto space = addr_space_manager->getDefaultCodeSpace ();
		switch (roprop) {
		case 1:
			break;
		case 2:
			// find ranges with pointers
			addRangesWithPointers(core, list, space);
			break;
		case 3:
			{
				RIOMapRef *mapref;
				RListIter *iter;
				RIO *io = core->io;
				RIOBank *bank = r_io_bank_get (io, io->bank);
				r_list_foreach_cpp<RIOMapRef>(bank->maprefs, [&](RIOMapRef *mapref) {
					RIOMap *map = r_io_map_get (io, mapref->id);
					ut64 begin = r_io_map_begin (map);
					ut64 end = r_io_map_end (map);
					if (map->perm & R_PERM_W) {
						return;
					}
					list.insertRange(space, begin, end);
				});
			}
			break;
		case 4:
			list.insertRange(space, 0x1000, ST64_MAX - 1);
			break;
		default:
			list.insertRange(space, 0, UT64_MAX - 1);
			break;
		}
		removeRelocRanges (core, list, space);
	}
}
