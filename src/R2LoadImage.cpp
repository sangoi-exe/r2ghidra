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

static RBinFile *windowsNeFile(RCoreLock &core, AddrSpace *space, const Address &source) {
	RBinFile *file = r_bin_cur (core->bin);
	RBinObject *object = file ? file->bo : nullptr;
	RBinInfo *info = object ? object->info : nullptr;
	if (!info || !info->rclass || strcmp (info->rclass, "ne") || !info->os || strcmp (info->os, "Windows") ||
		space->getAddrSize () != 6 || source.getSpace () != space || !object->relocs) {
		return nullptr;
	}
	return file;
}

static RBinReloc *firstNeReloc(RBinObject *object, ut64 source, int size) {
	const ut64 end = source + size;
	// Windows NE fields are at most four bytes; include a pointer starting before this token.
	const ut64 begin = source > 3 ? source - 3 : 0;
	if (end - begin > std::numeric_limits<int>::max ()) {
		throw LowlevelError ("Unrepresentable Windows NE instruction field span");
	}
	return r_bin_reloc_at (object->relocs, begin, end - begin);
}

static bool exactNeMachineField(const RBinReloc &reloc, ut64 source, int size) {
	const unsigned type = reloc.ntype & 7;
	if (type != 2 && type != 3 && !reloc.import) {
		return false;
	}
	const int width = reloc.type / 8;
	const bool expectedWidth = (type == 0 && width == 1) || ((type == 2 || type == 5) && width == 2) || (type == 3 && width == 4);
	const bool whole = source == reloc.vaddr && size == width;
	const bool component = type == 3 && size == 2 && (source == reloc.vaddr || source == reloc.vaddr + 2);
	return expectedWidth && (whole || component);
}

bool R2LoadImage::getInstructionField(const InstructionField &field) const {
	RCoreLock core (coreMutex);
	RBinFile *file = windowsNeFile (core, addr_space_manager->getDefaultCodeSpace (), field.source);
	if (!file || field.size <= 0) {
		return false;
	}
	const ut64 source = field.source.getOffset ();
	const ut64 end = source + field.size;
	RBinReloc *reloc = firstNeReloc (file->bo, source, field.size);
	const RBinReloc *limit = R_VEC_END_ITER (file->bo->relocs);
	for (; reloc && reloc < limit && reloc->vaddr < end; ++reloc) {
		const unsigned type = reloc->ntype & 7;
		if (type != 2 && type != 3 && !reloc->import) {
			continue;
		}
		const int width = reloc->type / 8;
		const ut64 relocEnd = reloc->vaddr + width;
		if (source >= relocEnd || end <= reloc->vaddr) {
			continue;
		}
		if (!exactNeMachineField (*reloc, source, field.size) || field.bigEndian || field.bitOffset != 0 || field.bitSize != field.size * 8) {
			throw LowlevelError ("Unrepresentable Windows NE relocated instruction field");
		}
		return true;
	}
	return false;
}

static bool declaredReadonlyNeSource(RBinFile *file, const RBinReloc &reloc, int size) {
	if (!file->buf || reloc.paddr < file->bo->loadaddr) {
		return false;
	}
	const ut64 offset = reloc.paddr - file->bo->loadaddr;
	const ut64 fileSize = r_buf_size (file->buf);
	if (offset > fileSize || (ut64)size > fileSize - offset) {
		return false;
	}
	RVecRBinSection *sections = r_bin_file_get_sections_vec (file);
	RBinSection *section;
	R_VEC_FOREACH (sections, section) {
		if (!section->is_segment || (section->perm & R_PERM_W) || reloc.vaddr < section->vaddr || reloc.paddr < section->paddr) {
			continue;
		}
		const ut64 displacement = reloc.vaddr - section->vaddr;
		if (displacement == reloc.paddr - section->paddr && displacement <= section->size && (ut64)size <= section->size - displacement) {
			return true;
		}
	}
	return false;
}

bool R2LoadImage::isCallPreservedStorage(const Address &storage, int4 size) const {
	RCoreLock core (coreMutex);
	RBinFile *file = windowsNeFile (core, addr_space_manager->getDefaultCodeSpace (), storage);
	if (!file || size <= 0 || size > 4) {
		return false;
	}
	const ut64 source = storage.getOffset ();
	RBinReloc *reloc = firstNeReloc (file->bo, source, size);
	const RBinReloc *limit = R_VEC_END_ITER (file->bo->relocs);
	for (; reloc && reloc < limit && reloc->vaddr < source + size; ++reloc) {
		if (exactNeMachineField (*reloc, source, size) && declaredReadonlyNeSource (file, *reloc, reloc->type / 8)) {
			return true;
		}
	}
	return false;
}

bool R2LoadImage::getInitialReference(const Address &storage, int4 size, InitialReferenceUse use, Address &target) const {
	RCoreLock core (coreMutex);
	AddrSpace *space = addr_space_manager->getDefaultCodeSpace ();
	RBinFile *file = windowsNeFile (core, space, storage);
	if (!file || (use == selector_reference ? size != 2 : size != 4)) {
		return false;
	}
	const ut64 source = storage.getOffset ();
	RBinReloc *reloc = firstNeReloc (file->bo, source, size);
	const RBinReloc *limit = R_VEC_END_ITER (file->bo->relocs);
	for (; reloc && reloc < limit && reloc->vaddr < source + size; ++reloc) {
		if (reloc->additive) {
			continue;
		}
		const unsigned type = reloc->ntype & 7;
		const int width = reloc->type / 8;
		if (use == selector_reference) {
			if (reloc->import || !((type == 2 && width == 2 && source == reloc->vaddr) || (type == 3 && width == 4 && source == reloc->vaddr + 2))) {
				continue;
			}
		} else if (type != 3 || width != 4 || source != reloc->vaddr) {
			continue;
		}
		// Declared non-writable storage admits an initial analysis fact, not runtime byte immutability.
		if (!declaredReadonlyNeSource (file, *reloc, width)) {
			continue;
		}
		ut64 address = reloc->import ? reloc->laddr : reloc->addend;
		if (address == UT64_MAX || address > space->getHighest ()) {
			throw LowlevelError ("Unrepresentable Windows NE initial reference target");
		}
		if (use == selector_reference) {
			address &= ~(ut64)UT32_MAX;
		}
		target = Address (space, address);
		return true;
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
