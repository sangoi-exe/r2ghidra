// SPDX-FileCopyrightText: 2019-2022 thestr4ng3r, pancake
// SPDX-License-Identifier: LGPL-3.0-only

#include "R2Architecture.h"
#include "R2LoadImage.h"
#include "R2Scope.h"
#include "R2TypeFactory.h"
#include "R2CommentDatabase.h"
#include "R2Utils.h"
#include "ArchMap.h"

#include <funcdata.hh>
#include <coreaction.hh>

#include <iostream>

using namespace ghidra;

#include "Dalvik.inc.cpp"

// maps radare2 calling conventions to proto model names, tried in order against the loaded cspec
static const std::map<std::string, std::vector<std::string>> cc_map = {
	{ "cdecl", { "__cdecl" } },
	{ "fastcall", { "__fastcall" } },
	{ "ms", { "__fastcall", "MSABI" } }, // MSABI covers the x86-64 gcc cspec, which has no __fastcall
	{ "stdcall", { "__stdcall" } },
	{ "cdecl-thiscall-ms", { "__thiscall" } },
	{ "sh32", { "__stdcall" } },
	{ "amd64", { "__stdcall" } },
	{ "arm64", { "__cdecl" } },
	{ "arm32", { "__stdcall" } },
	{ "arm16", { "__stdcall" } }, /* not actually __stdcall */
	{ "ppc-32", { "__stdcall" } }, /* PPC cspec default_proto: r3-r10 GPR / f1-f13 FP */
	{ "ppc-64", { "__stdcall" } }
};

std::string FilenameFromCore(RCore *core) {
	if (core && core->bin && core->bin->file) {
		return core->bin->file;
	}
	return std::string();
}

R2Architecture::R2Architecture(RCore *core, const std::string &sleigh_id)
	: SleighArchitecture (FilenameFromCore (core), sleigh_id.empty () ? SleighIdFromCore (core) : sleigh_id, &std::cout),
	coreMutex (core) {
#if 1
	collectSpecFiles(std::cerr);		///< Gather specification files in normal locations
	auto langs = getLanguageDescriptions ();
#endif
}

void R2Architecture::collectSpecFiles(std::ostream &errs) {
	SleighArchitecture::collectSpecFiles(errs);
}

const std::vector<LanguageDescription> &R2Architecture::getLanguageDescriptions() {
	return SleighArchitecture::getLanguageDescriptions();
}

ProtoModel *R2Architecture::protoModelFromR2CC(const char *cc, bool isEffectiveDefault) {
	if (!cc || !*cc) {
		RCoreLock core (getCore ());
		const char *analysisDefault = r_anal_cc_default (core->anal);
		return R_STR_ISNOTEMPTY (analysisDefault) ? protoModelFromR2CC (analysisDefault, true) : defaultfp;
	}
	auto native = protoModels.find (cc);
	if (native != protoModels.end () && !native->second->isUnknown ()) {
		return native->second;
	}
	auto mapping = cc_map.find (cc);
	if (mapping != cc_map.end ()) {
		for (const auto &name : mapping->second) {
			auto model = protoModels.find (name);
			if (model != protoModels.end () && !model->second->isUnknown ()) {
				return model->second;
			}
		}
	}
	if (isEffectiveDefault) {
		return defaultfp;
	}
	throw LowlevelError ("Unsupported explicit calling convention " + string (cc));
}

void R2Architecture::loadRegisters(const Translate *translate) {
	registers = {};
	if (!translate) {
		return;
	}
	std::map<VarnodeData, std::string> regs;
	translate->getAllRegisters (regs);
	for (const auto &reg : regs) {
		registers[reg.second] = reg.first;
		auto lower = tolower (reg.second);
		if (registers.find(lower) == registers.end()) {
			registers[lower] = reg.first;
		}
	}
}

const VarnodeData *R2Architecture::registerVarnodeFromR2Reg(const char *regname) {
	if (registers.empty ()) {
		// rebuilding here would invalidate every VarnodeData pointer handed out before
		loadRegisters (translate);
	}
	auto it = registers.find (regname);
	if (it == registers.end ()) {
		it = registers.find (tolower (regname));
	}
	return it == registers.end ()? nullptr: &it->second;
}

Address R2Architecture::registerAddressFromR2Reg(const char *regname) {
	const VarnodeData *vn = registerVarnodeFromR2Reg (regname);
	return vn? vn->getAddr (): Address (); // invalid addr if not found
}

std::string R2Architecture::registerNameFromAddress(const Address &addr, int4 size) {
	if (!translate || addr.isInvalid ()) {
		return "";
	}
	// r2 register profiles use lowercase names, sleigh uppercase
	return tolower (translate->getRegisterName (addr.getSpace (), addr.getOffset (), size));
}

Translate *R2Architecture::buildTranslator(DocumentStorage &store) {
	Translate *ret = SleighArchitecture::buildTranslator (store);
	loadRegisters(ret);
	return ret;
}

PcodeInjectLibrary *R2Architecture::buildPcodeInjectLibrary() {
	// Dalvik-only dynamic inject handling lives in Dalvik.inc.cpp; non-Dalvik payloads delegate normally.
	return buildR2DalvikPcodeInjectLibrary (this);
}

ContextDatabase *R2Architecture::getContextDatabase() {
	return context;
}

void R2Architecture::buildConstantPool(DocumentStorage &store) {
	cpool = buildR2DalvikConstantPool (this);
}

void R2Architecture::postSpecFile() {
	registerR2DalvikPostSpecInjects (this);
	RCoreLock core(getCore());
	r_list_foreach_cpp<RAnalFunction>(core->anal->fcns, [&](RAnalFunction *func) {
		if (func->is_noreturn) {
			// Configure noreturn functions
			Funcdata *infd = symboltab->getGlobalScope()->queryFunction(Address(getDefaultCodeSpace(), func->addr));
			if (!infd) {
				return;
			}
			infd->getFuncProto ().setNoReturn(true);
		}
	});
}

void R2Architecture::buildAction(DocumentStorage &store) {
	parseExtraRules (store); // Look for any additional rules
	allacts.universalAction (this);
	allacts.resetDefaults ();
	if (rawptr) {
		allacts.cloneGroup ("decompile", "decompile-deuglified");
		allacts.removeFromGroup ("decompile-deuglified", "fixateglobals"); // this action (ActionMapGlobals) will create these ugly uRam0x12345s
		allacts.setCurrent ("decompile-deuglified");
	}
}

void R2Architecture::buildLoader(DocumentStorage &store) {
	RCoreLock core (getCore ());
	collectSpecFiles (*errorstream);
	loader = new R2LoadImage (getCore (), this);
}

Scope *R2Architecture::buildDatabase(DocumentStorage &store) {
	symboltab = new Database (this, false);
	Scope *globalscope = new R2Scope (this);
	symboltab->attachScope (globalscope, nullptr);
	return globalscope;
}
void R2Architecture::buildCoreTypes(DocumentStorage &store) {
	// TODO: load from r2?
	types->setCoreType ("void", 1, TYPE_VOID, false);

	types->setCoreType ("bool", 1, TYPE_BOOL, false);
	types->setCoreType ("bool4", 4, TYPE_BOOL, false);
	types->setCoreType ("bool8", 8, TYPE_BOOL, false);

	types->setCoreType ("uint8_t", 1, TYPE_UINT, false);
	types->setCoreType ("uint16_t", 2, TYPE_UINT, false);
	types->setCoreType ("uint32_t", 4, TYPE_UINT, false);
	types->setCoreType ("uint64_t", 8, TYPE_UINT, false);
	types->setCoreType ("int8_t", 1, TYPE_INT, false);
	types->setCoreType ("int16_t", 2, TYPE_INT, false);
	types->setCoreType ("int32_t", 4, TYPE_INT, false);
	types->setCoreType ("int64_t", 8, TYPE_INT, false);
	types->setCoreType ("int", types->getSizeOfInt (), TYPE_INT, false);

	types->setCoreType ("double", types->getSizeOfDouble (), TYPE_FLOAT, false);
	types->setCoreType ("float", types->getSizeOfFloat (), TYPE_FLOAT, false);
	types->setCoreType ("float8", 8, TYPE_FLOAT, false);
	types->setCoreType ("float10", 10, TYPE_FLOAT, false);
	types->setCoreType ("float16", 16 ,TYPE_FLOAT, false);

	types->setCoreType ("uchar", types->getSizeOfChar (), TYPE_UNKNOWN, false);
	types->setCoreType ("ushort", types->getSizeOfShort (), TYPE_UNKNOWN, false);
	types->setCoreType ("uint", types->getSizeOfInt (), TYPE_UNKNOWN, false);
	types->setCoreType ("ulong", types->getSizeOfLong (), TYPE_UNKNOWN, false);

	types->setCoreType ("code", 1, TYPE_CODE, false);

	types->setCoreType ("char", types->getSizeOfChar (), TYPE_INT, true);
	types->setCoreType ("wchar", types->getSizeOfWChar (), TYPE_INT, true);
	// types->setCoreType ("char8_t", 1, TYPE_INT, true); // last type defined overrides the previous
	types->setCoreType ("char16_t", 2, TYPE_INT, true);
	types->setCoreType ("char32_t", 4, TYPE_INT, true);

	types->cacheCoreTypes ();
}

void R2Architecture::buildTypegrp(DocumentStorage &store) {
	r2TypeFactory_ = new R2TypeFactory (this);
	types = r2TypeFactory_;
}

void R2Architecture::buildCommentDB(DocumentStorage &store) {
	commentdb = new R2CommentDatabase (this);
}
