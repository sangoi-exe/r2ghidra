// SPDX-FileCopyrightText: 2019-2022 thestr4ng3r, pancake
// SPDX-License-Identifier: LGPL-3.0-only

#include "R2TypeFactory.h"
#include "R2Architecture.h"
#include "R2TypeCompat.h"
#include "fspec.hh"

#include <r_core.h>
#include <cctype>
#include <cstring>
#include <sstream>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <utility>
#include <algorithm>
#include <memory>
#include <numeric>

// Compatibility for older radare2 versions that don't have these type kinds
#ifndef R_TYPE_BASIC
#define R_TYPE_BASIC 0
#endif
#ifndef R_TYPE_FUNCTION
#define R_TYPE_FUNCTION 5
#endif

#include "R2Utils.h"

R2TypeFactory::R2TypeFactory(R2Architecture *arch) : TypeFactory (arch), arch (arch) {
}

R2TypeFactory::~R2TypeFactory() {
}

void R2TypeFactory::checkTypeConstruction() const {
	if (!typeConstructionError.empty ()) {
		throw LowlevelError (typeConstructionError);
	}
}

void R2TypeFactory::failTypeConstruction(const string &error) {
	if (typeConstructionError.empty ()) {
		typeConstructionError = error;
	}
	throw LowlevelError (typeConstructionError);
}

void R2TypeFactory::completeResolution(TypeResolution &resolution) {
	// Drain only at the outward boundary; containing by-value layouts are complete here.
	for (size_t i = 0; i < resolution.pendingAggregates.size (); i++) {
		Datatype *pointee = resolution.pendingAggregates[i];
		if (pointee->isIncomplete ()) {
			Datatype *type = queryR2 (pointee->getName (), resolution);
			if (!type || type->isIncomplete ()) {
				failTypeConstruction ("Failed to construct complete aggregate " + pointee->getName ());
			}
		}
	}
	resolveIncompleteTypedefs ();
}


static type_metatype formatToMeta(const char *fmt) {
	if (!fmt || !fmt[0]) {
		return TYPE_UNKNOWN;
	}
	switch (fmt[0]) {
	case 'd':
	case 'i':
	case 'c':
		return TYPE_INT;
	case 'u':
	case 'x':
	case 'o':
	case 'p':
		return TYPE_UINT;
	case 'f':
	case 'F':
		return TYPE_FLOAT;
	default:
		return TYPE_UNKNOWN;
	}
}

static std::string trim_ws(const std::string &in) {
	const auto start = in.find_first_not_of(" \t\n\r");
	if (start == std::string::npos) {
		return "";
	}
	const auto end = in.find_last_not_of(" \t\n\r");
	return in.substr(start, end - start + 1);
}

static std::string normalize_ws(const std::string &in) {
	std::stringstream ss(in);
	std::string token;
	std::string out;
	while (ss >> token) {
		if (!out.empty()) {
			out += " ";
		}
		out += token;
	}
	return out;
}

static std::string to_lower_ascii(const std::string &in) {
	std::string out;
	out.reserve(in.size());
	for (unsigned char ch : in) {
		out.push_back(static_cast<char>(std::tolower(ch)));
	}
	return out;
}

static bool ends_with(const std::string &str, const std::string &suffix) {
	if (suffix.size() > str.size()) {
		return false;
	}
	return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static int4 atoi_or(const std::string &s, int4 fallback) {
	errno = 0;
	char *end = nullptr;
	const long v = std::strtol(s.c_str(), &end, 10);
	if (end != s.c_str() + s.size() || errno == ERANGE || v < INT_MIN || v > INT_MAX) {
		return fallback;
	}
	return static_cast<int4>(v);
}

static bool parse_bits_suffix(const std::string &name, const std::string &prefix, int4 &size_out) {
	if (!r_str_startswith(name.c_str(), prefix.c_str())) {
		return false;
	}
	std::string rest = name.substr(prefix.size());
	if (ends_with(rest, "_t")) {
		rest = rest.substr(0, rest.size() - 2);
	}
	if (rest.empty()) {
		return false;
	}
	const int4 bits = atoi_or(rest, -1);
	if (bits <= 0 || (bits % 8) != 0) {
		return false;
	}
	size_out = bits / 8;
	return true;
}

struct BuiltinTypeSpec {
	int4 size = 0;
	type_metatype meta = TYPE_UNKNOWN;
};

static bool get_builtin_spec(const R2TypeFactory *factory, const std::string &name, BuiltinTypeSpec &spec) {
	const std::string lower = to_lower_ascii(name);

	if (lower == "size_t" || lower == "uintptr_t") {
		spec.size = factory->getSizeOfPointer();
		spec.meta = TYPE_UINT;
		return true;
	}
	if (lower == "ssize_t" || lower == "intptr_t" || lower == "ptrdiff_t") {
		spec.size = factory->getSizeOfPointer();
		spec.meta = TYPE_INT;
		return true;
	}
	if (lower == "bool" || lower == "_bool") {
		spec.size = 1;
		spec.meta = TYPE_BOOL;
		return true;
	}
	if (lower == "wchar_t") {
		spec.size = factory->getSizeOfWChar();
		spec.meta = TYPE_INT;
		return true;
	}
	if (lower == "uchar") {
		spec.size = factory->getSizeOfChar();
		spec.meta = TYPE_UINT;
		return true;
	}
	if (lower == "schar") {
		spec.size = factory->getSizeOfChar();
		spec.meta = TYPE_INT;
		return true;
	}
	if (lower == "ulonglong") {
		spec.size = factory->getSizeOfLongLong();
		spec.meta = TYPE_UINT;
		return true;
	}
	if (lower == "longlong") {
		spec.size = factory->getSizeOfLongLong();
		spec.meta = TYPE_INT;
		return true;
	}

	int4 size = 0;
	if (parse_bits_suffix(lower, "uint", size) ||
		parse_bits_suffix(lower, "ut", size) ||
		parse_bits_suffix(lower, "u", size)) {
		spec.size = size;
		spec.meta = TYPE_UINT;
		return true;
	}
	if (parse_bits_suffix(lower, "int", size) ||
		parse_bits_suffix(lower, "st", size) ||
		parse_bits_suffix(lower, "s", size)) {
		spec.size = size;
		spec.meta = TYPE_INT;
		return true;
	}

	std::stringstream ss(lower);
	std::string token;
	bool is_unsigned = false;
	bool is_signed = false;
	bool is_short = false;
	bool is_char = false;
	bool is_int = false;
	bool is_float = false;
	bool is_double = false;
	bool is_bool = false;
	bool is_wchar = false;
	int long_count = 0;
	int4 explicit_size = 0;
	while (ss >> token) {
		if (token == "const" || token == "volatile" || token == "restrict") {
			continue;
		}
		if (token == "unsigned") {
			is_unsigned = true;
			continue;
		}
		if (token == "signed") {
			is_signed = true;
			continue;
		}
		if (token == "short") {
			is_short = true;
			continue;
		}
		if (token == "long") {
			long_count++;
			continue;
		}
		if (token == "char") {
			is_char = true;
			continue;
		}
		if (token == "int") {
			is_int = true;
			continue;
		}
		if (token == "float") {
			is_float = true;
			continue;
		}
		if (token == "double") {
			is_double = true;
			continue;
		}
		if (token == "bool" || token == "_bool") {
			is_bool = true;
			continue;
		}
		if (token == "wchar_t") {
			is_wchar = true;
			continue;
		}
		int4 tok_size = 0;
		if (parse_bits_suffix(token, "uint", tok_size) || parse_bits_suffix(token, "ut", tok_size)) {
			explicit_size = tok_size;
			is_unsigned = true;
			continue;
		}
		if (parse_bits_suffix(token, "int", tok_size) || parse_bits_suffix(token, "st", tok_size)) {
			explicit_size = tok_size;
			continue;
		}
		return false;
	}

	if (explicit_size > 0) {
		spec.size = explicit_size;
		spec.meta = is_unsigned ? TYPE_UINT : TYPE_INT;
		return true;
	}
	if (is_bool) {
		spec.size = 1;
		spec.meta = TYPE_BOOL;
		return true;
	}
	if (is_wchar) {
		spec.size = factory->getSizeOfWChar();
		spec.meta = TYPE_INT;
		return true;
	}
	if (is_float || is_double) {
		spec.meta = TYPE_FLOAT;
		if (is_float) {
			spec.size = factory->getSizeOfFloat();
		} else if (long_count > 0) {
			spec.size = factory->getSizeOfLongDouble();
		} else {
			spec.size = factory->getSizeOfDouble();
		}
		return true;
	}
	if (is_char) {
		spec.size = factory->getSizeOfChar();
		spec.meta = is_unsigned ? TYPE_UINT : TYPE_INT;
		return true;
	}
	if (is_short) {
		spec.size = factory->getSizeOfShort();
		spec.meta = is_unsigned ? TYPE_UINT : TYPE_INT;
		return true;
	}
	if (long_count >= 2) {
		spec.size = factory->getSizeOfLongLong();
		spec.meta = is_unsigned ? TYPE_UINT : TYPE_INT;
		return true;
	}
	if (long_count == 1) {
		spec.size = factory->getSizeOfLong();
		spec.meta = is_unsigned ? TYPE_UINT : TYPE_INT;
		return true;
	}
	if (is_int || is_unsigned || is_signed) {
		spec.size = factory->getSizeOfInt();
		spec.meta = is_unsigned ? TYPE_UINT : TYPE_INT;
		return true;
	}
	return false;
}

static Datatype *base_or_unknown(R2TypeFactory *factory, int4 size, type_metatype meta) {
	Datatype *base = factory->getBase(size, meta);
	if (!base && meta != TYPE_UNKNOWN) {
		base = factory->getBase(size, TYPE_UNKNOWN);
	}
	return base;
}

static Datatype *make_typedef(R2TypeFactory *factory, Datatype *base, const std::string &name) {
	Datatype *typedefd = factory->getTypedef(base, name, 0, 0);
	factory->setName(typedefd, name);
	factory->setName(base, base->getName());
	return typedefd;
}

Datatype *R2TypeFactory::queryR2Base(const string &n) {
	RCoreLock core(arch->getCore());
	Sdb *sdb = core->anal->sdb_types;
	int4 size = 0;
	type_metatype meta = TYPE_UNKNOWN;
	BuiltinTypeSpec builtin;
	if (get_builtin_spec(this, n, builtin)) {
		size = builtin.size;
		meta = builtin.meta;
	} else {
		ut64 bits = r_type_get_bitsize(sdb, n.c_str());
		if (!bits || (bits % 8) != 0) {
			return nullptr;
		}
		size = bits / 8;
		char *format = r_type_format (sdb, n.c_str ());
		meta = formatToMeta (format);
		free (format);
	}
	Datatype *base = base_or_unknown(this, size, meta);
	if (!base) {
		return nullptr;
	}
	return make_typedef(this, base, n);
}

Datatype *R2TypeFactory::queryR2Struct(const string &n, TypeResolution &resolution) {
	RCoreLock core(arch->getCore ());
	std::unique_ptr<RAnalBaseType, decltype(&r_anal_base_type_free)> native (r_anal_get_base_type (core->anal, n.c_str ()), r_anal_base_type_free);
	if (!native) {
		return nullptr;
	}
	if (native->kind != R_ANAL_BASE_TYPE_KIND_STRUCT || native->size % 8 || native->size / 8 > INT_MAX) {
		return nullptr;
	}
	std::vector<TypeField> fields;
	try {
		TypeStruct *r = getTypeStruct(n);
		int4 maxAlign = 1;
		int4 layoutAlign = 0;
		int4 structSize = 0;
		RAnalTypeMember *member;
		R_VEC_FOREACH (r_anal_base_type_members (native.get ()), member) {
			Datatype *memberType = fromCStringResolved (member->type, nullptr, resolution);
			if (!memberType) {
				arch->addWarning ("Failed to match type " + std::string(member->type) + " of member " + member->name + " in struct " + n);
				return nullptr;
			}
			if (memberType->getMetatype () == TYPE_CODE) {
				failTypeConstruction ("Function member requires an explicit pointer in " + n);
			}
			if (member->count) {
				const int4 stride = memberType->getAlignSize();
				if (stride < 1 || member->count > static_cast<size_t>(INT_MAX / stride)) {
					return nullptr;
				}
				memberType = getTypeArray (static_cast<int4>(member->count), memberType);
			}
			if (member->offset > INT_MAX) {
				return nullptr;
			}
			const int4 offset = member->offset;
			if (memberType->getSize() > INT_MAX - offset) {
				return nullptr;
			}
			TypeField tf = {
				offset, // id = offset by default
				offset,
				member->name,
				memberType
			};
			fields.push_back(tf);
			maxAlign = std::max(maxAlign, memberType->getAlignment());
			layoutAlign = std::gcd(layoutAlign, offset);
			structSize = std::max(structSize, offset + memberType->getSize());
		}
		if (fields.empty ()) {
			arch->addWarning ("Struct " + n + " has no fields.");
			return nullptr;
		}
		int4 align = std::gcd(maxAlign, layoutAlign);
		if (native->size) {
			const int4 declaredSize = native->size / 8;
			if (declaredSize < structSize) {
				arch->addWarning ("Declared size is smaller than fields in struct " + n);
				return nullptr;
			}
			structSize = declaredSize;
			align = std::gcd(align, structSize);
		} else {
			const int4 rem = structSize % align;
			if (rem) {
				if (structSize > INT_MAX - (align - rem)) {
					return nullptr;
				}
				structSize += align - rem;
			}
		}
		// Host offsets and explicit extent constrain analysis alignment, not historical ABI alignment.
		std::stable_sort(fields.begin(), fields.end(), [](const TypeField &a, const TypeField &b) { return a.offset < b.offset; });
		setFields (fields, {}, r, structSize, align, 0);
		resolveIncompleteTypedefs ();
		return r;
	} catch (std::invalid_argument &e) {
		arch->addWarning ("Failed to load struct " + n + " from sdb.");
		return nullptr;
	}
}

Datatype *R2TypeFactory::queryR2Union(const string &n, TypeResolution &resolution) {
	RCoreLock core(arch->getCore ());
	std::unique_ptr<RAnalBaseType, decltype(&r_anal_base_type_free)> native (r_anal_get_base_type (core->anal, n.c_str ()), r_anal_base_type_free);
	if (!native) {
		arch->addWarning ("Failed to load union " + n + " from sdb.");
		return nullptr;
	}
	if (native->kind != R_ANAL_BASE_TYPE_KIND_UNION || native->size % 8 || native->size / 8 > INT_MAX) {
		arch->addWarning ("Invalid declared extent for union " + n);
		return nullptr;
	}
	std::vector<TypeField> fields;
	try {
		TypeUnion *r = getTypeUnion(n);
		int4 maxAlign = 1;
		int4 unionSize = 0;
		RAnalTypeMember *member;
		R_VEC_FOREACH (r_anal_base_type_members (native.get ()), member) {
			if (member->offset) {
				arch->addWarning ("Nonzero offset for member " + std::string(member->name) + " in union " + n);
				return nullptr;
			}
			Datatype *memberType = fromCStringResolved (member->type, nullptr, resolution);
			if (!memberType) {
				arch->addWarning ("Failed to match type " + std::string(member->type) + " of member " + member->name + " in union " + n);
				return nullptr;
			}
			if (memberType->getMetatype () == TYPE_CODE) {
				failTypeConstruction ("Function member requires an explicit pointer in " + n);
			}
			if (memberType->isIncomplete () || memberType->getSize () < 1) {
				arch->addWarning ("Incomplete member " + std::string(member->name) + " in union " + n);
				return nullptr;
			}
			if (member->count) {
				const int4 stride = memberType->getAlignSize();
				if (stride < 1 || member->count > static_cast<size_t>(INT_MAX / stride)) {
					arch->addWarning ("Invalid array extent for member " + std::string(member->name) + " in union " + n);
					return nullptr;
				}
				memberType = getTypeArray (static_cast<int4>(member->count), memberType);
			}
			TypeField tf = {
				0,
				0,
				member->name,
				memberType
			};
			fields.push_back(tf);
			maxAlign = std::max(maxAlign, memberType->getAlignment());
			unionSize = std::max(unionSize, memberType->getSize());
		}

		if (fields.empty ()) {
			arch->addWarning ("Union " + n + " has no fields.");
			return nullptr;
		}
		if (native->size) {
			const int4 declaredSize = native->size / 8;
			if (declaredSize < unionSize) {
				arch->addWarning ("Declared size is smaller than fields in union " + n);
				return nullptr;
			}
			unionSize = declaredSize;
			maxAlign = std::gcd(maxAlign, unionSize);
		} else {
			const int4 rem = unionSize % maxAlign;
			if (rem) {
				if (unionSize > INT_MAX - (maxAlign - rem)) {
					arch->addWarning ("Union extent exceeds native size limit for " + n);
					return nullptr;
				}
				unionSize += maxAlign - rem;
			}
		}
		setFields (fields, r, unionSize, maxAlign, 0);
		resolveIncompleteTypedefs ();
		return r;
	} catch (std::invalid_argument &e) {
		arch->addWarning ("Failed to load union " + n + " from sdb.");
		return nullptr;
	}
}

Datatype *R2TypeFactory::queryR2Enum(const string &n, TypeResolution &resolution) {
	RCoreLock core (arch->getCore ());
	RList *members = r_type_get_enum (core->anal->sdb_types, n.c_str ());
	if (!members) {
		Sdb *sdb = core->anal->sdb_types;
		const char *alias = sdb_const_get (sdb, ("typedef." + n).c_str (), nullptr);
		return alias ? queryR2Typedef(n, resolution, false) : nullptr;
	}

	std::vector<std::string> namelist;
	std::vector<uintb> vallist;
	std::vector<bool> assignlist;

	r_list_foreach_cpp <RTypeEnum>(members, [&](RTypeEnum *member) {
		if (!member->name || !member->val) {
			return;
		}
		uintb val = std::stoull (member->val, nullptr, 0);
		namelist.push_back (member->name);
		vallist.push_back (val);
		assignlist.push_back (true); // all enum values from r2 have explicit values
	});
	r_list_free (members);

	if (namelist.empty()) {
		return nullptr;
	}
	try {
		auto enumType = getTypeEnum(n);
		map<uintb,string> namemap;
		TypeEnum::assignValues(namemap,namelist,vallist,assignlist,enumType);
		setEnumValues(namemap, enumType);
		return enumType;
	} catch (LowlevelError &e) {
		arch->addWarning("Failed to load " + n);
		return nullptr;
	}
}

Datatype *R2TypeFactory::queryR2Function(const string &n, TypeResolution &resolution) {
	RCoreLock core(arch->getCore());
	Sdb *sdb = core->anal->sdb_types;

	const char *ret = r_type_func_ret(sdb, n.c_str());
	RTypeFunctionPrototype prototype;
	if (!r_type_func_get_prototype (sdb, n.c_str (), &prototype) || prototype == R_TYPE_FUNC_PROTOTYPE_UNKNOWN) {
		failTypeConstruction ("Unavailable parameter-list knowledge for function type " + n);
	}
	int arg_count = 0;
	if (prototype == R_TYPE_FUNC_PROTOTYPE_FIXED && !countargs (sdb, n.c_str (), &arg_count)) {
		failTypeConstruction ("Unavailable parameter count for function type " + n);
	}
	if (!ret) {
		failTypeConstruction ("Missing return type for function type " + n);
	}

	PrototypePieces proto;
	if (!arch->defaultfp) {
		failTypeConstruction ("Missing prototype model for function type " + n);
	}
	proto.model = arch->defaultfp;
	proto.name = n;
	proto.firstVarArgSlot = prototype == R_TYPE_FUNC_PROTOTYPE_UNSPECIFIED ? 0 : -1;
	proto.outtype = fromCStringResolved (ret, nullptr, resolution);
	if (proto.outtype && (proto.outtype->getMetatype () == TYPE_CODE || proto.outtype->getMetatype () == TYPE_ARRAY)) {
		failTypeConstruction ("Invalid function return type in " + n);
	}
	if (!proto.outtype) {
		failTypeConstruction ("Failed to resolve return type in " + n);
	}

	for (int i = 0; i < arg_count; i++) {
		std::unique_ptr<char, decltype(&free)> arg_type (r_type_func_args_type (sdb, n.c_str (), i), free);
		const char *arg_name = r_type_func_args_name(sdb, n.c_str(), i);
		// the variadic slot is stored as `,...` so the marker lands in the name, not the type
		if ((arg_type && !strcmp(arg_type.get (), "...")) || (arg_name && !strcmp(arg_name, "..."))) {
			proto.firstVarArgSlot = proto.intypes.size();
			continue;
		}

		Datatype *arg = nullptr;
		if (arg_type && *arg_type) {
			arg = fromCStringResolved(arg_type.get (), nullptr, resolution);
			if (!arg) {
				failTypeConstruction ("Failed to resolve parameter type in " + n);
			}
		}
		if (arg && arg->getMetatype () == TYPE_CODE) {
			failTypeConstruction ("Function parameter requires an explicit pointer in " + n);
		}
		if (!arg) {
			failTypeConstruction ("Missing parameter type in " + n);
		}
		proto.intypes.push_back(arg);
		proto.innames.push_back(arg_name ? arg_name : "");

	}

	return getTypeCode(proto);
}

Datatype *R2TypeFactory::queryR2Typedef(const string &n, TypeResolution &resolution, bool behindPointer) {
	RCoreLock core(arch->getCore());
	Sdb *sdb = core->anal->sdb_types;
	const char *target = sdb_const_get (sdb, ("typedef." + n).c_str (), nullptr);
	if(!target) {
		return nullptr;
	}
	Datatype *resolved = fromCStringResolved (target, nullptr, resolution, behindPointer);
	if (!resolved) {
		return nullptr;
	}
	Datatype *typedefd = getTypedef (resolved, n, 0, 0);
	setName (typedefd, n); // this removes the old name from the nametree
	setName (resolved, resolved->getName()); // add the old name back
	return typedefd;
}

Datatype *R2TypeFactory::queryR2(const string &n, TypeResolution &resolution, bool behindPointer) {
	if (n.empty()) {
		return nullptr;
	}
	if (resolution.stackTypes.find (n) != resolution.stackTypes.end ()) {
		arch->addWarning("Recursion detected while creating type " + n);
		return nullptr;
	}
	resolution.stackTypes.insert (n);
	struct StackEntry {
		std::set<std::string> &stack;
		const string &name;
		~StackEntry() { stack.erase (name); }
	} entry{resolution.stackTypes, n};

	RCoreLock core (arch->getCore ());
	int kind = r_type_kind (core->anal->sdb_types, n.c_str ());
	switch (kind) {
	case R_TYPE_BASIC:
		return queryR2Base(n);
	case R_TYPE_STRUCT:
	case R_TYPE_UNION: {
		try {
			Datatype *type = kind == R_TYPE_STRUCT ? queryR2Struct (n, resolution) : queryR2Union (n, resolution);
			if (!type || type->isIncomplete ()) {
				throw LowlevelError (string ("Failed to construct complete ") + (kind == R_TYPE_STRUCT ? "struct " : "union ") + n);
			}
			return type;
		} catch (const LowlevelError &error) {
			// Recursive dependents retain the identity; keep ownership but refuse further resolution.
			failTypeConstruction (error.explain);
		}
	}
	case R_TYPE_ENUM:
		return queryR2Enum (n, resolution);
	case R_TYPE_TYPEDEF:
		return queryR2Typedef (n, resolution, behindPointer);
	case R_TYPE_FUNCTION:
		return queryR2Function (n, resolution);
	default:
		return nullptr;
	}
}

Datatype *R2TypeFactory::findByIdResolved(const string &n, uint8 id, int4 sz, TypeResolution &resolution, Datatype *r, bool resolvedBase, bool behindPointer) {
	// resolve basic types
	if (!resolvedBase) {
		r = TypeFactory::findById (n, id, sz);
	}
	if (r == nullptr && n.empty()) {
		int4 fallback_size = (sz > 0) ? sz : 1;
		return getBase(fallback_size, TYPE_UNKNOWN);
	}
	// re-parsing a name already on the resolution stack would recurse forever
	const bool revisiting = resolution.stackTypes.find (n) != resolution.stackTypes.end ();
	if (r == nullptr || (r->isIncomplete () && !behindPointer && !revisiting)) {
		r = queryR2 (n, resolution, behindPointer);
	}
	if (r == nullptr && !revisiting) {
		const bool needs_parse =
			n.find('*') != std::string::npos ||
			n.rfind("const ", 0) == 0 ||
			n.rfind("volatile ", 0) == 0 ||
			n.rfind("struct ", 0) == 0 ||
			n.rfind("enum ", 0) == 0 ||
			n.rfind("union ", 0) == 0 ||
			n.rfind("func.", 0) == 0;
		if (needs_parse) {
			r = fromCStringResolved (n, nullptr, resolution);
		}
	}
	if (r == nullptr) {
		BuiltinTypeSpec builtin;
		if (get_builtin_spec (this, n, builtin)) {
			r = base_or_unknown (this, builtin.size, builtin.meta);
		}
	}
	return r;
}

Datatype *R2TypeFactory::findById(const string &n, uint8 id, int4 sz, std::set<std::string> &stackTypes) {
	checkTypeConstruction ();
	TypeResolution resolution{ stackTypes, {} };
	Datatype *type = findByIdResolved (n, id, sz, resolution, nullptr, false);
	completeResolution (resolution);
	return type;
}

// overriden call
Datatype *R2TypeFactory::findById(const string &n, uint8 id, int4 sz) {
	checkTypeConstruction ();
	Datatype *r = TypeFactory::findById (n, id, sz);
	// Native typerefs may refer to opaque identities; declarations check completeness separately.
	if (r) {
		return r;
	}
	// The slow path resolves declared names independently of the requested storage size.
	const bool cacheable = !n.empty () && sz <= 0;
	if (cacheable) {
		auto it = lookupCache.find (n);
		if (it != lookupCache.end ()) {
			return it->second;
		}
	}
	std::set<std::string> stackTypes; // to detect recursion
	TypeResolution resolution{ stackTypes, {} };
	r = findByIdResolved (n, id, sz, resolution, r, true);
	completeResolution (resolution);
	if (cacheable) {
		lookupCache[n] = r;
	}
	return r;
}

Datatype *R2TypeFactory::fromCString(const string &str, string *error, std::set<std::string> *stackTypes) {
	checkTypeConstruction ();
	const bool toplevel = !stackTypes || stackTypes->empty ();
	std::set<std::string> localStack;
	TypeResolution resolution{ stackTypes ? *stackTypes : localStack, {} };
	std::string parseError;
	Datatype *type = fromCStringResolved (str, &parseError, resolution);
	completeResolution (resolution);
	std::string key = normalize_ws (trim_ws (str));
	if (toplevel && !key.empty ()) {
		cstringCache.insert_or_assign (std::move(key), CStringCacheEntry{ type, parseError });
	}
	if (error && !type) {
		*error = parseError;
	}
	return type;
}

Datatype *R2TypeFactory::fromCStringResolved(const string &str, string *error, TypeResolution &resolution, bool behindPointer) {
	checkTypeConstruction ();
	std::string key = normalize_ws (trim_ws (str));
	if (key.empty ()) {
		return nullptr;
	}
	auto it = cstringCache.find (key);
	if (it != cstringCache.end ()) {
		const CStringCacheEntry &entry = it->second;
		if (error && !entry.type) {
			*error = entry.error;
		}
		return entry.type;
	}
	char *parseError = nullptr;
	std::unique_ptr<RTypeDecl, decltype(&r_type_decl_free)> decl (r_type_decl_parse (key.c_str (), R_TYPE_DECL_CONTEXT_ABSTRACT, core->anal->sdb_types, &parseError), r_type_decl_free);
	if (!decl) {
		if (error) {
			*error = parseError ? parseError : "Invalid type declaration";
		}
		free (parseError);
		return nullptr;
	}
	free (parseError);
	return fromDeclaration (decl->type, error, resolution, behindPointer);
}
