// SPDX-FileCopyrightText: 2026 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#include "R2TypeFactory.h"
#include "R2Architecture.h"

#include <fspec.hh>
#include <r_core.h>

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <memory>

using Declaration = std::unique_ptr<RTypeDecl, decltype(&r_type_decl_free)>;

bool R2TypeFactory::hasSegmentedPointers() const {
	return arch->getTarget ().rfind ("x86:LE:16:", 0) == 0 && getSizeOfPointer () == 2 && getSizeOfAltPointer () == 4;
}

RTypePointerKind R2TypeFactory::pointerKind(const TypePointer *type) const {
	if (hasSegmentedPointers () && type->getWordSize () == arch->getDefaultDataSpace ()->getWordSize ()) {
		if (type->getSize () == getSizeOfPointer ()) {
			return R_TYPE_POINTER_NEAR;
		}
		if (type->getSize () == getSizeOfAltPointer ()) {
			return R_TYPE_POINTER_FAR;
		}
	}
	return R_TYPE_POINTER_DEFAULT;
}

Datatype *R2TypeFactory::fromDeclaration(const RTypeDeclNode *node, string *error, TypeResolution &resolution, bool behindPointer, int depth) {
	if (depth > 64) {
		if (error) {
			*error = "Declaration nesting limit exceeded";
		}
		return nullptr;
	}
	if (!node) {
		return nullptr;
	}
	switch (node->kind) {
	case R_TYPE_DECL_BASE: {
		std::string name = node->base.name;
		for (const char *prefix : { "struct ", "union ", "enum " }) {
			if (name.rfind (prefix, 0) == 0) {
				name.erase (0, strlen (prefix));
				break;
			}
		}
		if (name == "void") {
			return getTypeVoid ();
		}
		if (name.rfind ("func.", 0) == 0) {
			return queryR2Function (name.substr (5), resolution);
		}
		if (behindPointer) {
			RCoreLock core (arch->getCore ());
			if (r_type_kind (core->anal->sdb_types, name.c_str ()) == R_TYPE_UNION) {
				// Only the pointer can be complete before its recursive union pointee.
				Datatype *base = TypeFactory::findById (name, 0, 0);
				if (!base) {
					base = getTypeUnion (name);
				}
				if (base->isIncomplete ()) {
					resolution.pendingUnions.push_back (base);
				}
				return base;
			}
		}
		return findByName (name, resolution);
	}
	case R_TYPE_DECL_POINTER: {
		int4 size = getSizeOfPointer ();
		if (node->pointer.kind != R_TYPE_POINTER_DEFAULT) {
			if (!hasSegmentedPointers ()) {
				failTypeConstruction ("Explicit near/far pointers require an x86/16 segmented target");
			}
			if (node->pointer.kind == R_TYPE_POINTER_FAR) {
				size = getSizeOfAltPointer ();
			}
		}
		Datatype *pointee = fromDeclaration (node->child, error, resolution, true, depth + 1);
		return pointee ? getTypePointer (size, pointee, arch->getDefaultDataSpace ()->getWordSize ()) : nullptr;
	}
	case R_TYPE_DECL_ARRAY: {
		errno = 0;
		char *end = nullptr;
		const long count = strtol (node->array.count, &end, 10);
		const bool validCount = end != node->array.count && !*end && errno != ERANGE && count > 0 && count <= INT_MAX;
		Datatype *element = fromDeclaration (node->child, error, resolution, false, depth + 1);
		if (!validCount || !element || element->isIncomplete () || element->getMetatype () == TYPE_CODE || element->getMetatype () == TYPE_VOID || element->getAlignSize () < 1 || count > INT_MAX / element->getAlignSize ()) {
			if (error) {
				*error = "Invalid or oversized array type";
			}
			return nullptr;
		}
		return getTypeArray (count, element);
	}
	case R_TYPE_DECL_FUNCTION: {
		if (!arch->defaultfp) {
			return getTypeCode ();
		}
		PrototypePieces proto;
		proto.model = arch->defaultfp;
		proto.firstVarArgSlot = -1;
		proto.outtype = fromDeclaration (node->child, error, resolution, false, depth + 1);
		if (!proto.outtype || proto.outtype->getMetatype () == TYPE_ARRAY || proto.outtype->getMetatype () == TYPE_CODE) {
			return nullptr;
		}
		for (RListIter *iter = node->function.parameters->head; iter; iter = iter->n) {
			auto param = static_cast<const RTypeDecl *>(iter->data);
			const bool arrayParameter = param->type->kind == R_TYPE_DECL_ARRAY;
			Datatype *type = fromDeclaration (arrayParameter ? param->type->child : param->type, error, resolution, arrayParameter, depth + 1);
			if (!type || type->getMetatype () == TYPE_VOID) {
				return nullptr;
			}
			// C parameter adjustment is distinct from object declaration interpretation.
			if (arrayParameter) {
				type = getTypePointer (getSizeOfPointer (), type, arch->getDefaultDataSpace ()->getWordSize ());
			} else if (type->getMetatype () == TYPE_ARRAY) {
				type = getTypePointer (getSizeOfPointer (), static_cast<TypeArray *>(type)->getBase (), arch->getDefaultDataSpace ()->getWordSize ());
			} else if (type->getMetatype () == TYPE_CODE) {
				type = getTypePointer (getSizeOfPointer (), type, arch->getDefaultDataSpace ()->getWordSize ());
			}
			proto.intypes.push_back (type);
			proto.innames.push_back (param->name ? param->name : "");
		}
		if (node->function.variadic || !node->function.prototype) {
			proto.firstVarArgSlot = proto.intypes.size ();
		}
		return getTypeCode (proto);
	}
	case R_TYPE_DECL_LVALUE_REFERENCE:
	case R_TYPE_DECL_RVALUE_REFERENCE:
		failTypeConstruction ("C++ references are not supported by native type import");
	}
	return nullptr;
}

RTypeDecl *R2TypeFactory::toDeclaration(Datatype *type, int depth) const {
	if (!type || depth > 64) {
		return nullptr;
	}
	Declaration decl (R_NEW0 (RTypeDecl), r_type_decl_free);
	decl->type = R_NEW0 (RTypeDeclNode);
	RTypeDeclNode *node = decl->type;
	if (type->getTypedef ()) {
		node->kind = R_TYPE_DECL_BASE;
		node->base.name = strdup (type->getName ().c_str ());
		return decl.release ();
	}
	switch (type->getMetatype ()) {
	case TYPE_PTR:
	case TYPE_PTRREL: {
		auto pointer = static_cast<TypePointer *>(type);
		node->kind = R_TYPE_DECL_POINTER;
		node->pointer.kind = pointerKind (pointer);
		// A coordinate-sized analysis pointer may not be an expressible C pointer.
		if (node->pointer.kind == R_TYPE_POINTER_DEFAULT && (pointer->getSize () != getSizeOfPointer () || pointer->getWordSize () != arch->getDefaultDataSpace ()->getWordSize ())) {
			return nullptr;
		}
		Declaration child (toDeclaration (pointer->getPtrTo (), depth + 1), r_type_decl_free);
		if (!child) {
			return nullptr;
		}
		node->child = child->type;
		child->type = nullptr;
		break;
	}
	case TYPE_ARRAY: {
		auto array = static_cast<TypeArray *>(type);
		node->kind = R_TYPE_DECL_ARRAY;
		node->array.count = strdup (std::to_string (array->numElements ()).c_str ());
		Declaration child (toDeclaration (array->getBase (), depth + 1), r_type_decl_free);
		if (!child) {
			return nullptr;
		}
		node->child = child->type;
		child->type = nullptr;
		break;
	}
	case TYPE_CODE: {
		const FuncProto *proto = static_cast<TypeCode *>(type)->getPrototype ();
		if (!proto) {
			return nullptr;
		}
		node->kind = R_TYPE_DECL_FUNCTION;
		node->function.parameters = r_list_newf (reinterpret_cast<RListFree> (r_type_decl_free));
		// Native C printing uses a no-fixed-argument vararg prototype for ().
		node->function.prototype = !proto->isDotdotdot () || proto->numParams () > 0;
		node->function.variadic = proto->isDotdotdot () && proto->numParams () > 0;
		Declaration child (toDeclaration (proto->getOutputType (), depth + 1), r_type_decl_free);
		if (!child) {
			return nullptr;
		}
		node->child = child->type;
		child->type = nullptr;
		for (int4 i = 0; i < proto->numParams (); i++) {
			ProtoParameter *param = proto->getParam (i);
			Declaration parameter (toDeclaration (param->getType (), depth + 1), r_type_decl_free);
			if (!parameter) {
				return nullptr;
			}
			if (!param->isNameUndefined ()) {
				parameter->name = strdup (param->getName ().c_str ());
			}
			if (!r_list_append (node->function.parameters, parameter.get ())) {
				return nullptr;
			}
			parameter.release ();
		}
		break;
	}
	case TYPE_UNKNOWN:
		if (type->getSize () != 1 && type->getSize () != 2 && type->getSize () != 4 && type->getSize () != 8) {
			return nullptr;
		}
		node->base.name = strdup (("uint" + std::to_string (type->getSize () * 8) + "_t").c_str ());
		break;
	case TYPE_VOID:
		node->base.name = strdup ("void");
		break;
	case TYPE_INT:
	case TYPE_UINT:
	case TYPE_BOOL:
	case TYPE_FLOAT:
	case TYPE_STRUCT:
	case TYPE_UNION:
	case TYPE_ENUM_INT:
	case TYPE_ENUM_UINT:
		if (type->getName ().empty ()) {
			return nullptr;
		}
		node->base.name = strdup (type->getName ().c_str ());
		break;
	default:
		return nullptr;
	}
	return decl.release ();
}

std::string R2TypeFactory::toCString(Datatype *type) const {
	Declaration decl (toDeclaration (type, 0), r_type_decl_free);
	if (!decl) {
		return "";
	}
	char *text = r_type_decl_render (decl.get (), false);
	std::string result = text ? text : "";
	free (text);
	return result;
}
