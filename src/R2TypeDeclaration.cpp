// SPDX-FileCopyrightText: 2026 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#include "R2TypeFactory.h"
#include "R2Architecture.h"

#include <fspec.hh>
#include <r_core.h>

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
	if (!node) {
		return nullptr;
	}
	if (node->qualifiers & ~(R_TYPE_DECL_CONST | R_TYPE_DECL_VOLATILE)) {
		failTypeConstruction ("Unsupported restrict or atomic qualification in native type import");
	}
	Datatype *type = fromUnqualifiedDeclaration (node, error, resolution, behindPointer, depth);
	uint4 qualifiers = 0;
	if (node->qualifiers & R_TYPE_DECL_CONST) {
		qualifiers |= Datatype::qualifier_const;
	}
	if (node->qualifiers & R_TYPE_DECL_VOLATILE) {
		qualifiers |= Datatype::qualifier_volatile;
	}
	return type ? getQualifiedType (type, qualifiers) : nullptr;
}

Datatype *R2TypeFactory::fromUnqualifiedDeclaration(const RTypeDeclNode *node, string *error, TypeResolution &resolution, bool behindPointer, int depth) {
	if (depth > 64) {
		if (error) {
			*error = "Declaration nesting limit exceeded";
		}
		return nullptr;
	}
	switch (node->kind) {
	case R_TYPE_DECL_BASE: {
		const string name = node->base.name;
		if (name == "void") {
			return getTypeVoid ();
		}
		if (name.rfind ("func.", 0) == 0) {
			return findByName (name, resolution, behindPointer);
		}
		RCoreLock core (arch->getCore ());
		const RTypeKind kind = r_type_kind (core->anal->sdb_types, name.c_str ());
		const string rawName = nativeName (name);
		RTypeKind tagKind = R_TYPE_INVALID;
		if (name.rfind ("struct ", 0) == 0) {
			tagKind = R_TYPE_STRUCT;
		} else if (name.rfind ("union ", 0) == 0) {
			tagKind = R_TYPE_UNION;
		} else if (name.rfind ("enum ", 0) == 0) {
			tagKind = R_TYPE_ENUM;
		}
		if (tagKind != R_TYPE_INVALID) {
			Sdb *tags = r_type_namespace (core->anal->sdb_types, R_TYPE_NAMESPACE_TAG, false);
			const RTypeKind actualKind = tags ? r_type_kind (tags, rawName.c_str ()) : R_TYPE_INVALID;
			if (actualKind != R_TYPE_INVALID && actualKind != tagKind) {
				failTypeConstruction ("Conflicting aggregate tag for " + rawName);
			}
		}
		const RTypeKind aggregateKind = tagKind != R_TYPE_INVALID ? tagKind : kind;
		if (behindPointer && (aggregateKind == R_TYPE_STRUCT || aggregateKind == R_TYPE_UNION)) {
			Datatype *base = TypeFactory::findById (rawName, nativeId (name), 0);
			const type_metatype meta = aggregateKind == R_TYPE_STRUCT ? TYPE_STRUCT : TYPE_UNION;
			if (base && base->getMetatype () != meta) {
				failTypeConstruction ("Conflicting aggregate identity for " + name);
			}
			if (!base) {
				base = aggregateKind == R_TYPE_STRUCT ? static_cast<Datatype *>(getTypeStruct (rawName, nativeId (name), name)) : getTypeUnion (rawName, nativeId (name), name);
			}
			Sdb *db = r_type_namespace (core->anal->sdb_types, tagKind != R_TYPE_INVALID ? R_TYPE_NAMESPACE_TAG : R_TYPE_NAMESPACE_ORDINARY, false);
			const string definitionKey = (aggregateKind == R_TYPE_STRUCT ? "struct." : "union.") + rawName;
			const char *definition = db ? sdb_const_get (db, definitionKey.c_str (), nullptr) : nullptr;
			if (base->isIncomplete () && definition && *definition) {
				resolution.pendingAggregates.push_back (base);
			}
			return base;
		}
		Datatype *type = findByName (name, resolution, behindPointer);
		if (!type || (!behindPointer && type->isIncomplete ())) {
			if (error) {
				*error = "Unable to resolve " + string (type ? "complete type '" : "type '") + name + "'";
			}
			return nullptr;
		}
		return type;
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
		const RTypeIntegerModel model = {
			static_cast<unsigned int>(getSizeOfInt () * 8),
			static_cast<unsigned int>(getSizeOfLong () * 8),
			static_cast<unsigned int>(getSizeOfLongLong () * 8)
		};
		ut64 count = 0;
		const char *boundError = nullptr;
		if (!r_type_array_bound (&model, node->array.count, &count, &boundError)) {
			if (error) {
				*error = boundError ? boundError : "Invalid array bound";
			}
			return nullptr;
		}
		Datatype *element = fromDeclaration (node->child, error, resolution, false, depth + 1);
		if (count > INT_MAX || !element || element->isIncomplete () || element->getMetatype () == TYPE_CODE || element->getMetatype () == TYPE_VOID || element->getAlignSize () < 1 || count > static_cast<ut64>(INT_MAX / element->getAlignSize ())) {
			if (error) {
				*error = "Invalid or oversized array type";
			}
			return nullptr;
		}
		return getTypeArray (static_cast<int4>(count), element);
	}
	case R_TYPE_DECL_FUNCTION: {
		PrototypePieces proto;
		proto.model = arch->protoModelFromR2CC (nullptr);
		if (!proto.model) {
			failTypeConstruction ("Missing prototype model for anonymous function type");
		}
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
	const uint4 qualifiers = type->getTypedef () ? type->getDeclarationQualifiers () : type->getQualifiers ();
	if (qualifiers & Datatype::qualifier_const) {
		node->qualifiers |= R_TYPE_DECL_CONST;
	}
	if (qualifiers & Datatype::qualifier_volatile) {
		node->qualifiers |= R_TYPE_DECL_VOLATILE;
	}
	if (type->getTypedef () || isFunctionRecord (type)) {
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
		node->array.count = strdup (array->numElements () ? std::to_string (array->numElements ()).c_str () : "");
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
		const ProtoModel *defaultModel = arch->protoModelFromR2CC (nullptr);
		if (!proto || proto->isModelUnknown () || !defaultModel || proto->getModelName () != defaultModel->getName ()) {
			return nullptr;
		}
		node->kind = R_TYPE_DECL_FUNCTION;
		node->function.parameters = r_list_newf (reinterpret_cast<RListFree> (r_type_decl_free));
		Datatype *returnType = proto->getOutputType ();
		for (int4 i = 0; i < proto->numParams (); i++) {
			ProtoParameter *param = proto->getParam (i);
			if (param->isHiddenReturn ()) {
				// Hidden return storage points to the logical result, not a source argument.
				returnType = static_cast<TypePointer *>(param->getType ())->getPtrTo ();
				continue;
			}
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
		// Native C printing uses a no-fixed-argument vararg prototype for ().
		const bool haveParameters = !r_list_empty (node->function.parameters);
		node->function.prototype = !proto->isDotdotdot () || haveParameters;
		node->function.variadic = proto->isDotdotdot () && haveParameters;
		Declaration child (toDeclaration (returnType, depth + 1), r_type_decl_free);
		if (!child) {
			return nullptr;
		}
		node->child = child->type;
		child->type = nullptr;
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
		node->base.name = strdup (declarationName (type).c_str ());
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
