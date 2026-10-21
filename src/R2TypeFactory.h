// SPDX-FileCopyrightText: 2019-2021 thestr4ng3r, pancake
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef R2GHIDRA_R2TYPEFACTORY_H
#define R2GHIDRA_R2TYPEFACTORY_H

#include <type.hh>
#include <r_util.h>

#include <unordered_map>

using namespace ghidra;
class R2Architecture;

class R2TypeFactory : public TypeFactory {
private:
	R2Architecture *arch;

	struct CStringCacheEntry {
		Datatype *type; // nullptr = cached resolution failure
		std::string error;
	};
	// both caches live for the factory's lifetime (one decompile); Datatypes are owned by the factory
	std::unordered_map<std::string, CStringCacheEntry> cstringCache;
	std::unordered_map<std::string, Datatype *> lookupCache;
	std::string typeConstructionError;

	struct TypeResolution {
		std::set<std::string> &stackTypes;
		std::vector<Datatype *> pendingAggregates;
	};

	void checkTypeConstruction() const;
	[[noreturn]] void failTypeConstruction(const string &error);
	void completeResolution(TypeResolution &resolution);

	Datatype *queryR2Struct(const string &n, TypeResolution &resolution);
	Datatype *queryR2Union(const string &n, TypeResolution &resolution);
	Datatype *queryR2Base(const string &n);
	Datatype *queryR2Enum(const string &n, TypeResolution &resolution);
	Datatype *queryR2Typedef(const string &n, TypeResolution &resolution, bool behindPointer);
	Datatype *queryR2Function(const string &n, TypeResolution &resolution);
	Datatype *queryR2(const string &n, TypeResolution &resolution, bool behindPointer = false);
	Datatype *fromCStringResolved(const string &str, string *error, TypeResolution &resolution, bool behindPointer = false);
	Datatype *fromDeclaration(const RTypeDeclNode *node, string *error, TypeResolution &resolution, bool behindPointer, int depth = 0);
	RTypeDecl *toDeclaration(Datatype *type, int depth) const;
	Datatype *findByIdResolved(const string &n, uint8 id, int4 sz, TypeResolution &resolution, Datatype *r, bool resolvedBase, bool behindPointer = false);
	Datatype *findByName(const string &n, TypeResolution &resolution, bool behindPointer = false) { return findByIdResolved(n, 0, 0, resolution, nullptr, false, behindPointer); }

protected:
	Datatype *findById(const string &n, uint8 id, int4 sz, std::set<std::string> &stackTypes);
	Datatype *findById(const string &n, uint8 id, int4 sz) override;
	using TypeFactory::findByName;
	Datatype *findByName(const string &n, std::set<std::string> &stackTypes) { return findById(n, 0, 0, stackTypes); }

public:
	using StackTypes = std::set<std::string>;
	R2TypeFactory(R2Architecture *arch);
	~R2TypeFactory() override;

	Datatype *fromCString(const string &str, string *error = nullptr, std::set<std::string> *stackTypes = nullptr);
	std::string toCString(Datatype *type) const;
	bool hasSegmentedPointers() const;
	RTypePointerKind pointerKind(const TypePointer *type) const;
};

#endif //R2GHIDRA_R2TYPEFACTORY_H
