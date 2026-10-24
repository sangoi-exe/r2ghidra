all: subprojects-zlib plugins

-include ../config.mk
include ../ghidra/deps.mk

R2GHIDRA_SRCS= R2Architecture.cpp
R2GHIDRA_SRCS+=PcodeFixupPreprocessor.cpp
R2GHIDRA_SRCS+=R2LoadImage.cpp
R2GHIDRA_SRCS+=R2Scope.cpp
R2GHIDRA_SRCS+=R2TypeFactory.cpp
R2GHIDRA_SRCS+=R2TypeDeclaration.cpp
R2GHIDRA_SRCS+=R2CommentDatabase.cpp
R2GHIDRA_SRCS+=CodeXMLParse.cpp
R2GHIDRA_SRCS+=ArchMap.cpp
R2GHIDRA_SRCS+=R2PrintC.cpp
R2GHIDRA_SRCS+=RCoreMutex.cpp
R2GHIDRA_SRCS+=r2harvest.cpp

R2GHIDRA_SRCS+=SleighAnalValue.cpp
R2GHIDRA_SRCS+=SleighAsm.cpp
R2GHIDRA_SRCS+=SleighInstruction.cpp

# R2GHIDRA_SRCS= ArchMap.cpp CodeXMLParse.cpp R2Architecture.cpp R2CommentDatabase.cpp R2LoadImage.cpp
# R2GHIDRA_SRCS+= R2PrintC.cpp R2Scope.cpp R2TypeFactory.cpp RCoreMutex.cpp SleighAnalValue.cpp SleighAsm.cpp
# R2GHIDRA_SRCS+= SleighInstruction.cpp

R2G_PLUG_SRCS= anal_ghidra.cpp core_ghidra.cpp
R2G_PLUG_SRCS+= anal_ghidra_plugin.o core_ghidra_plugin.o

# CXXFLAGS+=-DR2GHIDRA_SLEIGHHOME_DEFAULT=\"$(GHIDRA_HOME)\"

R2GHIDRA_OBJS=$(subst .cpp,.o,$(R2GHIDRA_SRCS))
R2G_PLUGIN_OBJS=$(subst .cpp,.o,$(R2G_PLUG_SRCS))

CFLAGS+=-DR2GHIDRA_SLEIGHHOME_DEFAULT=\"$(R2_USER_PLUGINS)/r2ghidra_sleigh\"
CFLAGS+=-w
CFLAGS+=-fPIC
CFLAGS+=-Wshadow
CFLAGS+=-I$(GHIDRA_DECOMPILER)
CFLAGS+=-I.
CFLAGS+=$(ZLIB_CFLAGS)

#CFLAGS+=-g -ggdb
#LDFLAGS+=-g -ggdb
#CXXFLAGS+=-g -ggdb

CXXFLAGS+=-std=c++20
CFLAGS+=$(R2_CFLAGS)

CXXFLAGS+=$(CFLAGS)

R2_LIBEXT=$(shell r2 -H R2_LIBEXT)
# TODO: rename to r2ghidra.$(R2_LIBEXT)
R2G_CORE_PLUGIN=core_ghidra.$(R2_LIBEXT)
R2G_ASM_PLUGIN=asm_ghidra.$(R2_LIBEXT)
R2G_ANAL_PLUGIN=anal_ghidra.$(R2_LIBEXT)

ifeq ($(R2_LIBEXT),)
Cannot run r2
endif


.PHONY: check-radare2-sdk
check-radare2-sdk:
	@printf '%s\n' \
		'#include "r2ghidra.h"' \
		'int main(int argc, char **argv) {' \
		'  RTypeNamespace space = R_TYPE_NAMESPACE_TAG;' \
		'  RAnalBaseType base = {};' \
		'  base.space = space;' \
		'  RAnalFunctionSignature signature = {};' \
		'  signature.type_name = argv[0];' \
		'  signature.prototype = R_TYPE_FUNC_PROTOTYPE_FIXED;' \
		'  RTypeDeclNode node = {};' \
		'  node.array.count = argv[0];' \
		'  node.function.prototype = true;' \
		'  node.function.callconv = argv[0];' \
		'  RTypeIntegerModel model = {16, 32, 64};' \
		'  ut64 count = 0;' \
		'  int parameters = argc;' \
		'  RTypeDecl *decl = r_type_decl_parse(argv[0], R_TYPE_DECL_CONTEXT_ABSTRACT, nullptr, nullptr);' \
		'  r_type_decl_free(decl);' \
		'  r_type_array_bound(&model, argv[0], &count, nullptr);' \
		'  r_type_func_args_count(nullptr, argv[0], &parameters);' \
		'  r_type_func_get_prototype(nullptr, argv[0], &signature.prototype);' \
		'  r_type_func_set_prototype(nullptr, argv[0], signature.prototype);' \
		'  Sdb *types = r_type_namespace(nullptr, base.space, false);' \
		'  free(r_type_identifier_key(argv[0], space));' \
		'  r_anal_base_type_free(r_anal_get_base_type(nullptr, argv[0], space));' \
		'  r_anal_function_signature_free(r_anal_function_get_signature(nullptr));' \
		'  RAnalFunctionSignaturePrepared *prepared = r_anal_function_signature_prepare_structured(nullptr, nullptr, &signature, true, nullptr);' \
		'  bool applied = r_anal_function_signature_apply(nullptr, nullptr, prepared);' \
		'  r_anal_function_signature_prepared_free(prepared);' \
		'  const char *call_type = r_anal_call_type_at(nullptr, argc);' \
		'  return applied && types && call_type;' \
		'}' \
		| $(CXX) $(CXXFLAGS) $(R2_CFLAGS) -x c++ - -o /dev/null $(R2_LDFLAGS) $(LDFLAGS) || { echo "r2ghidra requires radare2 ABI 159 or newer with intrinsic function conventions, current semantic type APIs, operational-CC-preserving structured preparation and the public call-site type query; rebuild the matching host SDK" >&2; exit 1; }

# zlib static build
../subprojects/zlib/libz.a: | check-radare2-sdk
	cd ../subprojects/zlib && CFLAGS="-fPIC" ./configure --static
	$(MAKE) -C ../subprojects/zlib libz.a

subprojects-zlib: ../subprojects/zlib/libz.a

clean:
	$(MAKE) -C fidb clean
	rm -f *.o
	rm -f *.o $(GHIDRA_DECOMPILER)/*.o
	rm -f $(R2G_CORE_PLUGIN) $(R2G_ASM_PLUGIN) $(R2G_ANAL_PLUGIN) sleighc fidb/r2fidb

plugins: $(R2G_CORE_PLUGIN) sleighc
	$(MAKE) sign
	$(MAKE) -C fidb

deps=$(R2GHIDRA_OBJS) $(GHIDRA_OBJS) $(R2G_PLUGIN_OBJS)

# zlib's configure rewrites zconf.h, racing any object that includes zlib.h under -j
$(R2GHIDRA_OBJS) $(GHIDRA_OBJS) $(SLEIGHTC_OBJS) $(R2G_PLUGIN_OBJS): | check-radare2-sdk ../subprojects/zlib/libz.a
sleighc $(R2G_CORE_PLUGIN) $(R2G_ANAL_PLUGIN): | check-radare2-sdk

asan:
	LDFLAGS="-fsanitize=address" CFLAGS="-fsanitize=address -g" $(MAKE) -j
	$(MAKE) user-install

$(R2G_CORE_PLUGIN): $(deps)
	$(CXX) -shared -o $@ $(R2GHIDRA_OBJS) $(GHIDRA_OBJS) core_ghidra.o \
		anal_ghidra.o core_ghidra_plugin.o anal_ghidra_plugin.o $(R2_LDFLAGS) $(ZLIB_LDFLAGS) $(LDFLAGS) $(CXXFLAGS)

$(R2G_ANAL_PLUGIN): $(deps)
	$(CXX) -shared $(GHIDRA_OBJS) anal_ghidra.o anal_ghidra_plugin.o \
		 $(R2GHIDRA_OBJS) $(R2_LDFLAGS) $(ZLIB_LDFLAGS) $(LDFLAGS) $(CXXFLAGS) -o $@

ifneq (,$(wildcard /usr/bin/codesign))
sign macsign:
	-codesign -f -s - *.dylib
else
sign macsign:
endif

core_ghidra.o: PcodeXmlEncode.h

%.o: %.cpp
	$(CXX) -fPIC $(CXXFLAGS) $(R2_CFLAGS) -c $<

PLUGDIR?=$(R2_LIBR_PLUGINS)

install:
	mkdir -p $(DESTDIR)$(BINDIR)
	cp -f sleighc $(DESTDIR)$(BINDIR)
	cp -f fidb/r2fidb $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(PLUGDIR)
	for a in *.$(R2_LIBEXT) ; do rm -f "$(DESTDIR)/$(PLUGDIR)/$$a" ; done
	cp -f *.$(R2_LIBEXT) $(DESTDIR)$(PLUGDIR)
	rm -f $(DESTDIR)$(PLUGDIR)/asm*ghidra*.$(R2_LIBEXT)
	rm -f $(DESTDIR)$(PLUGDIR)/anal*ghidra*.$(R2_LIBEXT)
ifneq (,$(wildcard /usr/bin/codesign))
	-codesign -f -s - $(DESTDIR)$(PLUGDIR)/*.$(R2_LIBEXT)
endif

uninstall:
	rm -f $(PLUGDIR)/*ghidra*.$(R2_LIBEXT)
	rm -f $(DESTDIR)/$(BINDIR)/sleighc
	rm -f $(DESTDIR)/$(BINDIR)/r2fidb

user-install:
	rm -f $(PLUGDIR)/asm*ghidra*.$(R2_LIBEXT)
	rm -f $(PLUGDIR)/anal*ghidra*.$(R2_LIBEXT)
	$(MAKE) install PLUGDIR=$(R2_USER_PLUGINS) BINDIR=$(shell r2pm -H R2PM_BINDIR)

user-uninstall:
	$(MAKE) uninstall PLUGDIR=$(R2_USER_PLUGINS) BINDIR=$(shell r2pm -H R2PM_BINDIR)
