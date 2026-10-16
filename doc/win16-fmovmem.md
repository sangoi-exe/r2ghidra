# Qualified Win16 fmovmem input

The native x86 16-bit Protected Mode compiler specification provides `borland_fmovmem_16far` for the whole-family-qualified Borland move core. An exact loaded native convention name is selected before radare2 convention aliases, the default convention shortcut, or generic radare2 convention conversion. Unknown native names still use the existing conversion path; a similar name is not an exact match.

This is a narrow, explicitly supplied analysis contract, not automatic toolchain detection or a general NE/Win16 importer. It requires the matching ghidra-native engine and specifications. Stock `__cdecl16far` is not a substitute: it makes stronger ES/DF preservation claims.

## Build the matching local components

`subprojects/ghidra-native.wrap` is the single engine URL/revision pin: Meson reads it directly, and `subprojects/ghidra-native.mk` derives its Make settings from it. It selects the `sangoi-exe/ghidra-native` fork at the exact qualified engine commit, not upstream 0.7.2. That commit exists in the local sibling checkout but has not been published by this work. Remote availability of the pinned commit remains unverified; a fresh network-only build is not yet established. Do not replace the pin with an older engine merely to make a remote fetch succeed.

Until the commit is published, populate a fresh subproject from the matching local sibling. Run this from the r2ghidra repository root, with `../ghidra-native` pointing to that engine repository. The commands refuse an existing subproject path rather than switching or stashing someone else's checkout; use a fresh disposable r2ghidra source copy if that path is already occupied.

```sh
(
    set -eu
    test ! -e subprojects/ghidra-native
    revision=$(sed -n 's/^revision *= *//p' subprojects/ghidra-native.wrap)
    git -C ../ghidra-native rev-parse --verify "$revision^{commit}"
    git clone --no-hardlinks ../ghidra-native subprojects/ghidra-native
    git -C subprojects/ghidra-native checkout --detach "$revision"
    test "$(git -C subprojects/ghidra-native rev-parse HEAD)" = "$revision"
)
```

Use the existing Meson build with the intended private radare2 on `PATH` and its development package selected by `PKG_CONFIG_PATH`; the normal compiler, Python, Meson/Ninja and zlib development dependencies are required. Create a fresh task-scoped cache build directory and use `--wrap-mode=nodownload` to avoid silently downloading a different dependency while preparing this unpublished local candidate:

```sh
pkg-config --modversion r_core
mkdir -p "$HOME/.cache/codex/native-win16-first-slice"
build=$(mktemp -d "$HOME/.cache/codex/native-win16-first-slice/r2ghidra-build-XXXXXX")
meson setup "$build" --wrap-mode=nodownload
meson compile -C "$build" -j 2 core_r2ghidra sleigh-DATA sleigh-x86 pcode-xml-test
```

These are the tested bounded build targets: the native plugin, DATA/x86 language specifications, and the p-code XML test executable. This command does not build or validate every processor, and building the test executable does not run it. Meson invokes the engine's existing patch runner; do not hand-edit its generated `src` tree or introduce a second engine pin. Make remains supported through the same wrap, but its subproject manager can stash and switch an existing checkout, so do not run it against an arbitrary source tree for this local procedure.

No global installation is necessary. For an isolated Linux replay from the r2ghidra root, continue in the same shell so `$build` selects the fresh directory above. Disable automatic plugins, explicitly load that newly built plugin, and select its matching flat x86 language directory before the commands below:

```sh
r2 -q -e cfg.plugins=false -e scr.color=0 -e bin.relocs.apply=true -c "L $build/libcore_r2ghidra.so" /path/to/SIMTOWER.EXE
```

```text
e r2ghidra.sleighhome=/absolute/r2ghidra/subprojects/ghidra-native/src/Processors/x86/data/languages
```

Replace the absolute language path with the local r2ghidra source path. Use the directory containing `x86.ldefs` and the compiled `x86.sla`, not the generic `Processors` root; the `sleigh-x86` target compiles these specifications. The plugin and language files must come from the same pinned engine candidate.

## Qualify the input first

Continue in that isolated read-only session, or use a private installation of the same matching plugin and specifications. Do not use `-w` or run the executable. Set these plugin options after the matching plugin loads:

```text
e asm.bits=16
e r2ghidra.lang=x86:LE:16:Protected Mode
e r2ghidra.timeout=30000
p8 128 @ 0x32e8
pdgsd 49 @ 0x32e8
pdgsd 20 @ 0x3341
```

For this specific SimTower file, file/host address `0x32e8` begins the 89-byte core, followed immediately at `0x3341` by the distinct 39-byte wrapper. Require all 128 bytes below, not only a prefix or historical helper name:

```text
45558bec56571e8b4e0c8b5e0a8b56088b46063bd1770c72043bc37306fdb80100eb03fc33c0c57606c47e0a8b4e0e0bc0740603f14e03f94ff7c701007404e311a4492bf02bf8d1e9f3a5730503f003f8a4fc1f5f5e5d4dcb45558bec5657ff760eff7608ff7606ff760cff760a0ee88eff83c40a8b56088b46065f5e5d4dcb
```

The core's instruction lengths are `1,1,2,1,1,1,3,3,3,3,2,2,2,2,2,1,3,2,1,2,3,3,3,2,2,2,1,2,1,4,2,2,1,1,2,2,2,2,2,2,2,1,1,1,1,1,1,1,1`. The wrapper's are `1,1,2,1,1,3,3,3,3,3,1,3,3,3,3,1,1,1,1,1`. Check native decoding in 16-bit context, the final plain RETF at `0x3340`, and the wrapper's PUSH CS at `0x3356` followed by a near CALL at `0x3357` targeting `0x32e8`. Disassembly/p-code can include internal repeat phases; do not mistake those for additional machine instructions. These addresses are specific to this file, not universal NE virtual addresses.

## Supply the exact host contract

In a fresh disposable analysis session, define a bounded host function without automatic argument inference, the two-word storage record, and the explicit signature:

```text
af+ 0x32e8 qualified_borland_fmovmem
afb+ 0x32e8 0x32e8 89
s 0x32e8
"td typedef unsigned short WORD;"
"td struct FarAddress16 { WORD offset; WORD selector; };"
tk struct.FarAddress16.offset=WORD,0,0
tk struct.FarAddress16.selector=WORD,2,0
"afs void qualified_borland_fmovmem(FarAddress16 source, FarAddress16 destination, WORD byte_count)"
tcc ax borland_fmovmem_16far(stack)
afc borland_fmovmem_16far
afs
afij
pdgd
pdgx
pdg
```

`td` alone is not layout qualification: the inspected host parser placed the second WORD at offset 4. The explicit `tk` member offsets supply the required packed four-byte record through the existing type database. Verify the imported native type is size 4 with size-2 unsigned fields at offsets 0 and 2. `FarAddress16` is an offset/selector storage record, not a native or host pointer.

`afs` can reset the host calling convention, so apply `afc` afterward. `tcc` only registers the name with radare2 so `afc` accepts it; its AX/stack declaration does not define this native ABI or override the explicit void return. The exact native model, not a generated `r2:borland_fmovmem_16far`, must own parameter storage, far-return behavior, and register effects. Do not substitute host BP/SP variable offsets for inspected native storage, or reuse automatic argument variables from an earlier analysis.

## Inspect the production result

`pdgd` exports the imported native type/prototype and selected language context; `pdgss` reports automatic language matching, not confirmation of an explicit language override. Require `prototype model="borland_fmovmem_16far" extrapop="4"`, a locked void return, and exactly three explicit parameters: four-byte `source` at entry stack offset 4, four-byte `destination` at 8, and two-byte unsigned `byte_count` at 12. There must be no invented incoming GPR argument. The far return consumes four bytes and purges no argument bytes; the caller owns the ten argument bytes.

Use `pdgx`, the production full native function/p-code XML, to inspect the post-analysis LOAD/STORE address operands and their SS/DS/ES selector plus 16-bit offset dependencies, and correlate retained operations with the original machine-instruction stream through RETF. A host function's size, nonempty C, parameter count, or `pdgj.pcode_ops` opcode list without operands does not establish this. Optimization and repeat lowering can merge or remove operations, so retained operation counts are not instruction counts.

The printed result must not imply a selector-free host-pointer mapping. Unknown selectors remain unknown: this procedure supplies no runtime selector table. The helper's raw selector/offset ordering and modulo-16-bit copy behavior are not unrestricted modern `memmove` semantics. The qualified register contract concerns low-16-bit ordinary intact-frame completion, not upper registers, faults, arbitrary aliases, selector validity, or whole-game correctness. NE imports/fixups, the complete extension/MCP migration, and automatic family recognition remain outside this procedure.
