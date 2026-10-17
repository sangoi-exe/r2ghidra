# Native Win16 observation and qualified fmovmem input

The native x86 16-bit compiler specification provides `borland_fmovmem_16far` for the whole-family-qualified Borland move core in both Real and Protected Mode. The matching engine also contains the qualified fill, structure-copy and selected TLINK writer models; their names are explicit contracts, not evidence that a particular function has been recognized. An exact loaded native convention name is selected before radare2 convention aliases, the default convention shortcut, or generic radare2 convention conversion. Unknown native names still use the existing conversion path; a similar name is not an exact match.

The manual helper procedure below is a narrow, explicitly supplied analysis contract, not automatic toolchain detection. Native host recognition is a separate host-plugin responsibility; this bridge build does not install it. The bridge automatically selects `x86:LE:16:Protected Mode` for loaded x86/16 NE inputs (`RBinInfo.rclass == ne`), while MZ/raw/other x86/16 inputs retain Real Mode and non-16 x86 retains its default flavor. An explicit `r2ghidra.lang` still overrides automatic selection. Matching host loading, engine and compiled language specifications are required. Stock `__cdecl16far` is not a substitute for the qualified model: it makes stronger ES/DF preservation claims.

## Build the matching local components

`subprojects/ghidra-native.wrap` is the single engine URL/revision pin: Meson reads it directly, and `subprojects/ghidra-native.mk` derives its Make settings from it. It selects the `sangoi-exe/ghidra-native` fork at the exact qualified engine commit, not upstream 0.7.2. The current pin is `c899e59609033ff416e533cea24eab499ed469dc`, which exists in the local direct-child checkout but has not been published by this work. The previous `8c0a00933c9d19d493c3858799bb3f8d0388f2fa` pin was published and fetched; that does not establish remote availability of the new pin. A fresh network-only build of the current pin is not yet established. Do not replace the pin with an older engine merely to make a remote fetch succeed.

Until the commit is published, populate a fresh subproject from the matching local direct child. Run this from the r2ghidra repository root, with `./ghidra-native` pointing to that editable engine repository. In a disposable r2ghidra source copy, supply the matching local engine repository at that direct-child path first. The commands refuse an existing subproject path rather than switching or stashing someone else's checkout; use a fresh disposable r2ghidra source copy if that path is already occupied.

```sh
(
    set -eu
    test ! -e subprojects/ghidra-native
    revision=$(sed -n 's/^revision *= *//p' subprojects/ghidra-native.wrap)
    git -C ./ghidra-native rev-parse --verify "$revision^{commit}"
    git clone --no-hardlinks ./ghidra-native subprojects/ghidra-native
    git -C subprojects/ghidra-native checkout --detach "$revision"
    test "$(git -C subprojects/ghidra-native rev-parse HEAD)" = "$revision"
)
```

Use the existing Meson build with the intended private radare2 on `PATH` and its development package selected by `PKG_CONFIG_PATH`; the normal compiler, Python, Meson/Ninja and zlib development dependencies are required. Create a fresh task-scoped cache build directory and use `--wrap-mode=nodownload` to avoid silently downloading a different dependency while preparing this unpublished local candidate:

```sh
pkg-config --modversion r_core
mkdir -p "$HOME/.cache/codex/native-transfer"
build=$(mktemp -d "$HOME/.cache/codex/native-transfer/r2ghidra-build-XXXXXX")
meson setup "$build" --wrap-mode=nodownload
meson compile -C "$build" -j 2 core_r2ghidra sleigh-DATA sleigh-x86 pcode-xml-test
meson test -C "$build" pcode-xml --print-errorlogs
```

These are the tested bounded build targets: the native plugin, DATA/x86 language specifications, and the p-code XML test executable. This command does not build or validate every processor, and the separate `meson test` command actually runs the encoder test; compilation alone does not. Meson invokes the engine's existing patch runner; do not hand-edit its generated `src` tree or introduce a second engine pin. Make remains supported through the same wrap, but its subproject manager can stash and switch an existing checkout, so do not run it against an arbitrary source tree for this local procedure.

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
e r2ghidra.timeout=30000
pd:gss
p8 128 @ 0x110e8
pd:gsd 49 @ 0x110e8
pd:gsd 20 @ 0x11141
```

With the native NE loader and `bin.relocs.apply=true`, this specific SimTower file maps file offset `0x32e8` to analysis address `0x110e8`, the start of the 89-byte core; file offset `0x3341` maps to `0x11141`, the distinct 39-byte wrapper. These are segment-ordinal coordinates `(segment << 16) | offset`, not flat file addresses or Windows runtime selectors. A second qualified copy is at `0x11294`/`0x112ed`. Require the loaded binary to identify as NE and the automatically matched language to be Protected Mode without an explicit override. Require all 128 bytes below, not only a prefix or historical helper name:

```text
45558bec56571e8b4e0c8b5e0a8b56088b46063bd1770c72043bc37306fdb80100eb03fc33c0c57606c47e0a8b4e0e0bc0740603f14e03f94ff7c701007404e311a4492bf02bf8d1e9f3a5730503f003f8a4fc1f5f5e5d4dcb45558bec5657ff760eff7608ff7606ff760cff760a0ee88eff83c40a8b56088b46065f5e5d4dcb
```

The core's instruction lengths are `1,1,2,1,1,1,3,3,3,3,2,2,2,2,2,1,3,2,1,2,3,3,3,2,2,2,1,2,1,4,2,2,1,1,2,2,2,2,2,2,2,1,1,1,1,1,1,1,1`. The wrapper's are `1,1,2,1,1,3,3,3,3,3,1,3,3,3,3,1,1,1,1,1`. Check native decoding in 16-bit context, the final plain RETF at `0x11140`, and the wrapper's PUSH CS at `0x11156` followed by a near CALL at `0x11157` targeting `0x110e8`. Disassembly/p-code can include internal repeat phases; do not mistake those for additional machine instructions. These addresses are specific to this file, not universal NE virtual addresses.

## Consume automatically qualified host contracts

With the matching native host Borland analysis plugin, ordinary `aaa` qualifies both move core/wrapper pairs in the original SimTower input at `0x110e8`/`0x11141` and `0x11294`/`0x112ed`. Qualification, preservation of conflicting analysis and the address-linked typed facts belong to that host plugin, not this bridge. Do not replace those facts with the manual setup below merely to make decompilation succeed.

The bridge consumes the host's canonical structured function signature: address-linked or name-resolved prototypes supply the return type, ordered parameters and noreturn metadata. The function's current operational calling convention still selects the native model; a declaration's stored convention does not override a later explicit `afc` selection. An authoritative complete prototype locks that model through the existing native prototype importer, including an explicit zero-argument prototype. Renaming a function does not invalidate its address-linked contract. Variable-derived signatures remain inference; they do not manufacture a locked declaration.

For the automatically qualified pairs, no `tcc` definition or manual `afs` replacement is required. The core uses `borland_fmovmem_16far`, returns void and takes `source`, `destination`, `byte_count`; the wrapper uses `borland_fmemmove_16far`, returns `FarAddress16` and takes `destination`, `source`, `byte_count`. Inspect the full function/context XML before and after a rename-only operation: the selected model must remain locked, both four-byte records must occupy entry stack offsets 4 and 8, and the two-byte count must occupy offset 12. Incoming SS remains symbolic, not zero or a guessed selector.

This establishes pre-save native consumption only. Legacy project command replay can reject convention names that have no host definition; saved-project restoration and MCP file-switch behavior require separate production-path proof. Do not add fake host conventions to hide that persistence boundary.

## Manual alternative: supply the exact host contract

In a fresh disposable analysis session without an automatically qualified contract, define a bounded host function without automatic argument inference, the two-word storage record, and the explicit signature:

```text
af+ 0x110e8 qualified_borland_fmovmem
afb+ 0x110e8 0x110e8 89
s 0x110e8
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

`afs` can reset the host calling convention, so apply `afc` afterward. In this manual alternative only, `tcc` registers the name with radare2 so `afc` accepts it; its AX/stack declaration does not define this native ABI or override the explicit void return. It is not a prerequisite for automatically applied facts. The exact native model, not a generated `r2:borland_fmovmem_16far`, must own parameter storage, far-return behavior, and register effects. Do not substitute host BP/SP variable offsets for inspected native storage, or reuse automatic argument variables from an earlier analysis.

## Inspect the production result

`pd:g` (alias `pdg`) prints C; it is not a raw p-code dump. `pd:gsd N` translates raw instructions without function analysis. `pd:gd` (alias `pdgd`) exports the imported native type/prototype and supplied architecture context/tracked values; `pdgss` reports automatic language matching, not confirmation of an explicit language override. Require `prototype model="borland_fmovmem_16far" extrapop="4"`, a locked void return, and exactly three explicit parameters: four-byte `source` at entry stack offset 4, four-byte `destination` at 8, and two-byte unsigned `byte_count` at 12. There must be no invented incoming GPR argument. The far return consumes four bytes and purges no argument bytes; the caller owns the ten argument bytes.

Use `pdgx`, the production full native function/p-code XML, to inspect the post-analysis LOAD/STORE address operands and their SS/DS/ES selector plus 16-bit offset dependencies, and correlate retained operations with the original machine-instruction stream through RETF. A host function's size, nonempty C, parameter count, or `pdgj.pcode_ops` opcode list without operands does not establish this. Optimization and repeat lowering can merge or remove operations, so retained operation counts are not instruction counts.

The printed result must not imply a selector-free host-pointer mapping. Unknown incoming DS/SS selectors remain symbolic: this procedure supplies no runtime selector table, no per-address persisted CS/DS/SS database, and no values derived from zero-initialized global registers. The current CS used in NE instruction coordinates is the analysis segment ordinal, not a demonstrated runtime selector. Existing processor defaults such as DF remain intact. Unknown or absent native models retain unknown extrapop instead of asserting the numeric bias used for variable coordinates; known models retain their declared numeric effect. The native engine may still infer an effective call effect where supported: unknown input is not a permanent inference lock. A plain RETF or a host own-return purge of zero does not alone prove whole-function net cleanup across subordinate calls, including the selected SCRANTIC HEAP/original FREE15 bodies. No private return-cache reset or new cleanup-state owner is implied. The engine keeps real synthesized CALL argument reads dependent on SS, including late prototype reconstruction, while abstract stack placeholders remain offset-only; near offsets wrap at 16 bits before segmentation. The helper's raw selector/offset ordering and modulo-16-bit copy behavior are not unrestricted modern `memmove` semantics. The qualified register contract concerns low-16-bit ordinary intact-frame completion, not upper registers, faults, arbitrary aliases, selector validity, or whole-game correctness. The matching native NE host supplies applied internal/import fixups and distinct ordinal import identities. The manual alternative alone does not establish automatic helper application; neither procedure establishes whole-image analysis, MCP lifecycle/project persistence or whole-game correctness. Those require their own production-path observations.

## Correlate original-image edges

Open originals read-only with `bin.relocs.apply=true`, never `-w`, and do not execute them. For Johnny Castaway (`SCRANTIC.EXE`, SHA-256 `f0552c281a2a9b367ad5f41402a907a3c99e73ad0a221ba14d063e31cff594ac`), compare host `aoj 1` and native `pd:gsd 1` at `0x100b0`: both must target `0x20000`. At entry, the five distinct import targets are KERNEL ordinals 91/23/30/132 and USER ordinal 5, not five identical `ffff` operands. For SimTower (SHA-256 `2825a3c53f77945c63b6d72e26faa7dde5ddd56c31ca668e67a12576d7feca96`), compare `0x10006 → 0x4f02d7`, `0x4f02ee → 0x11a55`, and the actual nonfirst-segment near CALL `0x4f00a1 → 0x4f3649`. File-offset decoding or a nonempty C result cannot prove these mapped edges.

Use bounded host functions and `pd:gx` to inspect analyzed CALL target varnodes/ordered operands, and `pd:gd` to inspect the actual supplied context. `pd:gj.pcode_ops` contains space/offset/uniq/opcode/dead-state metadata, not full operands; it cannot prove selector dependencies. Raw instruction p-code and analyzed function p-code are different observation boundaries. Unobserved runtime selectors, imported API execution, and final combined host-helper/MCP behavior remain explicit proof gaps.
