# Native Win16 observation and qualified fmovmem input

The native x86 16-bit compiler specification provides `borland_fmovmem_16far` for the whole-family-qualified Borland move core in both Real and Protected Mode. The matching engine also contains the qualified fill, structure-copy and selected TLINK writer models; their names are explicit contracts, not evidence that a particular function has been recognized. An exact loaded native convention name is selected before radare2 convention aliases, the default convention shortcut, or generic radare2 convention conversion. Unknown native names still use the existing conversion path; a similar name is not an exact match.

The manual helper procedure below is a narrow, explicitly supplied analysis contract, not automatic toolchain detection. Native host recognition is a separate host-plugin responsibility; this bridge build does not install it. The bridge automatically selects `x86:LE:16:Protected Mode` for loaded x86/16 NE inputs (`RBinInfo.rclass == ne`), while MZ/raw/other x86/16 inputs retain Real Mode and non-16 x86 retains its default flavor. An explicit `r2ghidra.lang` still overrides automatic selection. Matching host loading, engine and compiled language specifications are required. Stock `__cdecl16far` is not a substitute for the qualified model: it makes stronger ES/DF preservation claims.

## Build the matching local components

`subprojects/ghidra-native.wrap` is the single engine URL/revision pin: Meson reads it directly, and `subprojects/ghidra-native.mk` derives its Make settings from it. It selects the `sangoi-exe/ghidra-native` fork at the exact engine commit named by its `revision` field, not upstream 0.7.2. The local procedure below reads that field and can consume the exact committed revision without establishing its remote publication or acquisition. A fresh network-only build of the current pin is not yet established. Do not replace the pin with an older engine merely to make a remote fetch succeed.

For the qualified local build, populate a fresh subproject from the matching local direct child. Run this from the r2ghidra repository root, with `./ghidra-native` pointing to that editable engine repository. In a disposable r2ghidra source copy, supply the matching local engine repository at that direct-child path first. The commands refuse an existing subproject path rather than switching or stashing someone else's checkout; use a fresh disposable r2ghidra source copy if that path is already occupied.

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

Use the existing Meson build with the intended private radare2 on `PATH` and its development package selected by `PKG_CONFIG_PATH`; the normal compiler, Python, Meson/Ninja and zlib development dependencies are required. Create a fresh task-scoped cache build directory and use `--wrap-mode=nodownload` to avoid silently downloading a different dependency while preparing this matching local build:

```sh
pkg-config --modversion r_core
mkdir -p "$HOME/.cache/codex/r2ghidra/local-integration"
work=$(mktemp -d "$HOME/.cache/codex/r2ghidra/local-integration/run-XXXXXX")
build="$work/build"
mkdir -p "$work/tmp"
export TMPDIR="$work/tmp"
meson setup "$build" --wrap-mode=nodownload -Dghidra-native:tests=true
meson compile -C "$build" -j 2 core_r2ghidra sleigh-DATA sleigh-x86 pcode-xml-test decompiler_test
meson test -C "$build" ghidra-native-unittests patch-preparation pcode-xml --print-errorlogs
meson compile -C "$build" -j 2 core_r2ghidra sleigh-DATA sleigh-x86 pcode-xml-test decompiler_test
```

These bounded targets build the native plugin, DATA/x86 language specifications, native regression driver and p-code XML test executable from the same prepared engine. This command does not build or validate every processor. The separate `meson test` command runs the native regressions, preparation controls (including real Sleigh compilation) and encoder test; compilation alone does not. The repeated build validates matching reuse after generated language outputs exist.

The complete `test/db/extras/r2ghidra_types` file also exercises AARCH64 and PowerPC controls. Build the additional `sleigh-AARCH64` and `sleigh-PowerPC` targets and select a matching language bundle containing DATA, x86, AARCH64 and PowerPC for that run. The flat x86 directory used below is sufficient only for the x86-specific observations, not that full regression file.

Meson configuration and build reuse invoke the engine's shared preparation runner. `patch.done` records the ordered patch and prepared-source identities; matching prepared distributions need no Git. Stale, malformed or old empty markers, changed source inputs, and markerless dirty/partly prepared trees refuse without changing source bytes. Preserve changes and populate a new checkout or use a matching prepared distribution; never remove the marker and retry on that tree. Paired flat native objects, paired processor `.sla` outputs and the imported Make test target's narrowly classified object/dependency/executable outputs do not invalidate preparation; canonical sources, headers, grammars, specifications and includes remain checked. Generated parser `.cc`/`.hh` files are inputs too: regeneration that changes them still refuses. The [native test guide](../ghidra-native/tests/README.md) lists exact recognized outputs and the alternate `make -C src/decompiler test` procedure, which needs explicit preparation, the GNU toolchain/BFD and matching compiled languages. This is not support for every optional imported target. Do not hand-edit the prepared `src` tree or introduce a second engine pin.

Make remains supported through the same wrap. Its Git subproject manager can acquire a fresh checkout or switch a clean, unprepared checkout, but refuses a different pin in a prepared or dirty checkout before fetch or checkout. It does not stash changes or remove the preparation marker; preserve user bytes and use a fresh matching tree. Packaged distributions use their distribution Makefile to validate the prepared engine without Git acquisition. XPS Make/Meson also validate preparation on reuse through their own build dependencies. The bounded Meson procedure above does not qualify the full bridge Make, packaged-distribution or XPS host-linkage paths; those need separate consumer observations, not just native tests or source inspection.

No global installation is necessary. For an isolated Linux replay from the r2ghidra root, continue in the same shell so `$build` selects the fresh directory above. Disable automatic plugins, explicitly load that newly built plugin, and select its matching flat x86 language directory before the commands below:

```sh
r2 -q -e cfg.plugins=false -e scr.color=0 -e bin.relocs.apply=true -c "L $build/libcore_r2ghidra.so" /path/to/SIMTOWER.EXE
```

```text
e r2ghidra.sleighhome=/absolute/r2ghidra/subprojects/ghidra-native/src/Processors/x86/data/languages
```

Replace the absolute language path with the local r2ghidra source path. Use the directory containing `x86.ldefs` and the compiled `x86.sla`, not the generic `Processors` root; the `sleigh-x86` target compiles these specifications. The plugin and language files must come from the same pinned engine candidate.

## Target-correct declarations and pointer layers

Rebuild the host and plugin together and use the default `types.plugin=c2`: the bridge consumes the host's shared `RTypeDecl` API, not a private declarator parser or a scratch `typedef` passed back through `c2`. An older installed host is not a supported substitute. Both declaration import and harvest/writeback use that shared declaration structure; native compiler-specification data owns the bridge's fundamental sizes and default C pointer width. Shared syntax support for references does not provide native C++ reference import or ABI support; the bridge rejects reference declarations explicitly.

Array extents use the exported host `r_type_array_bound` evaluator with the selected native TypeFactory's `int`, `long` and `long long` widths, not the host process's C widths or an independent bridge expression parser. Decimal `8`, octal `010` and hexadecimal `0x8` agree; C precedence makes `1|2+3` equal five. With the qualified 16/32/64-bit integer model, `0xffff+2` wraps to one; with the 32/64/64-bit model it is 65537. Unsupported expressions and explicit zero or negative bounds fail visibly. The bridge separately checks native count capacity, element stride and representable total size.

An empty extent is distinct from explicit `[0]`: it imports and reverses as an unsized native zero-element array. The qualified `struct Packet {uint16_t length; uint8_t payload[];};` retains a two-byte prefix, payload offset two and the unsized tail through native datatype encoding, C output and `pdgw`. Typedef and nested arrays retain their element counts and marker offsets; near/far pointer elements retain their independent widths. This is declaration/layout propagation, not a dynamic flexible-array indexing or runtime allocation-size guarantee.

Actual `c2` forward declarations of structs and unions retain incomplete pointee identities, including through aliases. They do not publish a fabricated by-value layout: incomplete by-value aggregate definitions refuse. Declared unresolved arguments, results, locals and globals fail rather than substituting integer, void, inference unknown or format-character types; genuine native inference unknowns remain separate. An explicit zero-size local object also refuses; this does not prohibit a flexible tail in a complete aggregate prefix or a pointer to an unsized array.

For the selected x86/16 segmented languages, unqualified C pointers use the native two-byte default, explicit `near *` uses two bytes and explicit `far *` uses four bytes. Each layer is independent: `uint16_t far * near *` is a near pointer to a far pointer. Pointer-to-array and function-pointer parentheses remain significant. The specialized C printer spells each representable near/far layer from its native width; other targets retain ordinary native pointer syntax. An explicit near/far declaration on an unsupported target fails rather than becoming an unrelated type. Pointers used internally for synthetic analysis coordinates retain their coordinate width; they do not set the default C data model or establish runtime selectors.

The x86/16 model uses two-byte `int` and `short`, four-byte `long` and `float`, eight-byte `double`, and ten-byte `long double`. Its selected local analysis model keeps `long long` at eight bytes. The latter is not a claim that Borland 3.1 accepts `long long` source. Fixed-width names such as `uint32_t` remain fixed-width independently of the fundamental defaults.

Function-signature metadata remains under `func.NAME`; pointer representation is stored explicitly around the function reference, for example `typedef.CB=func.CB far *`. Bare `func.CB` denotes a function type, not a sized callback object. Previously saved callback declarations relying on the old implicit-pointer handle require re-import through `c2`; there is no migration or dual interpretation. The optional TinyCC parser still emits obsolete implicit callback handles and is outside this qualified declaration path: re-import those callback declarations with `types.plugin=c2`, rather than expecting a compatibility coercion. The removed `__r2ghidra_t_` workaround no longer creates scratch declarations or receives special reverse-conversion treatment. A retained alias is treated as an ordinary named alias, not unwrapped because of its prefix. None of these pointer qualifiers selects an operational calling convention.

Function source knowledge is the shared `RTypeFunctionPrototype` fact (`unknown`, `unspecified` or `fixed`), not an argument-count or signature-origin heuristic. Actual `()` and `(void)` declarations remain distinct; explicit ellipsis remains a separate recorded parameter marker. Named fixed callbacks require an available formal count. Named unspecified callbacks remain open; separately inferred analysis arguments do not become source formals. Unknown callback knowledge still fails instead of silently fabricating a fixed or open contract. Both shared abstract-declaration consumers supply `R_TYPE_DECL_CONTEXT_ABSTRACT` explicitly.

For actual functions, recorded-signature import installs a locked input list only for an authoritative complete fixed prototype. Recorded non-fixed inputs supply conditional native name/type recommendations, not a mandatory ordered prefix. Variable-derived analysis retains its existing symbol constraints, which may include native parameter locks; those constraints do not establish source specificity. Known return information is applied independently, including any hidden aggregate-return input required by the native model. The matching engine retains that input through symbol cleanup and parameter recovery without fixing genuine source inputs. `pdgw` preserves source knowledge and explicit ellipsis rather than converting inferred arguments or native open inputs into a fixed source declaration or literal `...`. Inference may refine register-width guesses across writes; the qualified fixtures demonstrate eventual stability, not a universal pass bound or recovery of their original C declarations.

`afs` and the native MCP prototype setter change only the addressed function. When a type is shared through explicit links, DWARF links or name lookup, these commands retain the shared source and select an ordinary function-local type binding. The structured Analysis setter intentionally updates the shared type instead. A fixed snapshot with unavailable formals cannot be written back as a complete empty list. Standalone `afn` retains its existing rename/migration behavior; command isolation does not change that separate operation.

Scope datatype marshaling uses the native datatype encoder, including full anonymous callback prototypes. Native prototype XML keeps the return in `returnsym` and only ordered inputs in `internallist`; the matching engine is required so a callback does not gain its return type as an input. Older erroneous native dumps containing that extra input are not migrated or supported as an alternate format.

In a fresh x86/16 Protected Mode session using the matching components, this bounded check exercises the corrected ordinary defaults without a compiler-specific callback convention:

```text
af+ 0 width_probe
afb+ 0 0 1
e r2ghidra.lang=x86:LE:16:Protected Mode
e types.plugin=c2
"afs void width_probe(int number, uint16_t *pointer, uint16_t marker)"
tcc ax __cdecl16far(stack)
afc __cdecl16far
pdgd~prototype model=
pdgd~addr space="stack"
pdg~width_probe(
```

Supply a one-byte RETF (`cb`) at address zero in the disposable input before defining this function. Require the exact locked `__cdecl16far` model and entry stack offsets 4, 6 and 8 for the ordered arguments, with a size-two pointer and near-qualified C spelling. Repeat with explicit near/far nested pointers and inspect both pointer nodes, not only total argument storage. `pdgw` followed by another `pdgd` checks the reverse boundary; compare type shape and storage, not only nonempty C. These checks establish the selected analysis model, not game recompilation or runtime selector validity.

Compound returns require the matching rebuilt host and native printer as well. Manual `afs uint16_t far *(near *returns_table(void))[3]` selects `returns_table` through shared signature preparation; Core still owns the rename and flags. With the explicit `__cdecl16far` model, the native complete header is `uint16_t far *(near * __cdecl16far returns_table(void)) [3]`, not an abstract return followed by a detached function name. Its return graph is a near pointer of size two to an array of three far pointers of size four; the array occupies twelve bytes. `pdgw`, `afs` and a fresh `pdgd` retain that graph.

The same contextual printer keeps `pdgj` function-name identity and backed parameter annotations: the `returns_table(uint16_t slot)` variant associates the function token with `returns_table` at its function address and the parameter token with `slot`. Native return-token associations remain separate from those function/parameter tokens. These observations qualify declaration shape, existing annotations and writeback using matching components; no original Borland compiler roundtrip or byte-identical game rebuild was performed.

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

This automatic-consumption procedure establishes the pre-save native boundary. Legacy project command replay can reject convention names that have no host definition; that is distinct from command-free v8 project restoration and native MCP file-switch observations. The final cumulative continuation/project/MCP workflow still requires its matching-component production proof; this procedure alone does not supply it. Do not add fake host conventions to hide a persistence boundary.

## Qualified TASM 3.1 flag/state contracts

The matching engine provides these explicit models in both x86 16-bit Real and Protected Mode. The exact-image host TASM 3.1 profile supplies their structured signatures; the model names neither recognize a function automatically nor establish a historical or universal TASM C ABI. Use the host's qualified facts rather than replacing manual or conflicting analysis to force a model selection.

| Native model | Host result and native output storage | Ordered register inputs |
| --- | --- | --- |
| `tasm31_sign_extension_state_16near` | `Tasm31SignExtensionState5`: five-byte CF/AX/DX state | AX, DX, DS, ES |
| `tasm31_current_state_16near` | `Tasm31CurrentState2`: two-byte ZF/AL state | AL, DS |
| `tasm31_padding_state_16near` | `Tasm31PaddingState5`: five-byte ZF/current DS/current ES state | DS, ES |
| `tasm31_conditional_store_16far` | void; no manufactured AL result | DS |

The three near models consume a two-byte return frame and purge no arguments; the supporting far leaf consumes a four-byte return frame and purges no arguments. These are finite normal-return contracts requiring valid selected memory, intact frames and noninterfering storage, not unrestricted CPU or memory-effect models. The current-state helper's optional qualified far leaf conditionally writes memory; neither helper is declared pure. The padding helper's six work descendants remain opaque: its output selectors are the then-current DS/ES, not a promise that entry selectors survived, and unproved AH/SI/BP/DI and segment/DF effects remain unknown rather than blanket-preserved or blanket-killed.

With the matching host, plugin and compiled x86 specifications, inspect `pd:gd` for the exact locked model, result size and ordered register inputs, then `pd:gx` and the original caller instructions for actual CF/ZF consumption and current-selector dependencies. Storage layout alone does not prove flag computation, caller flow or complete callee effects. Native tests and pin selection alone do not establish that combined host-to-bridge runtime observation; qualify matching local components as above before making that claim.

## Qualified TLINK51 inline-call continuation

For actual `x86:LE:16:` decompilation, the call-before-data preprocessor queries the native host's readonly `a:borland:continuations` projection once. The required response is an object with boolean `recognized` and an array `continuations` of integer `call`/`resume` pairs. A missing producer or malformed response fails visibly; an old host is not a supported fallback. Nonmatching images retain the established call-before-literal-pool truncation, including ARM.

For the exact recognized TLINK51 image, only current-qualified calls belonging to the current function receive the engine's `call_continuation` override, and only where native tracked-register storage actually supplies effective DF zero. A missing DF entry is not zero. An existing per-instruction native flow/destination override is preserved. Recognized images with refused, absent or DF-incompatible continuations never fall back to DATA-implies-noreturn. The host owns image/helper/caller/inline-byte qualification; the bridge does not duplicate that recognition or persist a qualification receipt.

The native continuation operation retains the real decoded CALL target and the adjacent machine return address pushed on the stack, then adds a separate analyzed branch to the qualified resume. On the original TLINK51 input, the qualified analysis pairs are `0x1de2c → 0x1de37`, `0x1de3f → 0x1de4c`, `0x1de4e → 0x1de59`, `0x1deb2 → 0x1dec7`, `0x1ded1 → 0x1dee0`, `0x1dee9 → 0x1def1` and `0x1defd → 0x1df1c`. Use the matching host's normal qualified analysis before inspecting `pd:gsd`, `pd:gd`, `pd:gx` and C for the bounded callers. Inspect actual CALL operands, pushed adjacent returns, resume edges and absence of decoded inline bytes; nonempty C or an operation count alone is not proof. Changing the consumed length byte at file offset `0xf02f` from 7 to 6 must refuse the original continuation set, not retain the old resume or replace the call with `CallReturn`.

Supplied/default DF zero is an analysis assumption, not proof of runtime DF, termination or return. These continuations do not establish unconditional completion, whole-function stack cleanup, or runtime selector validity; unknown cleanup and conditional-return properties remain unknown. Private task-cache processor-specification variants can expose DF one or absent tracked DF through the existing language input boundary when no host tracked-register setter exists; they are validation inputs, not new maintained specifications or runtime state.

## Manual alternative: supply the exact host contract

In a fresh disposable analysis session without an automatically qualified contract, define a bounded host function without automatic argument inference, the two-word storage record, and the explicit signature:

```text
af+ 0x110e8 qualified_borland_fmovmem
afb+ 0x110e8 0x110e8 89
s 0x110e8
"td typedef unsigned short WORD;"
"td struct FarAddress16 { WORD offset; WORD selector; };"
"afs void qualified_borland_fmovmem(FarAddress16 source, FarAddress16 destination, WORD byte_count)"
tcc ax borland_fmovmem_16far(stack)
afc borland_fmovmem_16far
afs
afij
pdgd
pdgx
pdg
```

The current native C parser places these two WORD fields at offsets 0 and 2, without `tk` member-offset corrections. Verify that host layout and the imported native type are size 4 with size-2 unsigned fields at offsets 0 and 2. `FarAddress16` is an offset/selector storage record, not a native or host pointer.

`afs` can reset the host calling convention, so apply `afc` afterward. In this manual alternative only, `tcc` registers the name with radare2 so `afc` accepts it; its AX/stack declaration does not define this native ABI or override the explicit void return. It is not a prerequisite for automatically applied facts. The exact native model, not a generated `r2:borland_fmovmem_16far`, must own parameter storage, far-return behavior, and register effects. Do not substitute host BP/SP variable offsets for inspected native storage, or reuse automatic argument variables from an earlier analysis.

## Inspect the production result

`pd:g` (alias `pdg`) prints C; it is not a raw p-code dump. `pd:gsd N` translates raw instructions without function analysis. `pd:gd` (alias `pdgd`) exports the imported native type/prototype and supplied architecture context/tracked values; `pdgss` reports automatic language matching, not confirmation of an explicit language override. Require `prototype model="borland_fmovmem_16far" extrapop="4"`, a locked void return, and exactly three explicit parameters: four-byte `source` at entry stack offset 4, four-byte `destination` at 8, and two-byte unsigned `byte_count` at 12. There must be no invented incoming GPR argument. The far return consumes four bytes and purges no argument bytes; the caller owns the ten argument bytes.

Use `pdgx`, the production full native function/p-code XML, to inspect the post-analysis LOAD/STORE address operands and their SS/DS/ES selector plus 16-bit offset dependencies, and correlate retained operations with the original machine-instruction stream through RETF. A host function's size, nonempty C, parameter count, or `pdgj.pcode_ops` opcode list without operands does not establish this. Optimization and repeat lowering can merge or remove operations, so retained operation counts are not instruction counts.

The printed result must not imply a selector-free host-pointer mapping. Unknown incoming DS/SS selectors remain symbolic: this procedure supplies no runtime selector table, no per-address persisted CS/DS/SS database, and no values derived from zero-initialized global registers. The current CS used in NE instruction coordinates is the analysis segment ordinal, not a demonstrated runtime selector. Existing processor defaults such as DF remain intact. Unknown or absent native models retain unknown extrapop instead of asserting the numeric bias used for variable coordinates; known models retain their declared numeric effect. The native engine may still infer an effective call effect where supported: unknown input is not a permanent inference lock. A plain RETF or a host own-return purge of zero does not alone prove whole-function net cleanup across subordinate calls, including the selected SCRANTIC HEAP/original FREE15 bodies. No private return-cache reset or new cleanup-state owner is implied. The engine keeps real synthesized CALL argument reads dependent on SS, including late prototype reconstruction, while abstract stack placeholders remain offset-only; near offsets wrap at 16 bits before segmentation. The helper's raw selector/offset ordering and modulo-16-bit copy behavior are not unrestricted modern `memmove` semantics. The qualified register contract concerns low-16-bit ordinary intact-frame completion, not upper registers, faults, arbitrary aliases, selector validity, or whole-game correctness. The matching native NE host supplies applied internal/import fixups and distinct ordinal import identities. The manual alternative alone does not establish automatic helper application; neither procedure establishes whole-image analysis, MCP lifecycle/project persistence or whole-game correctness. Those require their own production-path observations.

## Correlate original-image edges

Open originals read-only with `bin.relocs.apply=true`, never `-w`, and do not execute them. For Johnny Castaway (`SCRANTIC.EXE`, SHA-256 `f0552c281a2a9b367ad5f41402a907a3c99e73ad0a221ba14d063e31cff594ac`), compare host `aoj 1` and native `pd:gsd 1` at `0x100b0`: both must target `0x20000`. At entry, the five distinct import targets are KERNEL ordinals 91/23/30/132 and USER ordinal 5, not five identical `ffff` operands. For SimTower (SHA-256 `2825a3c53f77945c63b6d72e26faa7dde5ddd56c31ca668e67a12576d7feca96`), compare `0x10006 → 0x4f02d7`, `0x4f02ee → 0x11a55`, and the actual nonfirst-segment near CALL `0x4f00a1 → 0x4f3649`. File-offset decoding or a nonempty C result cannot prove these mapped edges.

Use bounded host functions and `pd:gx` to inspect analyzed CALL target varnodes/ordered operands, and `pd:gd` to inspect the actual supplied context. `pd:gj.pcode_ops` contains space/offset/uniq/opcode/dead-state metadata, not full operands; it cannot prove selector dependencies. Raw instruction p-code and analyzed function p-code are different observation boundaries. Unobserved runtime selectors, imported API execution, and final combined host-helper/MCP behavior remain explicit proof gaps.
