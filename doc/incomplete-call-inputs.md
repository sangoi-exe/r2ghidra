# Incomplete call inputs

A recovered machine value and its input storage do not necessarily identify a source parameter position or the source argument count. When positive callee input-use evidence establishes a value/storage association that the ordinary parameter model cannot place, the native decompiler retains the value as a real CALL operand and marks its source mapping incomplete. It does not insert an invented earlier argument or print the retained value as the first source parameter.

## C and JSON code

`pdg` uses explicit analysis notation for this case:

```c
__call_incomplete(stack_argument_consumer,__input_storage("stack",0x8,4,7));
```

The first expression names the actual call target. Each `__input_storage(space, offset, size, value)` associates a real input value with its native storage coordinate and byte width. These expressions are decompiler analysis notation, not source declarations, runtime helper calls or a compilable reconstruction of the original C signature. Their order does not supply source parameter positions or a known arity.

`pdgj.code` follows the same native C-markup path. Existing annotations retain operator instruction offsets, the named call target and supported value highlighting. Raw native markup also binds the retained value to its Varnode and operation. JSON does not gain a separate structured call-input API or arbitrary raw Varnode references; use `pdgx` for the association below. The `r2ghidra.deadcode` option changes retained-code presentation, not the meaning of incomplete input mapping.

## Structured `pdgx` output

For each current live call with storage-qualified inputs, `pdgx` emits a `call_input_storage` child of `result`, after `function` and before code markup. It is a sibling of the function wrapper, not a new native AST child. This excerpt is from the normal-code x86-32 example above; identities are specific to that analysis:

```xml
<call_input_storage source_mapping="incomplete">
  <seqnum space="ram" offset="0x1018" uniq="0x1d"/>
  <input operand="1" varref="0x95">
    <addr space="stack" offset="0x8" size="4"/>
  </input>
  <unresolved>
    <addr space="stack" offset="0x4" size="4"/>
  </unresolved>
</call_input_storage>
```

- `source_mapping="incomplete"` explicitly withholds source parameter placement and arity. Existing inferred prototype/model information elsewhere in the function is not a contrary assertion of source completeness.
- `seqnum` is the actual CALL operation's full native identity: address space, instruction offset and unique sequence value. Match it to the live operation in the existing function AST, not merely to the instruction address or target name.
- `input.operand` is the decimal P-code operand index. Operand zero is the target; the optional operation output is not an input. This is not a source parameter index.
- `input.varref` is the hexadecimal creation ID of the current operand's Varnode. It matches the operation's input reference and the existing AST Varnode pool entry. In this example that entry is a four-byte constant `7`. Identities are local to the current analysis output and need not survive reanalysis or a presentation-mode change.
- An input's `addr` describes its storage geometry, using native address-space, hexadecimal offset and byte-size encoding. It is in the callee-input/call-entry coordinate, not the constant or unique-space address of the value's representative Varnode. Here `stack+0x8:4` is the callee input storage; it is not a host process address or a source parameter number.
- `unresolved` describes a separate unresolved storage range. It contains only `addr`, without an operand or value reference. The example's `stack+0x4:4` does not acquire a fabricated value. These are the native analysis's current unresolved ranges, not a guarantee that every possible unknown input has been enumerated.

Ordinary calls emit no `call_input_storage` element. Its absence alone does not establish a complete source prototype or successful recovery of every input. The existing native function AST, packed codec and persistence formats are unchanged by this wrapper export.

## Evidence and explicit contracts

Normal bridge analysis can analyze available direct callee bodies already admitted in the host, then reanalyze the caller using native positive input-use evidence. During optional callee preparation, the bridge fixes the selected Core architecture so address-specific architecture hints do not reset supplied types or call-site links; bitness hints remain active. The previous fixed-architecture setting is restored when preparation ends, including on exception, before any native callee action. This does not create host functions, harvest inferred signatures or manufacture exact-PC prototype links. Native analysis can retain the geometry of eligible unselected input candidates as uncertainty before discarding their trials; absence of positive evidence does not prove a candidate unused or establish a source argument. When callee evidence is unavailable or the function has no body, unresolved storage remains visible in the existing CALL-PC warning; a storage/value association is not invented just to populate this element. A storage-only case can therefore have a warning without a `call_input_storage` element.

If an optional callee action raises a native decode error, the bridge discards that entire architecture and reconstructs the caller once without auxiliary callee analysis. Rendered code identifies the failing callee and the decode reason, and retains any unresolved-storage warning. `pdg*` and `pdgw` report the reconstruction through the standard warning log instead, subject to the configured log level; `pdg*` keeps its command stream unchanged. All auxiliary enrichment from the failed attempt is discarded, including evidence from an earlier successful callee; the bridge does not infer an input value or source position to replace it. The reconstruction retains the caller's selected interpretation, supplied contracts, output mode and explicit writeback behavior. A caller or initialization failure, an incomplete auxiliary action, or a different error does not use this recovery path. A failure of the reconstructed caller is reported normally, without another reconstruction.

Supplied complete prototypes and supplied fixed/variadic lists retain their existing authority. A source-positioned call remains an ordinary call rather than receiving a competing incomplete mapping. Inferred native prototype parameters remain distinct from the storage-qualified view; their count is not proof of source arity.

## Supported case and limits

Two observed x86-32 callers at `0x1000` store `7` and call an available callee at `0x1040` from `0x1018`; the callee reads `stack+0x8:4` and adds three. One caller saves and reloads its frame, while the other has no competing caller-side stack read. Without a separate callee-first decompilation, normal and retained-code C/JSON/XML preserve `7` as an actual CALL input associated with `stack+0x8:4` in both cases. The saved-frame case also leaves `stack+0x4:4` unresolved; the no-competing-read case does not fabricate that cell. With its callee missing or bodyless, the latter instead reports `stack+0x8:4` as storage-only uncertainty without an invented CALL value. Ordinary, explicitly supplied and existing fixed-input slicing controls remain separate behaviors. Maintained command regressions check selected output fragments and authority controls; complete captured XML additionally establishes the operation/operand/pool linkage, which fragment matching alone cannot prove.

This is not universal ABI or source-arity recovery. Partial-overlap residuals, supplied variadic-tail holes, arbitrary alias/model behavior and automatic restart-loop execution are not qualified by this case. Native lifecycle controls cover a real restart request followed by explicit clear/reset/reanalysis, not that automatic loop. No new external packed-receiver, persistence, machine-runtime or Windows behavior is established by the structured export.
