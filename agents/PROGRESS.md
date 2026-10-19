# Progress

Commit Message: Deploy Geist device monitor with strict AM1P+S, recovery masks and persistent VPS logs

Features (Planned):
- A NixOS VM test for services.geist-forward (the module is only parsed).
- Forwarding to a home that no one can reach INTO (strict NAT) is not
  possible with a blind forwarder; the mailbox way (docs/forwarding.md,
  way B) is the answer there.
- Media streaming: one object tops out at ~78 MB over the wire (payload
  ceiling 4), and there is no streaming path for multi-gigabyte values.
  The media-stream server use case needs this first.
- Peer discovery: every peer is pinned by hand. A per-store transport
  strength (today one `[transport] startTier` per process).
- Automatic tier climbing: `TriggerPolicy` is validated and carried, but
  a session only changes strength when asked.
- Carrier pairing (Bifrost 95a3ef2, local branch `carrier-pairing`) for
  geist-relayd, if Bifrost takes it back into its history.

Features (Done):
- PC / Android / VPS device monitor (2026-10-19): public Geist APIs only;
  shared-key plus pinned-signature authentication (AM1P+S), recovery mask
  FC/F0, native DAC handshake packages, two separate VPS relay/store
  daemons, persistent bounded debug logs and local handshake echoes.
  docs/device-monitor.md has builds, provisioning, services and paths.
- Initial handshakes enforce Geist's exact layout and configured minimum
  tier. A peer cannot submit a weaker mask under a server's stronger policy.
- Project port allocation 47650–47659, docs/ports.md. Deployed UDP ports
  remain 47655 (store) and 47656 (relay); no whole-range firewall opening.
- Tables as JSON / TOML (src/geist/tabletext.nim writes, tableread.nim reads, sessiontable.nim exportTable / importTable, src/clients/cli/tables.nim `geist export` / `geist import`): shape rows or columns (transposed), bytes and sealed values as hex or `\u00HH` escapes, chosen columns sealed per value with a key (`--seal-key`, from `geist keys new-sym`) or a password (salt kept in the file). Import keeps ids (twice = replace), `--fresh-ids` adds; all rows are checked before any is stored. Tests in test_tabletext (testApiSurface), example geist_tables, README 1.14.
- `geist keys` (src/geist/keyfolder.nim, words.nim, src/clients/cli/keys.nim): one folder for signing pairs (seeded: 24 words rebuild the identical pair), 32-byte symmetric keys and trusted peer pins. list, show (pick by number), --secret words, import --kind pair|sym, trust --pin with 12-word fingerprint check, drop. BIP-39 English list + checksum (vectors tested). Tests in test_keyfolder (testCrypto).
- Row map (keyring.nim): each ring save writes `rowmap` (generation, then rowKey<TAB>position). `sealedRow(K, ring, rowKey)` returns one row's sealed bytes without any key; empty when the map is stale or the row is missing. Bridge op `sealed` / Kotlin `GeistVault.sealedHex`. Avalon Cards shows locked fields as their real ciphertext with it.
- Per-batch checks (crypto/batch.nim): unkeyed Gimli digest (no key needed: damage) and keyed BLAKE3 tag (own MAC key: tampering), both over the sealed bytes plus position, row lengths and a cluster binding (schema + total row count). openBatch refuses before decrypting. Keyless `verifyStoreIntegrity` / `geist verify` checks every batch, cluster index hashes and missing clusters, for a store or a keyring folder. Sealed clusters the ledger lists cannot be dropped through the index. Ledger files carry a version marker; older, untagged ledgers are refused. config.mac/macBytes removed. Damaged files no longer crash parsers (checked enum bytes, offset spans). Byte-flip fuzz test: with the key no flip ever yields altered rows.
- sealKeyFile (keys.nim): Session.save reuses the derived key-file key (KeySet.sealing, filled by readKeyFile) while the password is the same and the master still seals to the same bytes; otherwise a fresh salt. Saves no longer cost an Argon2id run (~1.15 s on a phone). Pinned by a test in test_keys_backup.
- android/geistvault: keyrings on Android. The Nim bridge (src/main/nim) exports its two JNI functions itself (no C, no CMake); requests and answers are UTF-8 JSON bytes. Kotlin `GeistVault` (rings) and `GeistProfiles` (public profile list, sealed backup export/import refusing paths outside the vault). 3 instrumented tests pass on an Infinix X6871; test_vault_bridge covers the JSON layer on the desktop.
- Keyrings (src/geist/keyring.nim): a folder of sealed stores, each with its own password; unlock one at a time; save rewrites only changed open rings (locked rings stay byte-identical, tested). Exported from `geist`; tests in test_keyrings (testCrypto).
- `geist-forwardd` (src/geist/forward.nim): the VPS end of Client -> VPS ->
  Home on Bifrost's `UdpForwarder`. Bytes untouched, so ONE handshake, made
  client <-> home (0.22 s per call direct and forwarded). Answers must come
  from home; ping/pong (ping.nim) tells it home is alive; `followHome` is
  off by default. `[runtime.forward]`, `services.geist-forward`,
  `nimble checkForward`, docs/forwarding.md, examples/geist_forward.nim.
- One `stop.nim` for the four daemons (was three copies).
- The six roles, one call each (docs/roles.md): writer, reader, network
  syncer (`SyncAgent`), background daemon as server AND client
  (`geistd --sync`), converter (`convertDoc`, `geist convert`), in-memory
  sealing (`sealObject` / `openObject`).
- Every evaluation routine declares its `testKind` (567 of 567).
- Nesting: 93 triple sites -> 12, all in `evaluation/benchmarks/prototypes`
  (frozen experiments, kept as they were measured).
- Big files split: session (6 modules), serve / peers, transpose /
  transposed, doc / docnode, geist_cli / cli/*, geist_routed / _config.
- Files read from disk fail as errors, never defects: `readAt` checks the
  range before allocating and refuses short reads; `schemaFrom` walks a
  stored schema before decoding it.
- A failed open gives its write lease back; exit no longer crashes.
- Otter "dead config fields" checked one by one: all but two were read
  through `S.config.x`, which Otter does not follow. The two real ones
  (`transferTier`, `discoversPeers`) are removed.
- Earlier: production passes 1-3, restructure to the workspace
  conventions, Bifrost 29915b7 (see dated entries below).

Features (In Progress):
- None.

## 2026-10-19 Device monitor deployment

Architecture:
- src/geist/authentication.nim: optional shared key selects AM1P+S;
  a missing factor fails explicitly in strict builds. No protocol retry.
- network_events.nim + connectGeist / initGeistServer observer: metadata
  only, including masks, mode, endpoint, session, steps, bytes and failures.
- src/clients/monitor/: public Geist calls shared by WebUI, CLI and JNI.
  Android app: android/geistmonitor; shared Gradle tasks use its :app alias.
- geist_monitord.nim: relay mailbox or durable Geist message store with
  an echo after save. nix/device-monitor-module.nix creates both services.

Problems found and fixed:
- The recovery server hello is about 69 KB, larger than a UDP datagram.
  Added native DAC handshake package support to Bifrost (8268c72), with
  1200-byte chunks, parity, source/session/step binding and allocation limits.
- Leftover parity packets must not enter the established data decoder.
- Bifrost's general minimum allows layouts outside Geist's tier schedule;
  Geist now checks its own full layout and allowed masks before answering.
- Android's broad Eir import compiled an unrelated video/SIMD symbol;
  Bifrost now imports only RLE and Reed-Solomon.
- The VPS also needed the provider firewall rules; NixOS rules alone were
  insufficient. The phone's Wi-Fi was enabled while retaining airplane mode.
- The cached Nimble parallel helper used an obsolete glibc. Rebuilt the
  generated helper; the full suite then passed without changing shared tools.
- WebUI's bridge must load before DOMContentLoaded; it is now a blocking
  desktop-only head script. Desktop WebUI, like JNI, enters Nim on foreign
  threads, so the device-monitor preset uses useMalloc.

Verification:
- Full Geist suite: 621 checks pass, including new real-socket dual-factor
  recovery checks: wrong PSK, absent PSK, wrong signature pin and lower mask
  are refused; a valid connection carries the actual encrypted echo.
- Bifrost: 7 native package checks; existing PSK (13), handshake/package
  (33), session (50) checks pass.
- Android instrumented checks on the connected phone: PSK import,
  connections, PC -> phone, phone -> PC, and persistent VPS echo.
- Both deployed daemons restart under systemd; saved VPS messages survive
  the deployment restart. Desktop/Android use the same UI and client code.
- nim-check and forced Otter checks reviewed. Reported key strings are test
  fixtures or the WebUI version; the two multiline var-init findings have
  actual initializers. Existing structural candidates are outside this work;
  serve dispatch was split to keep the new networking steps readable.

Dependency pins:
- Bifrost 8268c7263c014baf61c59e80b12688285ff24375.
- Tyr ab76527e3dc7765e7c40ee97b187f0f50db5aaa5, both directly and in Bifrost.
- Tyr and Bifrost main/nightly are synchronized and published.

Notes:
- Last problem encountered: Otter lists ~50 "dead" configurator fields
  and ~55 unused public routines. Checked by grep: almost all are false
  positives (fields read as `S.config.x`, thread procs, callbacks,
  benchmark and prototype entry points). Fixed: only the two above, plus
  the CLI, which ignored `[storage] preset` from configs/default.toml
  because it started from a hardcoded "app".

## 2026-10-10 Tables As JSON And TOML

What changed, and where it now lives:

```text
  src/geist/tabletext.nim      schema + rows -> text. Shape (rows | columns),
                               binary form (hex | escaped), sealed columns
  src/geist/tableread.nim      text -> schema + plain cells, every cell
                               checked against its column's kind
  src/geist/sessiontable.nim   exportTable / importTable on a Session
  src/clients/cli/tables.nim   geist export <file> / geist import <file>
  src/clients/geist_cli.nim    the command `case` is now two tables
                               (anyMode, directOnly) and one lookup
```

Also: `textBytes` / `bytesText` moved into types.nim (they were copied in
dynamic.nim and seal.nim); `slotKindName` reads a word table
(`slotKindWords`) that the table reader uses too; `quoteToml` escapes every
control character as `\u00HH` (a raw \x01 used to make invalid TOML);
`keyfolder.symmetricKey` hands out one symmetric key.

Last big change or problem encountered:
- Fylgia's TOML reader turned `é` into the letter `u` followed by
  `00e9`. It did not know `\u`, `\U` or `\e` at all, so the escaped
  binary form could never have been read back from TOML.
- Fixed in Fylgia-Utils (9381c5b, with tests) and the submodule moved to
  it. Worked: all 256 byte values round-trip through TOML and JSON.

Verification:
- `nimble test` (whole suite, 618 checks) green after the final refactor;
  also run on their own: test_tabletext (23), test_doc, test_show,
  test_option_precedence, the example, and checkAll / checkModular /
  checkRelay / checkRouter /
  checkForward.

## 2026-09-27 Production Passes

Three commits after the restructure, each verified with the whole suite:

```text
  pass  what                                               found by
  ----  -------------------------------------------------  ----------------
  1     886 declaration findings, deep quits, dead state,  nim-check, Otter
        the benchmark that never compiled
  2     peer bytes walked before decoding; contracts;      reading decodeRows
        depth-4 sites; roles; named result tuples          beside decodeQuery
  3     transport split; third-party notices; docs         Otter SEAM finding
```

What was wrong that nobody had seen:
- `decodeQuery` trusted every length off the wire, and `serveOnce` does not
  catch defects, so one malformed request from a pinned peer stopped
  geistd. Now: `checkQueryBytes` first, and an error REPLY.
- The benchmark referenced `packedConfig`, renamed long ago, and opened
  generation 1 by file name. `nimble bench` could not have run.
- `runStatistics` recorded this machine's path in a tracked file.

Verification (final state):
- `nimble test`: 531 checks across 34 files, zero failures.
- `nimble checkAll`, `checkModular`, `checkRelay`, `checkRouter`,
  `runExamples`, `runBenchmarks`, `buildAll`, `demoCli`: clean.

Last big change or problem encountered:
- The mechanical declaration pass first produced
  `default(tuple[ok: bool, node: JsonNode, err: string])` -- correct and
  unreadable. Fix: tuple types get a field-by-field literal
  (`(false, default(JsonNode), "")`) and long lines wrap. Worked.
- The per-file checker cannot read a multi-line type; seven of those were
  genuinely without a value. Fix: named the tuples (`BuiltRow`,
  `TransposeStatus`, `FollowStep`) instead of repeating them. Worked.

## 2026-09-27 One Settings File, Shared Tasks, Every Dependency Pinned

What changed, and where it now lives:

```text
  before                                  now
  --------------------------------------  -------------------------------------
  config.toml [storage] [backup]          configs/default.toml [runtime.storage]
              [transport]                   [runtime.backup] [runtime.transport]
  version / license in the .nimble file   configs/default.toml [project]
  --mm:orc --threads:on in every task     configs/default.toml [nim]
  -d:hasLibsodium in config.nims          configs/default.toml [define]
  29 own tasks, incl. autopush/switch     Nimble-Tasks + 22 Geist-only tasks
  buildBins / buildAll (compile check)    buildAll / checkAll
  bench, stats, examples, example*        runBenchmarks, runStatistics,
                                          runExamples (shared)
  nimsimd from ~/.nimble                  submodules/nimsimd, frozen at 1.3.2
  Bifrost 95a3ef2 (never pushed)          29915b7 (GitHub main)
```

Build presets, each holding only its difference: `server` (opt speed,
tier secret, hourly backups), `iot` (opt size, iot storage preset, no row
ids), `android` (no libsodium). The library reads `[runtime]` of
`configs/default.toml` at start-up and then the named preset's file, by
FILE NAME in its working directory -- never a path from the build machine.

`src/geist/` stays where it is rather than moving to `src/protocols/`:
Bifrost's `src/` is on Geist's path and has its own `protocols/` folder,
so two would make `import protocols/...` ambiguous.

Verification:
- `nimble test`: 522 checks across 33 files, zero failures (518 before,
  plus 4 for the preset layering).
- `nimble checkAll`, `checkModular`, `checkRelay`, `checkRouter`,
  `runExamples`, `buildAll` (all five programs), `demoCli`: clean.
- `nim c --noNimblePath src/clients/geist_cli.nim` builds: nothing comes
  from `~/.nimble` any more.

Last big change or problem encountered:
- Bifrost's `acceptAmeHandshake` no longer takes the authentication; it
  opens the finish with the one `answerAmeHandshake` stored. Geist answers
  with the FIRST pin as a stand-in (the hello names nobody) and tries every
  pin at the finish.
- Fix: each attempt's copy of the server state is given the pin under test
  in its `authentication` field. Worked: the live-socket suite, which runs
  real handshakes between daemons holding several pins, passes.
- The old test "the shipped config.toml parses" passed VACUOUSLY once the
  file moved -- a missing file is also "ok". It now points at
  configs/default.toml and checks the file was actually read.

## 2026-09-11 Bifrost's Private Handshake

Bifrost was rewritten; Geist was still calling the API it had before. The
parts that moved, and what each became here:

```text
  what Bifrost used to offer          what it offers now
  ---------------------------------   ---------------------------------
  beginAmePinnedHandshake             beginAmeHandshake(.., mode)
  answerAmePinnedHandshake            answerAmeHandshake(.., auth)
  finishAmePinnedHandshake            finishAmeHandshake(.., auth)
  twelve <scenario>DacDefaults()      dacDefaultsFor(scenario)
  a hello naming its sender           a hello naming NOBODY
  no anti-flood                       cookie challenge + hello retry
  raw records on the wire             records inside AME frames
```

The one that changed the code rather than the spelling is the third row.
AME's handshake is now PRIVATE: a client hello carries key material and
nothing else, and each side's identity travels sealed. So the server can
no longer look up a peer's pin when the hello arrives -- it does not yet
know who is calling.

What `src/geist/transport.nim` does instead:

```text
  hello arrives  -> no cookie yet? send one back, remember NOTHING
                 -> cookie good?   answer with our own identity sealed,
                                   remember the half-finished handshake
  finish arrives -> open the seal, then try each trusted pin in turn;
                    the first that matches names the peer and its rights
```

Trying every pin is cheap: Bifrost compares the name and the public keys
before it verifies any signature, so a pin that is not the caller costs a
string compare. Opening the sealed block is symmetric work, repeated per
attempt, which is why the loop stops at the first pin that works.

`serveOnce` now reads what a frame IS off the frame -- the four handshake
packet kinds are distinguishable from session data -- instead of guessing
from what the server remembers about that address. That removed the old
"an open session that will not open a frame might be a peer saying hello
again" fallback, which was a guess that could mask a real failure.

Also in this change:
- `requireCookie` in `[transport]` of config.toml, default true, read by
  `geistd`. Off is only right on a socket strangers cannot reach.
- `geistDescriptor` gives the local identity a one-year validity window.
  Bifrost now checks one, and a pinned key that never expires is a key
  nobody can retire without visiting every peer that pinned it.
- Dependency pins aligned with Bifrost's own (Eir, Tyr, Fylgia, SIMD,
  Otter). Geist's Eir predated `RsCodec` and Bifrost would not compile
  against it.

Verification:
- `nimble buildAll`, `nimble test`: the whole suite, including the
  live-socket daemon tests that run a real handshake over a real socket.

## 2026-09-11 The Tree Where The Conventions Say

- `tests/` -> `evaluation/tests/`, `bench/` -> `evaluation/benchmarks/`,
  new `evaluation/statistics/` holding a recorded Otter measurement.
- `.iron/PROGRESS.md` -> `agents/PROGRESS.md`; the rest of `.iron/`
  deleted and gitignored. The copied conventions went with it: they are
  read from the workspace `Agent-Conventions` repo, and a copy drifts.
- Five test files imported `../src/geist` while the rest imported `geist`
  off the configured path. All of them use the configured path now, so
  moving the directory did not have to move the imports with it.

Last big change or problem encountered:
- The CI workflow called `doctor`, `testProtocols`, `testSoak`,
  `testInterfaces` and `benchCore`. None of those tasks has ever existed
  in `geist_database.nimble`, so the workflow failed on its first step
  and nothing after it had ever run.
- Fix: rewrote `.github/workflows/ci.yml` against the tasks that do
  exist. The nix job had the same problem and got the same treatment; it
  also never linked `Rune-Pragmas`, so `nix-build` could not have
  compiled a single module.


## 2026-08-09 README At The Byte Level

Summary:
- **Terms first.** A new section defines every word the rest of the file
  uses -- store root, generation, manifest, cluster, aux region, log
  position vs @position, epoch, batch, ledger, pin, frame, envelope,
  package, spool -- grouped by where they live. In front of it, the three
  rules that describe every byte Geist writes: little-endian fixed-width
  integers, u32-length-prefixed text, u32-counted lists. There are no
  others, and saying so once removes the guesswork from every layout
  below.
- **The row, rebuilt from a real dump.** `Note(noteId: 7, title: "hi")`
  as thirty actual bytes with an offset table and a byte ruler, then the
  bitmap-prefix arithmetic, then the id split into its 24-bit tag and
  40-bit counter. The point the picture makes: a stored row is a prefix
  followed by its columns end to end, which is exactly why the column
  copy can take one apart and put it back without knowing what any
  column means.
- **The framing, rebuilt the same way.** Cluster = schema block, rows,
  optional offset table; file = 32-byte header, 76-byte index entries,
  cluster bodies. Both printed as real bytes off a real file, with every
  field named and the arithmetic (`at = 32 + 76*3 = 260`) shown rather
  than asserted.
- **The tails.** The offset table's two shapes, the manifest (`"102\n"`),
  the lease line, the cursor line, and the journal chain as a formula:
  `chain(n) = H(chain(n-1) || rowBytes(n))`.
- **The network request, byte for byte.** A `find` as its 58 real bytes
  and a reply as its 54, offset by offset; then the envelope byte, the
  32,000-byte package threshold against the 65,507-byte frame ceiling,
  and the handshake ordering with the one-socket rule drawn out.
- **The column copy and the relay envelope** got the same treatment: the
  `.getr` directory, its two region shapes and the reconstruction
  identity; the outbound message envelope and why its schemaId is 0xFFF1.
- **The prose is now tested.** `tests/test_documented_bytes.nim` asserts
  the offsets, enum numbers, widths and thresholds the README prints. A
  reordered `QueryOp` or a moved threshold now fails a test that names
  the README, instead of leaving the file describing a format that no
  longer exists.

Verification:
- `nimble test`: 240 checks, up from 224; 17 new in
  `tests/test_documented_bytes.nim`.
- Every byte table in the README was produced by dumping a real store and
  a real encoded Query/Reply, not written from the source by hand.

Last big change or problem encountered:
- Ran `nimble c` on a scratch file, which made nimble inject its config
  block into `config.nims` and write a `--noNimblePath` `nimble.paths`.
  That removed the package path nimsimd lives on and broke every direct
  `nim c` in the repo until it was reverted. Use `nimble <task>` or plain
  `nim c`; `nimble c` edits tracked files as a side effect.

## 2026-08-09 Showing And Transposing

Summary:
- **The library could not print itself.** The aligned table lived in the
  CLI, so a caller holding a Session had to write their own columns or
  shell out to `geist list`. `geist/show.nim` now owns it, `echo db`
  works, and the CLI draws its tables with the same code.
- **A big table is elided the way a big matrix is written** -- corners,
  with the middle marked, on BOTH axes. `echo` on a 500,000-row store was
  never going to be a printout. The elided rows are not rendered and then
  dropped: `show` asks the style which positions it needs and fetches
  only those, so printing twenty lines of a million-row store costs
  twenty rows. `everything()` turns it off for a caller who means it.
- **`geist/transpose.nim` keeps a column-first copy of the entry rows.**
  `name.getr.gN` beside `name.ge1st.gN`: the row header prefix, then one
  region per column, dense (arithmetic) when every row spends the same
  bytes on it and offset-addressed otherwise. A search reads one region
  instead of every row. Measured on 20,000 rows of four columns:

      find over tag     bytes read     time
      row scan           2,018,475     3.24 ms
      column scan          239,804     0.43 ms

- **It is a copy, never the truth.** The row-major generation keeps the
  metadata, journal, key ledger and id allocator, and those are excluded
  from transposition on purpose -- a column store of a hash-chained
  journal is a chain nobody can walk. So the copy is rebuilt rather than
  patched, is not in `artifactSet()`, and losing it costs a rebuild.
- **Reconstruction is byte-exact**, which is what lets the same rows come
  back as ordinary objects: a row is its header prefix followed by each
  column in schema order, so taking it apart and putting it back needs no
  knowledge of any column's meaning. Tested over varying, dense and
  collapsing schemas, every row, byte for byte.
- **Four modes answer "when is it rewritten":** `tmOnSave` (never stale,
  slowest writes), `tmInterval` with `transposeEverySeconds` (for a
  daemon), `tmManual` plus `syncTransposed` (write when you like, sync
  when it suits), `tmNone`. `[storage] transpose` in config.toml says
  which, and a misspelled mode is refused at the file rather than
  silently leaving the feature off.
- **Which copy is newer is derived, not tracked.** The copy's header
  records the generation it was built from and the manifest records the
  live one; comparing them gives absent / current / stale / orphaned. A
  tracker file would be a second copy of a fact already on disk, and the
  two would eventually disagree.
- **A stale copy is refused rather than searched.** Yesterday's rows
  would look like the database being wrong; a slow answer today is
  better than a fast wrong one.
- **The copy holds the LOG.** Superseded versions and tombstones are in
  it because they are in the entry cluster, so a hit is a log position
  and `visibleIndexOf` decides whether it is still an answer. Without
  that step `geist find` would have started returning rows `list` does
  not show -- there is a test that would fail if the CLI stopped asking.
- Refused outright: a transposed copy on a SEALED store. It would be
  plaintext columns beside an encrypted file, which is the same values
  with the grouping made obvious rather than a smaller leak.

Verification:
- `nimble test`: 224 checks, up from 192; 33 new across
  `tests/test_show.nim` and `tests/test_transpose.nim`.
- `nimble buildAll`, `checkModular`, `checkRelay`, `examples` (now four,
  including `geist_fast_search`), all clean.
- CLI: `transpose [status]`, `--transposed` on list/get/find, a column
  copy line in `info`, and `find` reporting what it read.

Last big change or problem encountered:
- The first cut of the CLI fast path returned log positions straight from
  the column scan, which would have resurrected superseded rows and
  deleted ones. Caught by asking what a hit MEANS rather than by a
  failing test -- the fixture had no updates in it. The test came second.
- Saw one SIGSEGV at exit in `releaseHeldLeases`, in a program that never
  called `db.close()`. Not reproducible in 24 further runs and unrelated
  to this change; noted rather than chased.

## 2026-08-09 README Top-Down

Summary:
- The previous pass got the words right and the ORDER wrong. Imports
  ("pick a door") and the internal border/nest/overlap tables came before
  anything had been done with a store, so every section arrived without a
  reason to exist.
- Restructured as a funnel. Part 1 is a store on disk; part 2 is part 1
  plus a pinned link; part 3 is part 2 with the store taken back out.
  That is also exactly what the three imports and the four binaries are,
  so they now explain themselves instead of being announced up front.
- Every section opens with the call that does the thing and only then
  says how it works: `openGeist` before store layout, `put`/`byId` before
  id-vs-position, `save` before the generation swap, `entryCount` /
  `logCount` before the log-versus-view picture, `geist schema` before
  column kinds, `geist inspect` before the cluster index, the sealed open
  before batches, `observeStore` before its cost, a preset call before
  the five config layers.
- Borders, nesting and overlaps moved to a "For contributors" section at
  the end, where they read as a consequence rather than a preface.
- Examples are real rather than plausible: CLI outputs are pasted from
  actual runs of the built binaries, and every Nim snippet was compiled
  and run before it went in.
- The first example now saves, closes and REOPENS instead of deleting the
  row it had just stored. A save whose store ends up empty demonstrates
  nothing; the reopen is the part that shows the row survived the
  process, under the id `put` returned.

Last big change or problem encountered:
- Two wording details were wrong in the inherited draft and are now taken
  from the source: the lease refusal carries "held by pid N on HOST, Ms
  ago", and `geist sync` reports requests and the resulting log position,
  not just a row count.

## 2026-08-09 README borders and plain entry points

Summary:
- Reworked README around low-level ASCII pictures and explicit user doors
  (local store, sealed watch, observe, two desktops, CLI, relay).
- Added a Borders section: disk half | wire half | union, Geist | Bifrost,
  geistd | geist-relayd, preset | machine config, id | @position.
- Stated every intentional nest (row in cluster, batch in cluster, id in
  row, AME in Bifrost link, spool in RAM) and every intentional overlap
  (Query/Reply shared, config.toml two readers, pin flags shared, apply
  rule shared) plus the easy false overlaps (sync chain vs message relay).
- Config, seal, transport, layout, and source map now name which side of
  a border they sit on.

Last big change or problem encountered:
- Prior README was accurate but dense and mixed borders; easy to miss that
  network is a thin union and that relay shares wire shape but not storage.

## 2026-08-08 The Daemon Without A Database

Summary:
- **Half the useful things to do with an authenticated link between two of
  your own machines have no rows in them.** A phone sending a voice clip to
  a desktop for transcription, an orchestrator triggering a job, a script
  fanning log lines at a collector -- all of them want the pinned
  post-quantum transport and none of them want a packed-row store. They
  were paying for one anyway, because the only way to reach the transport
  was `import geist/network`, which re-exported the whole database.
- **`geist-relayd` is `geistd` with a pipe where the store would be.** Same
  handshake, same `.pin` files, same `Query`/`Reply` wire -- a different
  `ServedHandler`, which is all `serveOnce` ever needed. No new wire ops,
  no second codec, no protocol change: a relay and a database daemon are
  indistinguishable until the handler runs.

      --to exec    the command's stdout becomes the sender's reply
      --to file    one line per message, plain or JSON
      --to stdout  the same lines, for a shell pipeline
      --to spool   held in memory for a peer to collect

- **A third door.** `import geist` was storage-only and `import
  geist/network` was both; `import geist/wire` is now the wire without the
  database. `network.nim` became the union of the two halves rather than a
  copy of one of them, and `PeerRight`/`PeerContext` moved to `types.nim` --
  every handler is told who is asking, and not every handler owns a socket.
- **The modularity claim is checked rather than asserted.** `nimble
  checkRelay` compiles a relay into a private nimcache and then reads the C
  files the compiler emitted, failing if a database module appears among
  them. An import three modules deep is exactly the kind that gets added
  without anyone noticing, and the mirror task `checkModular` guards the
  same line from the other side.
- **The safety properties are the ones worth naming.** An `--exec` command
  gets the body on stdin and never on its command line, so a pinned peer
  cannot turn a message into a shell; a hung command is killed rather than
  wedging the daemon; who sent a message is the subject on the certificate
  the handshake verified, never anything the payload said; every status
  line goes to stderr so `--to stdout` stays a clean pipe; and a database
  question is refused by name rather than answered emptily.
- **The spool is deliberately small.** A bounded in-memory ring per stream,
  dropping the OLDEST and counting the drop, with every answer carrying the
  stream's total so a reader whose cursor jumped further than the messages
  it received knows it missed some. Nothing survives a restart -- a message
  that must belongs in `geistd`, which is a different program on purpose.

Verification:
- `nimble test`: 192 checks, up from 166; 27 of them new in
  `tests/test_relay.nim`.
- `nimble checkRelay` and `nimble checkModular` both green: neither half
  compiles the other.
- `nix build .#checks.x86_64-linux.relay-pipe`: 12 subtests, exit 0. Three
  real guests -- a phone sends, a desktop transcribes and answers, a laptop
  collects the same message from the spool without consuming the phone's.
- The other two VM tests re-run after the `types.nim` move.

Last big change or problem encountered:
- Two escaping mistakes in the VM test, both mine and both the same shape:
  `{geistPackage}` inside a Python f-string is a Python placeholder, not a
  Nix one, and a NUL byte does not survive being written into a shell
  command. The second was fixed by sending the binary case from a `--file`
  instead, which tests the relay rather than the test driver's quoting.

## 2026-08-08 Appends Were O(n^2)

Summary:
- **Storing N rows cost O(N^2).** `appendPacked` called `rebuildLive` on
  every single append, and `rebuildLive` walks every id in the index and
  decodes each row's flags to decide whether it is a tombstone. So every
  insert re-examined the whole database. Measured on a message-shaped
  schema:

      10,000 rows    8.2 s      1,222 rows/s
      50,000 rows  210.0 s        238 rows/s

  Five times the rows for 25.7 times the work. 200k rows would have taken
  roughly an hour.
- **The fix is what the module already documented.** `rebuildLive`'s own
  comment says the live LIST only changes shape when a row is superseded
  or removed, and "an append of a brand new id only adds to the end" --
  the code just did not do that. `noteAppend` now owns the whole decision:
  a fresh id appends to `live` in O(1), a fresh tombstone changes nothing,
  and only a KNOWN id (an update or a delete) triggers a rebuild.

      10,000 rows   48 ms     (was 8.2 s)     170x
      50,000 rows  225 ms     (was 210 s)     933x
     200,000 rows  767 ms
     500,000 rows  1.63 s     -- linear from here, ~300k rows/s

- **Two guards, because a correctness test would never have caught this.**
  The answers were always right; only the cost was wrong, and at the 100-row
  fixtures the rest of the suite uses, quadratic is free. So: one test that
  interleaves appends, updates and deletes and checks the incremental view
  against a full reopen, and one that asserts 4x the rows costs under 8x
  the time -- a ratio rather than a wall clock, so it means the same on a
  slow machine. The quadratic version scored ~16.
- While measuring, the other scale numbers were recorded for the first
  time: a 500k-row store opens in 453 ms, holds 164 MiB resident (RAM
  tracks the file size, since a session loads every cluster), answers
  `byId` in 1 microsecond regardless of size, and takes 144 ms for a
  `find`, which is the unindexed linear scan behaving exactly as expected.

Verification:
- `nimble test`: 166 checks, up from 164.
- Both VM tests still pass.

Last big change or problem encountered:
- Found by asking whether the database was ready to back an application,
  and answering with a measurement instead of a reading of the code. The
  existing benchmark tops out at 20k rows, where the defect costs seconds
  and looks like a constant factor. It is worth raising that ceiling: this
  was invisible at every size the project routinely tested.

## 2026-08-08 The Config Sets, and a rowIdentity Bug Found by Writing Them Down

Summary:
- **`applyDefaults` was overruling presets it had promised not to.** Its
  own doc comment says "only the settings config.toml actually names are
  applied", and three of the four settings honour that with a zero
  sentinel -- a zero threshold or zero copies means "the file did not
  mention it". `rowIdentity` is a bool and has no such value, so the
  built-in `true` was written over the preset unconditionally.
  `iotConfig` and `streamConfig` set `rowIdentity = false` on purpose, so
  every telemetry database created through a preset name got `__rowId` and
  `__flags` anyway: **32-byte rows where the preset asked for 16**, on
  exactly the workload the preset exists to shrink. Verified with
  `geist --preset iot init`, which reported `rowBytes: 32` before and
  reports `16` after.
- `GeistDefaults` gains `rowIdentityNamed`, set from `hasKey`, and
  `applyDefaults` writes the bool only when the file named it. Two tests
  pin both directions: a preset that was not asked about keeps its choice,
  and a file that names the key still wins.
- **The same defect, twice more, in both option parsers.** Writing down
  "a command line option always wins over the file" meant checking it, and
  it was false in four places: `geist --preset app`, `geist --limit 20`,
  `geistd --preset app` and `geistd --listen dac://127.0.0.1:47655` all
  LOST to `userconfig.toml`, because each parser decided "was this typed?"
  by comparing the value against the default -- which fails precisely when
  someone types the default. The daemon case is the worst of them: a file
  could move a daemon that was explicitly bound to loopback onto a
  routable address. Both parsers now record the option names actually
  given. `Options` is exported for the test, matching the daemon's
  existing `DaemonConfig`/`parseArgs` precedent.
- **The README now documents the five config sets and every key in both
  TOML files.** Five different things were being called "config" -- the
  preset, the library defaults, the transport policy, the installation
  settings and the invocation -- with no single place saying which owns
  what or how they combine. There are now tables for the sets, for the
  precedence order, and for every key of `config.toml` and
  `userconfig.toml` with its type, default and equivalent flag.

Verification:
- `nimble test`: 157 checks, up from 155; the two new ones are the
  rowIdentity precedence.
- Preset figures in the README re-checked against `config.nim` rather than
  copied forward: batch sizes, ciphers and identity flags all confirmed.

Last big change or problem encountered:
- The bug was found by writing the documentation, not by a test. Trying to
  state plainly how a preset and a defaults file combine meant reading
  `applyDefaults` line by line, and the asymmetry between three guarded
  fields and one unguarded one is obvious the moment it has to be written
  down in a table. Worth remembering as an argument for documenting
  behaviour rather than intent.

## 2026-08-08 The Storage/Network Split, and `follow` becomes `need`

Summary:
- **`import geist` no longer depends on Bifrost at all.** It used to pull
  the whole AME/DAC stack -- handshake, post-quantum KEM, peer directory --
  into any program that only wanted to write rows to a file. The library
  is now two halves that share one repo and one config file:

      import geist            rows, files, encryption, backup, settings
      import geist/network    the above, plus peers (re-exports geist)

  Nothing in the storage half imports anything in the network half; delete
  `network.nim` and `import geist` still builds.
- **Proven, not asserted.** `nimble checkModular` compiles
  `tests/modular/storage_only.nim` with Bifrost REMOVED from the search
  path. It passes, and `geist/network` correctly fails the same way with
  `cannot open file: bifrost_exchange_protocols`. A comment asking people
  to keep the halves apart would not have survived a year.
- **`settings.nim` was the one straggler.** It imported `masks` purely to
  type `[transport]`'s `startTier`, so every storage-only build compiled
  an algorithm table it could not name. The `[transport]` section moved to
  `transport_settings.nim` on the network side; the TOML reader both halves
  need became `toml_read.nim`. Same file on disk, two readers.
  `initGeistNetworkDefaults` validates both sections for programs that
  have both, so a typo in `[transport]` still stops the CLI and the daemon.
- **`follow.nim` is now `need.nim`**, and `followRemote` is `needRemote`.
  `follow` already meant something else here -- `followStore` watches a
  local file move -- and one word for two ideas is one too many. The new
  name is the question the call actually asks a peer: what do I need?

Verification:
- `nimble test`: 155 checks, unchanged by the split.
- `nimble checkModular` passes; the storage-only binary runs.
- `nimble buildAll`, `nimble examples`, `nimble demoCli`, `nimble buildBins` clean.

Last big change or problem encountered:
- The headline C-module count moved less than expected (83 -> 77) because
  Nim's dead-code elimination was already eliding most of the unused
  transport, and the bulk of the generated C is the crypto Geist genuinely
  uses. The measurement that matters is not module count but the
  dependency: the storage half now BUILDS with the exchange stack absent,
  which it could not before. Three Falcon modules still arrive through
  `tyr_crypto`'s own facade, which re-exports a signature scheme a
  disk-only build has no use for; removing those means importing Tyr's
  submodules individually and is a change in that repo's granularity, not
  this one's.

## 2026-08-08 Catch-up, the NixOS Module, and Two VM Tests

Summary:
- **The pull direction existed in the library and nowhere else.** A peer
  could be *pushed* to (`--allow-write` + `geist --remote ... put`), but
  nothing could ask a peer for what it had: `qoSync` was reachable from
  the CLI only through `info`/`inspect`/`schema`, which print and discard.
  `src/geist/follow.nim` is the client-side mirror of `answer.nim` --
  `followRemote` catches a local database up with a peer -- and
  `geist sync --path X --remote Y` is the verb. Without it there was no
  chain to test.
- **Cursors persist, epochs guard them.** A follower's position lives in
  `.geist-cursors` beside the database, one line per peer, written
  durably AFTER the rows it describes. The peer's log epoch is stored
  with it: when the peer compacts, the position is discarded rather than
  trusted and the catch-up restarts from zero. Re-applying a held row is
  a no-op, so a rewind costs bandwidth and never duplicates.
- **A database with no schema adopts the sender's**, so a desktop joins a
  chain by naming one peer and nothing else.
- **The NixOS module was rewritten.** Every option it had mapped to a flag
  of the retired daemon (`--aec-key-hex-file`, `--identity-store`,
  `--peer-subject`, `serveDac`, `--no-discover`, ...). It now maps
  one-to-one onto the daemon that exists, keeps pins as plain paths
  because pins are public, and loads the two passwords through systemd
  credentials so they stay out of the store. It asserts what the daemon
  would refuse anyway: at least one pin, and an identity file that is not
  a store path.
- **`nix/default.nix` had two real bugs**, not just dead references: it
  built `geist` from `src/geist.nim` -- the library facade, which has no
  entry point -- rather than from the CLI, and it compiled without
  `--mm:orc --threads:on`, so a Nix-built binary used a different memory
  model from everything the suite covers. Both fixed; the retired
  `geist_spirit` and `ame_epoch_probe` targets and the unused
  tpm2-tools/libsecret wrappers are gone.
- **Two NixOS VM tests, replacing one that drove a retired CLI.**
  `two-desktop-exchange` configures its two nodes *differently* on
  purpose -- encrypted/writable against plain/read-only -- so both halves
  of every choice are exercised. `three-desktop-relay` chains
  origin -> middle -> tail, where the ends share a network but hold no
  pin for each other, and checks that a row arrives two hops away under
  the id its origin minted.

Verification:
- `nimble test`: 155 checks, up from 153; the two new ones are the chain,
  in `test_daemon_live.nim`.
- `nix build .#checks.x86_64-linux.two-desktop-exchange` passes: 12
  subtests over two booted guests.
- `nix build .#checks.x86_64-linux.three-desktop-relay` passes: 9 subtests
  over three, including the id comparison across both hops.
- `nimble buildAll`, `nimble examples`, `nimble demoCli` clean.

Last big change or problem encountered:
- The VM tests caught two things worth having caught. `network-online.target`
  is passive in a statically addressed guest -- nothing requests it until
  a unit does -- so waiting on it hung; the tests wait for the address
  instead. And an assertion of mine was simply wrong about the lease
  refusal's wording: the daemon says "already open for writing: held by
  pid N on <host>", which is better than what I asserted, since it names
  the holder. The product was right and the test was not, which is the
  correct way round for a first run.

## 2026-08-07 Simplification and Doc Purge

Summary:
- **One publish path.** `save` and `restoreSlot` both hand-rolled
  verify -> commit -> retire -> advance. `publishGeneration` is that
  second half, once, so the cleanup of a half-written generation lives in
  one place.
- **One settings reader.** Four near-identical accessors (`str`, `num`,
  `flag`, `strList`) collapsed into a generic `setting[T]` plus one
  overload for lists: the fallback decides the type.
- **One frame for a CLI write.** `writing(o, db): ...` replaces the
  open/act/save/close boilerplate in put, set, delete, compact and
  checkpoint.
- **Leases release themselves on exit.** `fail()` quits without unwinding,
  which used to strand the lock file and make the next writer wait out the
  staleness window for a process that was already gone.
- **Dead surface removed.** `Cluster` (a worse duplicate of
  `ClusterBuild`), `EntryId`, `followChanges`, `identityColumns`,
  `describePeers`, and the `QueryHandler`/`serveGeistOnce` pair from the
  previous pass. `withoutIdentity` was dead too and is now what
  `geist schema` prints, so its spec line round-trips into `init`.
- **Docs for the retired implementation deleted**: `docs/geist_database/`,
  `docs/geist_client/`, `docs/geist_protocols/`, `docs/client/`,
  `AUDIT_2026-06-25.md`, `audit.md`, `docs/examples/rapid_setup.md` --
  34 files describing facades, records and CLI flags that no longer
  exist. `CONTRIBUTING.md` rewritten for the repo as it is.
- **DESIGN_RATIONALE and STORAGE_PLAN brought up to date.** The sections
  on per-cluster overflow, `readOptimize`/`maxInline`, `Slot`'s shape and
  the variable-slot pointer described a format that is two rewrites old.
  Each is now either the reason the thing is gone or the reasoning that
  outlived it. `docs/nix.md` carries a stale-warning header naming the
  flags today's daemon actually takes.

Verification:
- `nimble test`: 153 checks, unchanged by the refactor.
- `nimble buildAll`, `nimble examples`, `nimble demoCli` clean.

Last big change or problem encountered:
- Nothing broke, which was the point: every change here was either a
  deletion or an extraction with the tests already in place to catch it.
  The one judgement call was leaving session.nim at 1600 lines rather
  than splitting it -- the maintenance half depends on a private publish
  step, and exporting an internal to enable a split is a worse trade than
  a long-but-cohesive module.

## 2026-08-06 Durability, Row Identity, Real Exchange

Summary:
- **Durable generation swap.** `save` no longer truncates the live file.
  It writes the NEXT generation, fsyncs it, verifies it reads back, and
  only then renames the manifest; N-1 is retained as a fallback and
  debris above the live generation is swept by the lease holder.
  `src/geist/durable.nim` owns the fsync and the rename-over dance.
- **Write lease.** `src/geist/lease.nim`: one writer per store root, a
  lock file plus an in-process registry -- the file answers "another
  program", the registry answers "another Session of mine". A writable
  open that finds it held opens read-only and names the holder.
- **Row identity.** `src/geist/rowid.nim`: two reserved leading columns,
  `__rowId` and `__flags`. `put` returns an id, `set` appends a new
  version, `delete` appends a tombstone, `compact` reclaims. Ids are
  `24-bit node tag | 40-bit counter`, so two desktops never allocate the
  same one, and the allocator's position is persisted so a compacted id
  is never handed out again.
- **A daemon worth running.** One socket, an AME session per peer kept
  across requests, peers interleaving freely. `qoSync`/`qoPoll` carry
  ROWS; `qoPut`/`qoDelete` accept them, gated by rights that come from
  the peer's pin (`--trust` reads, `--allow-write` writes).
  `src/geist/answer.nim` holds the protocol's meaning in the library, so
  the daemon is wiring.
- **Payloads larger than a datagram.** Replies stop at ~28 KB and say
  where to resume; what still cannot fit is chunked under a one-byte
  envelope through Bifrost's package machinery, digest-checked on
  arrival, every chunk sealed in an ordinary AME frame.
- **Sidecar reclamation.** `sweepSidecar` deletes payloads no stored row
  references, walking the log AND every backup slot before deleting
  anything.
- **Settings.** `config.toml` for library defaults (preset, sidecar
  threshold, rowIdentity, backup copies, tier policy), `userconfig.toml`
  for an installation (path, listen, identity, trusted pins), parsed
  through Fylgia's TOML reader; an unknown key is an error rather than a
  shrug, and a command line option always wins over a file.
- **The CLI can write remotely.** `geist --remote ... put` builds its row
  against the daemon's schema and sends no id; the daemon names the row.
  A write accepted over the wire is saved BEFORE it is acknowledged,
  whatever `writeMode` would have done locally: a peer told its row was
  stored never sends it again.

Verification:
- `nimble test` passes: 153 checks across 14 suites.
- Verified between two real OS processes, not only in-process: a `geistd`
  and a `geist --remote` exchanging a pinned handshake, a listing, and a
  write that survived `kill -9` of the daemon.
- `tests/test_daemon_live.nim` runs a real server on a bound UDP port:
  multi-request sessions, two peers at once, sync catch-up, subscriptions,
  a refused write and an accepted one verified on disk, and a 200 KB row
  fetched whole over ~170 chunks.
- `nimble examples`, `nimble demoCli` and `nimble buildAll` all clean.

Last big change or problem encountered:
- Row ids had to become node-scoped. The first live push test looked like
  it worked and had in fact overwritten the receiver's first row: both
  databases had allocated id 1, and from the receiver's side an id it
  already knows IS an update by definition. Sequential counters cannot be
  made safe between peers, so an id now carries the tag of the database
  that issued it.
- Fixing the generation swap broke backups silently. Slots were named
  after the live artifact, so once every save published a new file name,
  each save started a fresh rotation that never rotated -- one .b1 per
  generation, growing forever. Found by the sidecar sweep, which needed
  to enumerate slots and could not.


## 2026-08-02 CLI, Daemon, Meta/Journal Sealing

Summary:
- `sealMeta` / `sealJournal` config flags, defaulting to true when a cipher
  is selected. Each sealed cluster gets its OWN ledger, because batch
  coordinates are (batchIndex, groupId) and would collide across clusters.
  The ledger file now carries one ledger per cluster.
- `src/geist/dynamic.nim`: schema-driven row access so a tool with no
  compile-time object type can still read and write any database. Schema
  specs ("id:int,title:text"), field=value row building, row rendering,
  and `projectRows` for sending only the overflow slices a reply needs.
- `openSessionWithSchema` split out of `openSession[T]`, so a session can
  be opened from a schema stored in the file.
- `src/geist/identity.nim`: persisted signing identities and shareable
  pins. Secret keys sealed with Argon2id + cascade; pins public and
  integrity-checked.
- `src/clients/geist_cli.nim`: geist CLI, direct or remote. inspect,
  schema, info, init, put, get, list, find, checkpoint, backup, restore,
  rekey, keygen, presets. `inspect` and `schema` need no password.
- `src/server/geistd.nim`: geistd daemon. Serves reads over AME/DAC and
  re-reads the file when it changes underneath, at the cost of one index
  read per request.

Verification:
- `nimble test` passes: 56 checks across 7 suites.
- CLI direct mode exercised end to end on plain and encrypted databases.
- Full pinned client-daemon round trip verified: list, find, get, --json.
- Daemon reload demonstrated: a direct `geist put` during a daemon run was
  picked up (3 rows -> 4) instead of being overwritten.

Last big change or problem encountered:
- The transport surfaced three real defects. Both sides were pinning
  themselves (fresh identity per run), so the handshake correctly refused;
  fixed with persisted identity files and exchanged pins. The handshake's
  peerTrust was not forwarded to initAmeSession, failing every request
  after a successful handshake. And the reply went to the handshake's
  source address, but the client reconnects on a new port, so it had to
  reply to the AME packet's own source. A fourth: Reply carried rows whose
  pointers referenced an overflow region the client never received.

## 2026-08-01 Rearchitecture

Summary:
- Replaced the 48,650-line implementation with a packed-row model. `Row`
  is the only codec type; one generic `fieldPairs` mapper is the sole
  ingestion path, so a model struct costs zero codec lines.
- Files are header + seekable cluster index + clusters, each cluster
  owning its overflow region. Index cost is 32 B + 80 B per cluster
  regardless of file size, which is what makes passive observation cheap.
- Values at or above `sidecarThreshold` (1 KiB default) move to a
  content-addressed sidecar folder, replacing the old Koerper folder.
- Encryption is per (row range x column group). ChaCha20 XOR AES-CTR
  cascade, both legs seekable; nonce derived from
  (keyRef, group, batch, epoch) with a monotonic epoch, so reuse is
  structurally impossible; AAD binds position; Merkle root replaces a
  flat tag so a row verifies with a log2(N) path.
- Key lifecycle: Argon2id-sealed key file, public integrity-checked
  ledger, generation manifest as the single atomic swap point for the
  three-file artifact set, per-batch rekey instead of global rewrite.
- Backup rotates .b1/.b2/.b3 on write count or interval and refuses to
  rotate an incomplete artifact set.
- Transport reduced to masks: Geist defines the AME suite layout and the
  per-tier KEM/signature/cipher/MAC/hash/KDF masks; Bifrost performs the
  handshake and moves every frame. The 2,801-line dac_transport and the
  1,300 lines of stale AEC naming are gone.

Verification:
- `nimble test` passes: 41 checks across 6 suites.
- All three examples run: quickstart, encrypted, observe.
- At-rest encryption verified by canary: no plaintext marker on disk,
  correct decrypt on reopen, epoch advances on every rewrite.
- Every tier validates against Bifrost's own `validateAmeTier`.

Features implemented:
- types, secret, mapper, format, store, sidecar, config, session
- crypto: cipher, mac, batch, column
- keys, backup, masks, transport, facade

Features in progress:
- Sealing currently covers the entry cluster; meta and journal clusters
  are written in clear.
- `serveGeistOnce` handles one request per bind; no long-lived server loop
  or daemon binary yet.
- No CLI yet.

Last big change or problem encountered:
- Tests caught three real defects: negative integers overflowed on pack
  (fixed with a two's-complement cast), externalised values lost their
  type on read (fixed with a per-value flag bit in the length word), and
  `rekeyBatch` could return the keyRef it was replacing when a ledger
  loaded from disk was ahead of the allocator (fixed by advancing past
  the previous reference). All three are now covered by tests.
