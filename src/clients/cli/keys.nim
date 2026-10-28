## ---------------------------------------------------------------------
## geist cli <- `geist keys ...`: the symmetric keys, made and moved
## ---------------------------------------------------------------------
##
## Part of the `geist` command line client; src/clients/geist_cli.nim is
## the entry point. What the keys ARE is src/geist/keyfolder.nim.
##
##   geist keys list
##     #  kind       name
##     1  symmetric  backup
##     2  pair       server     <- geist-sync's, shown here by name only
##     3  peer       laptop     <- geist-sync's, shown here by name only
##
##   geist keys new-sym backup          32 random bytes, sealed
##   geist keys show backup --secret    the 24 words that rebuild it
##
## Moving a symmetric key to another Geist:
##
##   here:   geist keys show backup --secret
##   there:  geist keys import backup --kind sym --words "<24 words>"
##
## Signing pairs and peer pins share this folder but need Bifrost, so
## `geist-sync keys ...` makes and shows them.

import std/[os, strutils]

import runePragmas
import ../../geist/keyfolder
import ./common

proc keysDirOf*(o: Options): string {.role: parser, tag: "cli|config".} =
  ## o: --keys, or ~/.config/geist/keys when it was not given.
  result = if o.keysDir.len > 0: o.keysDir
           else: getConfigDir() / "geist" / "keys"

proc mustDo(r: tuple[ok: bool, err: string]) {.role: helper, inline,
    tag: "cli|status".} =
  ## r: a result that ends the run when it failed.
  if not r.ok:
    fail(r.err)

proc printList(f: KeyFolder) {.role: dataWriter, tag: "cli|formatting".} =
  ## f: the numbered listing every other subcommand refers back to.
  var
    L: seq[KeyEntry] = f.listKeys()
    i: int = 0
  if L.len == 0:
    echo "no keys in ", f.dir, "  (geist keys new-sym <name>)"
    return
  echo "#   kind       name"
  while i < L.len:
    echo alignLeft($(i + 1), 4), alignLeft(kindName(L[i].kind), 11), L[i].name
    i = i + 1

proc pickKey(f: KeyFolder, o: Options): KeyEntry {.role: parser,
    tag: "cli|parsing|read".} =
  ## f/o: the key named after the subcommand, or one picked by number
  ## from the printed list when none was named.
  var
    choice: string = ""
    found: tuple[ok: bool, entry: KeyEntry, err: string] =
      (false, KeyEntry(), "")
  if o.args.len > 1:
    choice = o.args[1]
  else:
    f.printList()
    if f.listKeys().len == 0:
      fail("nothing to choose from")
    stdout.write "number: "
    stdout.flushFile()
    choice = stdin.readLine().strip()
  found = f.findKey(choice)
  if not found.ok:
    fail(found.err)
  result = found.entry

proc nameArg(o: Options): string {.role: parser, tag: "cli|parsing".} =
  ## o: the name after the subcommand, required.
  if o.args.len < 2:
    fail("keys " & o.args[0] & " needs a name")
  result = o.args[1]

proc wordsArg(o: Options, what: string): string {.role: parser,
    tag: "cli|parsing|read".} =
  ## o: --words, or typed in when it was not given (so the words stay out
  ## of the shell history). what: what to ask for.
  if o.words.len > 0:
    return o.words
  stdout.write what, ": "
  stdout.flushFile()
  result = stdin.readLine().strip()

proc showKey(f: KeyFolder, o: Options) {.role: actor,
    tag: "cli|cryptoBoundary|read".} =
  ## f/o: what one key looks like. Only a symmetric key's words are shown
  ## here; a pair or a peer is shown by geist-sync, which has its fingerprint.
  var
    e: KeyEntry = f.pickKey(o)
    sec: tuple[ok: bool, words: string, err: string] = (false, "", "")
  echo "name:   ", e.name
  echo "kind:   ", kindName(e.kind)
  if e.kind != kkSymmetric:
    echo ""
    echo "fingerprint and secret: geist-sync keys show ", e.name
    return
  if not o.showSecret:
    echo ""
    echo "add --secret for the 24 words that rebuild this key elsewhere"
    return
  sec = f.secretWords(e)
  if not sec.ok:
    fail(sec.err)
  echo ""
  echo "SECRET (24 words) -- whoever reads these owns the key:"
  echo "  ", sec.words
  echo ""
  echo "elsewhere: geist keys import ", e.name, " --kind sym --words \"...\""

proc cmdKeys*(o: Options) {.role: orchestrator,
    tag: "cli|cryptoBoundary|orchestrator".} =
  ## o: `keys <what> [name]` with --keys, --words, --kind, --secret.
  var
    f: KeyFolder = openKeyFolder(keysDirOf(o), resolvePassword(o))
    what: string = if o.args.len > 0: o.args[0] else: "list"
  case what
  of "list":
    f.printList()
  of "new-sym":
    mustDo(f.newSymmetric(nameArg(o)))
    echo "created symmetric key '", nameArg(o), "'"
  of "show":
    f.showKey(o)
  of "import":
    if o.kind notin ["sym", "symmetric"]:
      fail("keys import needs --kind sym; pairs are imported by geist-sync")
    mustDo(f.importWords(nameArg(o), kkSymmetric, wordsArg(o, "24 words")))
    echo "imported symmetric '", nameArg(o), "'"
  of "drop":
    mustDo(f.dropKey(f.pickKey(o)))
    echo "dropped"
  of "new-pair", "trust":
    fail("`keys " & what & "` is geist-sync's: run `geist-sync keys " &
      what & "`")
  else:
    fail("unknown `keys " & what & "`; try `geist help`")
