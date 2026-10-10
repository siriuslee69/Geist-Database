## ---------------------------------------------------------------------
## geist cli <- `geist keys ...`: make, list, show and move keys
## ---------------------------------------------------------------------
##
## Part of the `geist` command line client; src/clients/geist_cli.nim is
## the entry point. What the keys ARE is src/geist/keyfolder.nim.
##
##   geist keys list
##     #  kind       name
##     1  pair       server
##     2  symmetric  backup
##     3  peer       laptop
##
##   geist keys show            <- prints the list, asks for a number
##   geist keys show server     <- 12 fingerprint words (public)
##   geist keys show 2 --secret <- 24 secret words (whoever has them,
##                                 has the key)
##
## Moving a symmetric key to another Geist:
##
##   here:   geist keys show backup --secret
##   there:  geist keys import backup --kind sym --words "<24 words>"
##
## Letting a client trust a server:
##
##   server: geist keys new-pair server ; geist keys show server
##   client: geist keys trust server --pin server.pin --words "<12 words>"
##
## The pair's files work wherever `--identity` and `--peer-pin` are asked
## for: <keys>/pairs/<name>.id and <keys>/peers/<name>.pin.

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
    echo "no keys in ", f.dir, "  (geist keys new-pair <name>)"
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
  ## f/o: what one key looks like, public part first.
  var
    e: KeyEntry = f.pickKey(o)
    pub: tuple[ok: bool, words: string, err: string] = (false, "", "")
    sec: tuple[ok: bool, words: string, err: string] = (false, "", "")
  echo "name:   ", e.name
  echo "kind:   ", kindName(e.kind)
  case e.kind
  of kkPair:
    echo "secret: ", f.keyFile(e.name, kfPairSecret), "   (--identity)"
    echo "pin:    ", f.keyFile(e.name, kfPairPin), "  <- hand this to peers"
  of kkPeer:
    echo "pin:    ", f.keyFile(e.name, kfPeerPin), "  (--peer-pin, --trust)"
  of kkSymmetric:
    discard
  pub = f.publicWords(e)
  if pub.ok:
    echo ""
    echo "fingerprint (public, 12 words) -- the receiving side checks the pin with:"
    echo "  ", pub.words
  if not o.showSecret:
    if e.kind != kkPeer:
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
  echo "elsewhere: geist keys import ", e.name, " --kind ",
    (if e.kind == kkPair: "pair" else: "sym"), " --words \"...\""

proc cmdKeys*(o: Options) {.role: orchestrator,
    tag: "cli|cryptoBoundary|orchestrator".} =
  ## o: `keys <what> [name]` with --keys, --words, --pin, --kind, --secret.
  var
    f: KeyFolder = openKeyFolder(keysDirOf(o), resolvePassword(o))
    what: string = if o.args.len > 0: o.args[0] else: "list"
    kind: KeyKind = kkSymmetric
  case what
  of "list":
    f.printList()
  of "new-pair":
    mustDo(f.newPair(nameArg(o)))
    echo "created pair '", nameArg(o), "'"
    f.showKey(o)
  of "new-sym":
    mustDo(f.newSymmetric(nameArg(o)))
    echo "created symmetric key '", nameArg(o), "'"
  of "show":
    f.showKey(o)
  of "import":
    case o.kind
    of "pair": kind = kkPair
    of "sym", "symmetric": kind = kkSymmetric
    else: fail("keys import needs --kind pair or --kind sym")
    mustDo(f.importWords(nameArg(o), kind, wordsArg(o, "24 words")))
    echo "imported ", kindName(kind), " '", nameArg(o), "'"
  of "trust":
    if o.pinFile.len == 0:
      fail("keys trust needs --pin <file>")
    mustDo(f.trustPin(nameArg(o), o.pinFile,
      wordsArg(o, "12 fingerprint words (empty = skip the check)")))
    echo "trusting '", nameArg(o), "': ", f.keyFile(nameArg(o), kfPeerPin)
  of "drop":
    mustDo(f.dropKey(f.pickKey(o)))
    echo "dropped"
  else:
    fail("unknown `keys " & what & "`; try `geist help`")
