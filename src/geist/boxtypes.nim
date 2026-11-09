## ---------------------------------------------------------------------
## Box types <- what a box is, who it belongs to, and who may do what in it
## ---------------------------------------------------------------------
##
## A BOX is one place that keeps items for somebody: a vault of sealed keys, a
## posting box, the records of one chat. Every box has a KIND, and the kind's
## RULE says how it behaves.
##
## Def. 1 (owner): who a box belongs to.
##   account   one box per account; its id IS the account's id.
##   space     one box per space (a chat, a group). Whoever makes it owns it.
## Def. 2 (access): who may read, or write.
##   owner     the owner only
##   members   the owner and the members the owner listed
##   whitelist the owner and the subjects the owner listed
##   anyone    every subject that is not empty
## Def. 3 (mode): what a write does.
##   append    a new item under a new key; a key is WRITE-ONCE
##   overwrite one value per key; a write names the version it replaces
##   queue     items wait until a reader acknowledges them, then they go
##   takeOnce  the owner fills it; a reader TAKES the oldest item, which is
##             gone in the same step, so no two readers get the same one
## Def. 4 (blind): true = the writer sealed the items and this machine holds no
##   key for them. false = this machine may read them, and seals them at rest
##   when it was handed a key.
## Def. 5 (signed): every item must carry a label signed by a key the box holds
##   (see ./box.nim). The check works on any machine, without trusting the one
##   the item came through.
## Def. 6 (subject): who asks, as text. Geist does not know where the caller is
##   or how it was identified. The caller says who, Geist decides.
##
## Nothing here knows about a network. `import geist` is enough for all of it.

import std/[json, strutils, tables]

import runePragmas
import ./types
import ./secret
import ./lease
import ./trust
import ./toml_read

export trust

const
  boxRefused* = "no such box, or not allowed"
    ## One answer for both, on purpose: nobody learns which boxes exist by asking.
  boxInlineMax* = 64 * 1024
    ## an item at or above this size goes into its own file beside the log
  boxZeroHead* = "0000000000000000000000000000000000000000000000000000000000000000"
    ## the chain head of a signed box with no item yet

type
  BoxOwner* = enum
    boAccount, boSpace

  BoxAccess* = enum
    baOwner, baMembers, baWhitelist, baAnyone

  BoxMode* = enum
    bmAppend, bmOverwrite, bmQueue, bmTakeOnce

  BoxAction* = enum
    bxCreate,
      ## make a box of this kind
    bxRead,
      ## list or fetch items
    bxWrite,
      ## put an item
    bxTake,
      ## takeOnce: get and delete the oldest item
    bxAck,
      ## queue: delete items that were read
    bxAdmin
      ## change the box's members or whitelist

  BoxRule* {.role: configurator, tag: "boxes|config|types".} = object
    ## One kind of box.
    name*: string
    owner*: BoxOwner
    read*: BoxAccess
    write*: BoxAccess
    mode*: BoxMode
    blind*: bool
    signed*: bool
    keepMs*: uint64
      ## how long an item is kept; 0 = until it is deleted
    maxItemBytes*: int
    maxItems*: int

  BoxHead* {.role: truthState, tag: "boxes|types",
      expectedCount: [0, -1], lifeCycle: lcSession.} = object
    ## Who one box belongs to and who may use it.
    kind*: string
    id*: string
    owner*: string
    members*: seq[string]
    whitelist*: seq[string]
    trust*: TrustTable
      ## the keys a signed box takes labels from

  BoxItem* {.role: truthState, tag: "boxes|types",
      expectedCount: [0, -1], lifeCycle: lcJob.} = object
    ## One item.
    key*: string
    number*: uint64
      ## 1, 2, 3 ... per box, in the order this box accepted items
    version*: uint64
    writer*: string
    atMs*: uint64
    label*: string
      ## signed boxes only
    data*: seq[uint8]

  BoxResult* {.role: preparedData, tag: "boxes|types".} = object
    ## The answer of every call. Nothing raises.
    ok*: bool
    err*: string
    items*: seq[BoxItem]
    number*: uint64
      ## the number the item got (put), or the newest number in the box
    version*: uint64
    chainHead*: string
      ## signed boxes: what the next label must name as `prev`

  BoxKey* {.role: truthState, tag: "boxes|cryptoBoundary|types",
      expectedCount: 1, lifeCycle: lcForever.} = ref object
    ## The key handed over for data at rest. One object, shared by every open box:
    ## a Secret cannot be copied, on purpose. nil = no key.
    secret*: Secret

  BoxSlot* {.role: memory, tag: "boxes|types",
      expectedCount: [0, -1], lifeCycle: lcSession.} = object
    ## Where one live item lies in its log.
    number*: uint64
    version*: uint64
    atMs*: uint64
    writer*: string
    offset*: int64
    frameBytes*: int64
    blobBytes*: int64

  BoxFile* {.role: memory, tag: "boxes|types",
      expectedCount: [0, 4096], lifeCycle: lcSession.} = ref object
    ## One open box: its log, and what the log adds up to.
    dir*: string
    name*: string
      ## "kind/id", sealed into every record
    logId*: uint64
      ## changes when the log is rewritten; a copy on another machine sees that
    size*: int64
      ## where the next record goes
    head*: BoxHead
    counter*: uint64
    index*: Table[string, BoxSlot]
    numbers*: seq[uint64]
      ## numbers ever seen in this log, ascending; some may be gone
    keyOf*: Table[uint64, string]
    chain*: string
    liveBytes*: int64
    reader*: File
    writer*: File
    dirty*: bool
    drop*: seq[uint64]
      ## large items replaced or deleted; their files go after the next sync
    useTick*: uint64
    atRest*: BoxKey

  BoxLimits* {.role: configurator, tag: "boxes|config|types".} = object
    ## What one owner may use. 0 = no limit.
    maxBoxesPerOwner*: int
    maxBytesPerOwner*: int64

  BoxUsage* {.role: memory, tag: "boxes|types",
      expectedCount: [0, -1], lifeCycle: lcForever.} = object
    ## What one owner uses now.
    boxes*: int
    bytes*: int64

  BoxShelf* {.role: truthState, tag: "boxes|types",
      expectedCount: 1, lifeCycle: lcForever.} = ref object
    ## Every box below one folder.
    root*: string
    rules*: seq[BoxRule]
    limits*: BoxLimits
    atRest*: BoxKey
    lease*: Lease
    open*: Table[string, BoxFile]
    maxOpen*: int
    tick*: uint64
    usage*: Table[string, BoxUsage]
    counters*: Table[string, uint64]
      ## newest number of every box touched so far; a watcher asks here and no
      ## box has to be opened to learn that nothing is new

proc newBoxKey*(A: openArray[uint8]): BoxKey {.role: configurator,
    tag: "boxes|appApi|cryptoBoundary".} =
  ## A: the key bytes, handed over by whoever holds them.
  result = BoxKey(secret: initSecret(A))

proc ruleOf*(R: openArray[BoxRule], kind: string): tuple[ok: bool, rule: BoxRule] {.
    role: parser, tag: "boxes".} =
  ## R/kind: the rule of one kind, or ok = false.
  for r in R:
    if r.name == kind:
      return (true, r)
  result = (false, BoxRule())

proc grants(A: BoxAccess, H: BoxHead, subject: string): bool {.role: parser,
    inline.} =
  ## A/H/subject: Def. 2 for one subject.
  case A
  of baOwner: result = subject == H.owner
  of baMembers: result = subject == H.owner or subject in H.members
  of baWhitelist: result = subject == H.owner or subject in H.whitelist
  of baAnyone: result = subject.len > 0

proc mayBox*(R: BoxRule, H: BoxHead, subject: string,
    action: BoxAction): bool {.role: parser, tag: "boxes|permission".} =
  ## R/H/subject/action: may this subject do this to this box? An empty subject
  ## may do nothing.
  if subject.len == 0:
    return false
  case action
  of bxCreate: result = R.owner == boSpace or subject == H.id
  of bxAdmin: result = subject == H.owner
  of bxWrite: result = grants(R.write, H, subject)
  of bxRead: result = grants(R.read, H, subject)
  of bxTake: result = R.mode == bmTakeOnce and grants(R.read, H, subject)
  of bxAck: result = R.mode == bmQueue and grants(R.read, H, subject)

proc validBoxId*(id: string): bool {.role: sanitizer, tag: "boxes".} =
  ## id: letters, digits, '-', '_', '.' (never first), at most 128 characters,
  ## so it is always one folder name and can never climb out of the shelf.
  result = id.len > 0 and id.len <= 128 and id[0] != '.' and
    id.allCharsInSet(Letters + Digits + {'-', '_', '.'})

## ---------------------------- rules from a file -----------------------------

const
  boxRuleKeys*: array[9, string] = ["owner", "read", "write", "mode", "blind",
    "signed", "keepDays", "maxItemBytes", "maxItems"]

proc defaultBoxRule*(name: string): BoxRule {.role: configurator, tag: "boxes|config".} =
  ## name: a kind. What every rule starts from.
  result = BoxRule(name: name, owner: boAccount, read: baOwner, write: baOwner,
    mode: bmAppend, blind: true, maxItemBytes: 65_536, maxItems: 100_000)

proc parseBoxOwner(s: string): tuple[ok: bool, v: BoxOwner] {.role: parser.} =
  ## s: Def. 1 as written in the file.
  case s.strip().toLowerAscii()
  of "account": result = (true, boAccount)
  of "space": result = (true, boSpace)
  else: result = (false, boAccount)

proc parseBoxAccess(s: string): tuple[ok: bool, v: BoxAccess] {.role: parser.} =
  ## s: Def. 2 as written in the file.
  case s.strip().toLowerAscii()
  of "owner": result = (true, baOwner)
  of "members": result = (true, baMembers)
  of "whitelist": result = (true, baWhitelist)
  of "anyone": result = (true, baAnyone)
  else: result = (false, baOwner)

proc parseBoxMode(s: string): tuple[ok: bool, v: BoxMode] {.role: parser.} =
  ## s: Def. 3 as written in the file.
  case s.strip().toLowerAscii()
  of "append": result = (true, bmAppend)
  of "overwrite": result = (true, bmOverwrite)
  of "queue": result = (true, bmQueue)
  of "takeonce", "take-once": result = (true, bmTakeOnce)
  else: result = (false, bmAppend)

proc boxRuleWords(n: JsonNode, R: var BoxRule): string {.role: parser.} =
  ## n/R: the four words of one kind written into R; "" or what is wrong.
  var
    o: tuple[ok: bool, v: BoxOwner] = parseBoxOwner(n.setting("owner", "account"))
    r: tuple[ok: bool, v: BoxAccess] = parseBoxAccess(n.setting("read", "owner"))
    w: tuple[ok: bool, v: BoxAccess] = parseBoxAccess(n.setting("write", "owner"))
    m: tuple[ok: bool, v: BoxMode] = parseBoxMode(n.setting("mode", "append"))
  if not o.ok: return "owner must be account or space"
  if not r.ok or not w.ok: return "read and write must be owner, members, whitelist or anyone"
  if not m.ok: return "mode must be append, overwrite, queue or takeOnce"
  R.owner = o.v
  R.read = r.v
  R.write = w.v
  R.mode = m.v
  result = ""

proc boxRuleError*(R: BoxRule): string {.role: sanitizer, tag: "boxes|config".} =
  ## R: "" when the rule can be served; otherwise what does not fit.
  if R.name.len == 0 or not R.name.allCharsInSet(Letters + Digits):
    return "a box kind name is letters and digits only"
  if R.maxItemBytes <= 0 or R.maxItems <= 0:
    return "maxItemBytes and maxItems must be at least 1"
  if R.owner == boAccount and (R.read == baMembers or R.write == baMembers):
    return "an account box has no members; use owner, whitelist or anyone"
  if R.mode == bmTakeOnce and R.write != baOwner:
    return "a takeOnce box is filled by its owner only"
  if R.signed and R.mode != bmAppend:
    return "a signed box is a chain of items, so its mode must be append"
  result = ""

proc parseBoxRule*(name: string, n: JsonNode,
    extraKeys: openArray[string] = []): tuple[ok: bool, rule: BoxRule, err: string] {.
    role: parser, tag: "boxes|config|parsing".} =
  ## name/n: one kind's table. extraKeys: keys the caller reads itself (how often
  ## to push, and such), so they are not reported as misspelled.
  var
    known: seq[string] = @boxRuleKeys & @extraKeys
    complaint: string = checkKeys(n, known, "[runtime.boxes." & name & "]")
  result.rule = defaultBoxRule(name)
  if complaint.len > 0:
    return (false, result.rule, complaint)
  complaint = boxRuleWords(n, result.rule)
  result.rule.blind = n.setting("blind", true)
  result.rule.signed = n.setting("signed", false)
  result.rule.keepMs = uint64(n.setting("keepDays", 0)) * 86_400_000'u64
  result.rule.maxItemBytes = n.setting("maxItemBytes", result.rule.maxItemBytes)
  result.rule.maxItems = n.setting("maxItems", result.rule.maxItems)
  if complaint.len == 0:
    complaint = boxRuleError(result.rule)
  if complaint.len > 0:
    return (false, result.rule, "[runtime.boxes." & name & "]: " & complaint)
  result = (true, result.rule, "")
