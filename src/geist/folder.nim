## ---------------------------------------------------------------------
## Folder <- the hashed version, permission and parameter files of a database folder
## ---------------------------------------------------------------------
##
## A folder that holds Geist databases carries two small text files:
##
##   geist.version       which format the databases use, and when they were made
##   geist.permissions   whether the folder may be read, written, and given sidecars
##
## Each database in the folder also has a parameters file, <name>.params, with the
## settings its bytes depend on: the hash families, the cipher, the batch size.
## A reader takes those from the file, not from its own preset, so a store made
## under one preset opens under any build that has the same families.
##
##   folder/
##     geist.version           format, created, digest
##     geist.permissions       read / write / sidecars, digest
##     main.params             contentHash, treeHash, chainHash, cipher, ..., digest
##     main.ge1st.g1 ...       the data
##
## Every file ends with a `digest` line: the BLAKE3 hash of the lines above it.
##
## Def. 1 (fail closed): when a check cannot be made, refuse. A folder whose files
##   are missing, do not parse, or whose digest does not match is read by nobody
##   and written by nobody, until someone adopts it or repairs the files.
## Def. 2 (fresh folder): a folder with no database in it yet. A writable open
##   creates its files; a read-only open finds nothing and reads nothing.
## Def. 3 (force read): `inspectFolder` shows the files and the rows, as text or
##   JSON, without any check. It never writes.

import std/[os, strutils, json, tables, times]

import runePragmas
import ./types
import ./config
import ./format
import ./crypto/hashing
import ./seek
import ./dynamic

const
  folderVersionName*: string = "geist.version"
  folderPermissionsName*: string = "geist.permissions"
  paramsSuffix*: string = ".params"
  folderFileFormat*: int = 1
    ## Version of these three text files, not of the database format.

type
  FolderPolicy* {.role: truthState, tag: "appApi|db|types".} = object
    ## What the folder allows. Each flag is "allow" or "deny" in the file.
    read*: bool
    write*: bool
    sidecars*: bool

  FolderCheck* {.role: truthState, tag: "appApi|db|types".} = object
    ## ok: the folder may be used as its files say. fresh: there is no database
    ## in the folder yet, so a writable open should create the files.
    ok*: bool
    fresh*: bool
    policy*: FolderPolicy
    err*: string

  StoreParams* {.role: truthState, tag: "appApi|db|types".} = object
    ## The configuration values that a reader of the bytes must agree with.
    contentHash*: HashKind
    contentHashBytes*: uint8
    treeHash*: HashKind
    treeHashBytes*: uint8
    chainHash*: HashKind
    cipher*: CipherKind
    batchRows*: uint32
    autoCollapse*: bool
    rowIdentity*: bool

  ParamsLoad* {.role: truthState, tag: "appApi|db|types".} = object
    ok*: bool
    found*: bool
    params*: StoreParams
    err*: string

proc hexText(A: openArray[uint8]): string {.role: helper, tag: "formatting|read".} =
  ## A: bytes rendered as lowercase hex.
  const digits = "0123456789abcdef"
  var
    i: int = 0
  result = newString(A.len * 2)
  while i < A.len:
    result[i * 2] = digits[int(A[i] shr 4)]
    result[i * 2 + 1] = digits[int(A[i] and 0x0F'u8)]
    i = i + 1

proc digestOf*(body: string): string {.role: helper, tag: "cryptoBoundary|read".} =
  ## body: the text a file carries above its digest line. Its hash, in hex.
  var
    bytes: ByteSeq = cast[ByteSeq](body)
  result = hexText(geistHash(hkBlake3, bytes, 32))

proc renderFile(pairs: seq[tuple[key, value: string]]): string {.
    role: helper, tag: "formatting|write".} =
  ## pairs: the key/value lines, in order. Returns the file text, digest last.
  var
    body: string = ""
  for p in pairs:
    body.add p.key & " = " & p.value & "\n"
  result = body & "digest = " & digestOf(body) & "\n"

proc splitFile(text: string): tuple[ok: bool, pairs: Table[string, string],
    err: string] {.role: parser, tag: "formatting|read".} =
  ## text: a folder or params file. The digest must be the last line and must
  ## match the lines above it. Returns the key/value pairs, or why not.
  var
    lines: seq[string] = text.splitLines()
    body: string = ""
    stated: string = ""
    i: int = 0
    eq: int = -1
    key: string = ""
    value: string = ""
  result.pairs = initTable[string, string]()
  while lines.len > 0 and lines[^1].strip().len == 0:
    lines.setLen(lines.len - 1)
  if lines.len == 0:
    result.err = "the file is empty"
    return
  if not lines[^1].startsWith("digest = "):
    result.err = "the file does not end with a digest line"
    return
  stated = lines[^1]["digest = ".len .. ^1].strip()
  while i < lines.len - 1:
    body.add lines[i] & "\n"
    i = i + 1
  if digestOf(body) != stated:
    result.err = "the digest does not match the file: it was changed or damaged"
    return
  for line in lines[0 .. ^2]:
    eq = line.find(" = ")
    if line.strip().len == 0 or line.startsWith("#"):
      continue
    if eq <= 0:
      result.err = "a line is not 'key = value': " & line
      return
    key = line[0 ..< eq].strip()
    value = line[eq + 3 .. ^1].strip().strip(chars = {'"'})
    result.pairs[key] = value
  result.ok = true

proc hasDatabase(dir: string): bool {.role: parser, tag: "storageIo|read".} =
  ## dir: true when the folder already holds a database file or a params file.
  if not dirExists(dir):
    return false
  for f in walkFiles(dir / "*.ge1st*"):
    return true
  for f in walkFiles(dir / ("*" & paramsSuffix)):
    return true
  result = false

proc storeHasData*(dir, name: string): bool {.role: parser, tag: "storageIo|read".} =
  ## dir/name: true when the database `name` already has a data file in the folder.
  for f in walkFiles(dir / (name & ".ge1st*")):
    return true
  result = false

proc folderFilesOf(dir: string): tuple[version, permissions: string] {.
    role: helper, tag: "storageIo".} =
  result.version = dir / folderVersionName
  result.permissions = dir / folderPermissionsName

proc writeAtomic(path, text: string) {.role: dataWriter, tag: "storageIo|write".} =
  ## path/text: the file is written beside its name and renamed into place, so a
  ## crash leaves the old file or the new one, never half of each.
  var
    tmp: string = path & ".tmp"
  writeFile(tmp, text)
  moveFile(tmp, path)

proc parseFlag(value: string): tuple[ok: bool, allow: bool] {.role: parser.} =
  ## value: "allow" or "deny". Anything else is not a flag.
  case value
  of "allow":
    result = (true, true)
  of "deny":
    result = (true, false)
  else:
    result = (false, false)

proc checkFolder*(dir: string, forWrite: bool): FolderCheck {.role: parser,
    tag: "storageIo|read".} =
  ## dir/forWrite: may this folder be used for the purpose? Fail closed: anything
  ## that is not clearly valid is an error, and the error says what to do.
  var
    files: tuple[version, permissions: string] = folderFilesOf(dir)
    version: tuple[ok: bool, pairs: Table[string, string], err: string] =
      (false, initTable[string, string](), "")
    perms: tuple[ok: bool, pairs: Table[string, string], err: string] =
      (false, initTable[string, string](), "")
    flag: tuple[ok: bool, allow: bool] = (false, false)
    format: int = 0
  result.policy = FolderPolicy(read: true, write: true, sidecars: true)
  if not fileExists(files.version) and not fileExists(files.permissions):
    if not hasDatabase(dir):
      result.ok = true
      result.fresh = true
      return
    result.err = "the folder " & dir & " holds Geist data but has no " &
      folderVersionName & " or " & folderPermissionsName & ", so it is refused " &
      "for reading and for writing. Check the data, then run `geist folder " &
      "adopt " & dir & "` to create the files."
    return
  if not fileExists(files.version) or not fileExists(files.permissions):
    result.err = "the folder " & dir & " has one of " & folderVersionName & " and " &
      folderPermissionsName & " but not both, so it is refused"
    return
  version = splitFile(readFile(files.version))
  if not version.ok:
    result.err = folderVersionName & ": " & version.err
    return
  if not version.pairs.hasKey("format"):
    result.err = folderVersionName & " names no format"
    return
  try:
    format = parseInt(version.pairs["format"])
  except ValueError:
    result.err = folderVersionName & " names a format that is not a number"
    return
  if format > int(geistFormatVersion):
    result.err = "the folder uses format " & $format & ", newer than this build " &
      "reads (" & $int(geistFormatVersion) & "); refused"
    return
  perms = splitFile(readFile(files.permissions))
  if not perms.ok:
    result.err = folderPermissionsName & ": " & perms.err
    return
  for key in ["read", "write", "sidecars"]:
    if not perms.pairs.hasKey(key):
      result.err = folderPermissionsName & " does not say whether " & key &
        " is allowed"
      return
    flag = parseFlag(perms.pairs[key])
    if not flag.ok:
      result.err = folderPermissionsName & ": " & key & " must be allow or deny"
      return
    case key
    of "read": result.policy.read = flag.allow
    of "write": result.policy.write = flag.allow
    else: result.policy.sidecars = flag.allow
  if forWrite and not result.policy.write:
    result.err = "the folder " & dir & " is read-only: " & folderPermissionsName &
      " says write = deny"
    return
  if not forWrite and not result.policy.read:
    result.err = "the folder " & dir & " may not be read: " & folderPermissionsName &
      " says read = deny"
    return
  result.ok = true

proc writeFolderFiles*(dir: string, policy: FolderPolicy) {.role: dataWriter,
    tag: "storageIo|write".} =
  ## dir/policy: create the two folder files with the given permissions, unless
  ## they exist already. Nothing here overwrites a folder that was checked.
  var
    files: tuple[version, permissions: string] = folderFilesOf(dir)
    pairs: seq[tuple[key, value: string]] = @[]
  if not dirExists(dir):
    createDir(dir)
  if not fileExists(files.version):
    pairs = @[("geist-version", "1"), ("format", $int(geistFormatVersion)),
      ("library", "2.0.0"), ("created", $getTime().toUnix())]
    writeAtomic(files.version, renderFile(pairs))
  if not fileExists(files.permissions):
    pairs = @[("geist-permissions", "1"),
      ("read", (if policy.read: "allow" else: "deny")),
      ("write", (if policy.write: "allow" else: "deny")),
      ("sidecars", (if policy.sidecars: "allow" else: "deny"))]
    writeAtomic(files.permissions, renderFile(pairs))

proc paramsPath(dir, name: string): string {.role: helper, tag: "storageIo".} =
  ## dir/name: where a database's parameters file lives.
  result = dir / (name & paramsSuffix)

proc paramsOf*(c: GeistConfig): StoreParams {.role: parser, tag: "appApi|db|read".} =
  ## c: a configuration. Its reading-relevant values, as a parameters record.
  result.contentHash = c.contentHash
  result.contentHashBytes = c.contentHashBytes
  result.treeHash = c.treeHash
  result.treeHashBytes = c.treeHashBytes
  result.chainHash = c.chainHash
  result.cipher = c.cipher
  result.batchRows = c.batchRows
  result.autoCollapse = c.autoCollapse
  result.rowIdentity = c.rowIdentity

proc applyParams*(c: GeistConfig, p: StoreParams): GeistConfig {.role: configurator,
    tag: "appApi|db|read".} =
  ## c/p: the reader's configuration with the store's own values put over it. The
  ## store decides how its bytes are read. Everything else in c is untouched.
  result = c
  result.contentHash = p.contentHash
  result.contentHashBytes = p.contentHashBytes
  result.treeHash = p.treeHash
  result.treeHashBytes = p.treeHashBytes
  result.chainHash = p.chainHash
  result.cipher = p.cipher
  result.batchRows = p.batchRows
  result.autoCollapse = p.autoCollapse
  result.rowIdentity = p.rowIdentity

proc saveParams*(dir, name: string, c: GeistConfig) {.role: dataWriter,
    tag: "storageIo|write".} =
  ## dir/name/c: write the parameters file of a new database.
  var
    p: StoreParams = paramsOf(c)
    pairs: seq[tuple[key, value: string]] = @[
      ("geist-params", "1"),
      ("contentHash", $p.contentHash),
      ("contentHashBytes", $p.contentHashBytes),
      ("treeHash", $p.treeHash),
      ("treeHashBytes", $p.treeHashBytes),
      ("chainHash", $p.chainHash),
      ("cipher", $p.cipher),
      ("batchRows", $p.batchRows),
      ("autoCollapse", (if p.autoCollapse: "true" else: "false")),
      ("rowIdentity", (if p.rowIdentity: "true" else: "false"))]
  writeAtomic(paramsPath(dir, name), renderFile(pairs))

proc loadParams*(dir, name: string): ParamsLoad {.role: parser, tag: "storageIo|read".} =
  ## dir/name: the parameters file of a database. found is false when there is
  ## none, which is how a database made before parameters existed looks.
  var
    path: string = paramsPath(dir, name)
    got: tuple[ok: bool, pairs: Table[string, string], err: string] =
      (false, initTable[string, string](), "")
  if not fileExists(path):
    result.ok = true
    return
  result.found = true
  got = splitFile(readFile(path))
  if not got.ok:
    result.err = name & paramsSuffix & ": " & got.err
    return
  try:
    result.params.contentHash = parseEnum[HashKind](got.pairs["contentHash"])
    result.params.contentHashBytes = uint8(parseInt(got.pairs["contentHashBytes"]))
    result.params.treeHash = parseEnum[HashKind](got.pairs["treeHash"])
    result.params.treeHashBytes = uint8(parseInt(got.pairs["treeHashBytes"]))
    result.params.chainHash = parseEnum[HashKind](got.pairs["chainHash"])
    result.params.cipher = parseEnum[CipherKind](got.pairs["cipher"])
    result.params.batchRows = uint32(parseInt(got.pairs["batchRows"]))
    result.params.autoCollapse = got.pairs["autoCollapse"] == "true"
    result.params.rowIdentity = got.pairs["rowIdentity"] == "true"
  except CatchableError as e:
    result.err = name & paramsSuffix & " does not hold a value this build knows: " &
      e.msg
    return
  result.ok = true

proc adoptFolder*(dir: string, policy: FolderPolicy = FolderPolicy(read: true,
    write: true, sidecars: true)): tuple[ok: bool, err: string] {.role: dataWriter,
    tag: "storageIo|write".} =
  ## dir/policy: give an existing folder its two files, so it can be used again.
  ## Refused when the folder already has files, because adopting must never
  ## replace a check that was made. The data is not opened here.
  if fileExists(dir / folderVersionName) or fileExists(dir / folderPermissionsName):
    return (false, "the folder already has " & folderVersionName & " or " &
      folderPermissionsName & "; nothing was changed")
  writeFolderFiles(dir, policy)
  result = (true, "")

proc describeFolder*(dir: string, asJson: bool): string {.role: helper,
    tag: "storageIo|read".} =
  ## dir/asJson: what the folder's files say, read without any check.
  var
    files: tuple[version, permissions: string] = folderFilesOf(dir)
    report: JsonNode = newJObject()
    names: JsonNode = newJArray()
    text: string = ""
  for path in [files.version, files.permissions]:
    if fileExists(path):
      report[extractFilename(path)] = %readFile(path)
    else:
      report[extractFilename(path)] = %"(missing)"
  for f in walkFiles(dir / "*" & paramsSuffix):
    names.add %extractFilename(f)
  report["params"] = names
  if asJson:
    result = report.pretty()
  else:
    for key, value in report.pairs:
      text.add "== " & key & "\n" & value.getStr() & "\n"
    result = text

proc inspectRows(path: string): JsonNode {.role: parser, tag: "storageIo|read".} =
  ## path: a live data file. Its rows as JSON, one object per row, without the
  ## checks. A sealed file is named as sealed, because its rows need a password.
  var
    opened: tuple[ok: bool, h: SeekHandle, err: string] = openSeek(path)
  result = newJArray()
  if not opened.ok:
    result.add %("cannot open: " & opened.err)
    return
  if looksSealed(opened.h):
    result.add %"sealed: the rows need the password, which inspect does not take"
    return
  var
    rows = opened.h.seekRange(0'u32, opened.h.rowCount)
    i: int = 0
    fields: JsonNode = nil
    texts: seq[string] = @[]
  while i < rows.len:
    texts = renderRow(opened.h.schema, rows[i].data)
    fields = newJObject()
    for j in 0 ..< opened.h.schema.slots.len:
      fields[nameOf(opened.h.schema, opened.h.schema.slots[j].nameId)] = %texts[j]
    result.add %*{"row": i, "fields": fields}
    i = i + 1

proc inspectFolder*(dir: string, asJson: bool): string {.role: orchestrator,
    tag: "storageIo|read".} =
  ## dir/asJson: force read. Shows the folder's files and every database's rows, as
  ## text or as JSON. The checks are NOT made: this is for a person who needs to see
  ## what is there, and it writes nothing.
  var
    report: JsonNode = newJObject()
    dbs: JsonNode = newJObject()
    name: string = ""
    base: string = ""
  result = describeFolder(dir, asJson)
  if not asJson:
    for f in walkFiles(dir / "*.ge1st*"):
      base = extractFilename(f)
      result.add "\n== data " & base & "\n" & hexText(cast[seq[uint8]](
        readFile(f)[0 ..< min(64, readFile(f).len)])) & "\n"
    return
  for f in walkFiles(dir / "*.ge1st*"):
    name = extractFilename(f)
    dbs[name] = inspectRows(f)
  report["folder"] = %dir
  report["files"] = %(describeFolder(dir, true).parseJson())
  report["rows"] = dbs
  result = report.pretty()
