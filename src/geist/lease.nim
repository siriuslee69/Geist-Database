## ---------------------------------------------------------------------
## Lease <- one writer per store root, enforced rather than assumed
## ---------------------------------------------------------------------
##
##   acquireLease(dir)  -> held      | taken by pid 4711 since 12:03
##   releaseLease(S)                 <- on close, and on crash by staleness
##
## A Geist session holds the whole database in memory and republishes it as
## a new generation. Two of those writing the same store root do not
## interleave rows -- the second one's save simply describes a world in
## which the first one's writes never happened. No amount of atomic
## renaming fixes that, because both files are internally consistent.
##
##   without a lease            with a lease
##   ---------------            ------------
##   A opens (10 rows)          A opens, takes the lease
##   B opens (10 rows)          B opens -> lease held -> read-only or error
##   A puts 5, saves  -> 15     A puts 5, saves -> 15
##   B puts 1, saves  -> 11     B is not in a position to lose them
##            ^ A's five rows are gone and nothing reported it
##
## The lease is a FILE, not an advisory flock: it must survive being read by
## a different process on a network filesystem where flock semantics vary,
## and it must be inspectable by a human wondering who holds it.
##
##   <root>/.geist-lock    pid | boot-unique token | host | epoch seconds
##
## Staleness, not liveness, is what makes it safe: a holder refreshes the
## timestamp on every save, and a lease older than `leaseStaleSeconds` with
## a pid that is gone may be broken. A live pid NEVER has its lease broken,
## whatever the timestamp says.

import std/[exitprocs, locks, nativesockets, os, strutils, times]

import runePragmas
import ./durable

const
  leaseName* = ".geist-lock"
  leaseStaleSeconds* = 120'i64
    ## How old a lease must be before a dead holder's claim can be broken.
    ## Long enough that a slow save on a busy disk never looks abandoned,
    ## short enough that a crashed process does not lock a desktop app out
    ## for the rest of the session.

type
  LeaseInfo* {.role: truthState, tag: "db|storageIo|types".} = object
    ## What the lock file says. `pid` and `host` exist to be shown to a
    ## person: "held by pid 4711 on thinkpad" is an actionable message and
    ## "database is locked" is not.
    pid*: int
    host*: string
    at*: int64

  Lease* {.role: truthState, tag: "db|storageIo|types".} = object
    ## held: false means every write path must refuse.
    ## path: the lock file, kept so release does not have to recompute it.
    ## root: the normalised store root, which is the registry key below.
    held*: bool
    path*: string
    root*: string
    info*: LeaseInfo

proc leasePath*(dir: string): string {.role: helper, inline,
    tag: "db|storageIo".} =
  ## dir: store root whose lock file path is returned.
  result = dir / leaseName

proc encodeLease(i: LeaseInfo): string {.role: encryptor,
    tag: "codecBoundary|write".} =
  ## i: lease contents rendered as one human-readable line.
  result = $i.pid & " " & i.host & " " & $i.at & "\n"

proc decodeLease(s: string): tuple[ok: bool, info: LeaseInfo] {.role: parser,
    tag: "codecBoundary|read".} =
  ## s: one lock file's contents.
  var
    parts: seq[string] = @[]
  parts = s.strip().split(' ')
  if parts.len < 3:
    return (false, LeaseInfo())
  try:
    result.info.pid = parseInt(parts[0])
    result.info.host = parts[1]
    result.info.at = parseBiggestInt(parts[2]).int64
    result.ok = true
  except ValueError:
    result = (false, LeaseInfo())

## --------------------- same-process bookkeeping ----------------------
##
## The lock file identifies a PROCESS, so it cannot tell one Session from
## another inside the same program -- and two Sessions on one store root
## overwrite each other exactly as thoroughly as two processes would. This
## registry is the missing half: the file answers "another program", the
## registry answers "another Session of mine".
##
## It doubles as crash recovery. A lock file naming OUR pid that this
## registry has never heard of cannot be ours: it belongs to a dead process
## whose pid the system handed out again, so it may be taken over.

type
  LeaseClaim = tuple[root, path: string, pid: int]
    ## One lease this process holds: where it is, and under whose pid.

  LeaseRegistry {.role: memory, expectedCount: 1, lifeCycle: lcForever.} = object
    ## Every lease this process holds, and the lock around them.
    lock: Lock
    claims: seq[LeaseClaim]

var
  leases: ptr LeaseRegistry = createShared(LeaseRegistry)
    ## Allocated once and NEVER freed, on purpose. The exit handler below
    ## reads it at the very end of the program -- after the runtime has
    ## already torn down ordinary globals. An ordinary global here was
    ## read after it was gone: every program that ended with a writable
    ## session still open crashed on the way out and left its lock file.

initLock(leases.lock)

proc indexOfRoot(A: openArray[LeaseClaim], root: string): int {.role: parser,
    tag: "db|lifecycle".} =
  ## A/root: the claim list and the store path looked up in it, or -1.
  ##
  ## Takes the list as a PARAMETER rather than reading the registry, so it
  ## is only ever called with the lock already held.
  var
    i: int = 0
  result = -1
  while i < A.len:
    if A[i].root == root:
      return i
    i = i + 1

proc claimLocally(root, path: string, pid: int): bool {.role: actor,
    tag: "db|lifecycle".} =
  ## root/path/pid: the claim being recorded.
  ## Returns false when this process already holds it, in which case
  ## nothing is registered and the caller must not proceed.
  withLock leases.lock:
    {.gcsafe.}:
      if leases.claims.indexOfRoot(root) >= 0:
        return false
      leases.claims.add (root: root, path: path, pid: pid)
      result = true

proc releaseLocally(root: string) {.role: actor,
    tag: "db|lifecycle".} =
  ## root: normalised store path dropped from the registry.
  var
    i: int = 0
  withLock leases.lock:
    {.gcsafe.}:
      i = leases.claims.indexOfRoot(root)
      if i >= 0:
        leases.claims.delete(i)

proc dropLockFile(path: string, pid: int) {.role: dataWriter,
    tag: "db|lifecycle|storageIo".} =
  ## path/pid: remove a lock file only if it is still OURS. A lease we
  ## broke as stale may since have been re-taken by a third process.
  var
    raw: string = ""
  try:
    if not fileExists(path):
      return
    raw = readFile(path)
  except CatchableError:
    return
  if decodeLease(raw).info.pid != pid:
    return
  try:
    removeFile(path)
  except CatchableError:
    discard

proc releaseHeldLeases() {.role: actor, noconv.} =
  ## Every lease this process still holds, released as it exits.
  ##
  ## A CLI that stops on an error calls `quit`, which unwinds nothing.
  ## Without this the lock file outlives the process and the next writer
  ## waits out the staleness window for a program that is already gone --
  ## a self-inflicted outage after a typo.
  withLock leases.lock:
    {.gcsafe.}:
      for held in leases.claims:
        dropLockFile(held.path, held.pid)
      leases.claims = @[]

addExitProc(releaseHeldLeases)

proc processAlive*(pid: int): bool {.role: parser,
    tag: "db|status".} =
  ## pid: process identifier probed WITHOUT signalling it.
  ##
  ## On Linux `/proc/<pid>` answers this with no permissions and no risk of
  ## disturbing the process. Elsewhere the honest answer is "assume it is
  ## alive", which errs toward refusing to break someone else's lease --
  ## the safe direction, since the alternative loses data.
  when defined(linux):
    result = dirExists("/proc/" & $pid)
  else:
    result = true

proc readLease*(dir: string): tuple[ok: bool, info: LeaseInfo] {.role: dataFetcher,
    tag: "db|read|storageIo".} =
  ## dir: store root whose current holder is reported, if any.
  var
    p: string = ""
  p = leasePath(dir)
  if not fileExists(p):
    return (false, LeaseInfo())
  try:
    result = decodeLease(readFile(p))
  except CatchableError:
    result = (false, LeaseInfo())

proc describeLease*(i: LeaseInfo): string {.role: helper,
    tag: "db|status".} =
  ## i: lease rendered for an error message a person has to act on.
  result = "held by pid " & $i.pid & " on " & i.host & ", " &
    $(getTime().toUnix() - i.at) & "s ago"

proc breakable(i: LeaseInfo): bool {.role: parser,
    tag: "db|status".} =
  ## i: existing lease tested for abandonment.
  ## Both conditions must hold: old ENOUGH and its process is gone. A stale
  ## timestamp alone is a busy writer; a dead pid alone may be a pid that
  ## was reused.
  result = (getTime().toUnix() - i.at) > leaseStaleSeconds and
    not processAlive(i.pid)

proc acquireLease*(dir: string): tuple[ok: bool, lease: Lease,
    err: string] {.role: actor,
    tag: "db|lifecycle|storageIo|write".} =
  ## dir: store root claimed for writing.
  ##
  ## Returns ok = false with a description of the holder rather than raising,
  ## because "someone else has it" is a normal answer a caller may want to
  ## handle by opening read-only instead.
  var
    existing: tuple[ok: bool, info: LeaseInfo] = (false, default(LeaseInfo))
    written: tuple[ok: bool, err: string] = (false, "")
    root: string = ""
  if not dirExists(dir):
    createDir(dir)
  root = absolutePath(dir)
  if not claimLocally(root, leasePath(dir), getCurrentProcessId()):
    return (false, Lease(),
      "database is already open for writing by this process (pid " &
      $getCurrentProcessId() & ", another Session on the same store root)")
  existing = readLease(dir)
  # A lock file naming our own pid that the registry does not know is a dead
  # process's leftover, not a live claim -- see the registry note above.
  if existing.ok and existing.info.pid != getCurrentProcessId() and
      not breakable(existing.info):
    releaseLocally(root)
    return (false, Lease(), "database is already open for writing: " &
      describeLease(existing.info))
  result.lease.root = root
  result.lease.path = leasePath(dir)
  result.lease.info.pid = getCurrentProcessId()
  result.lease.info.host = getHostName()
  result.lease.info.at = getTime().toUnix()
  written = replaceDurable(result.lease.path,
    encodeLease(result.lease.info))
  if not written.ok:
    releaseLocally(root)
    return (false, Lease(), written.err)
  result.lease.held = true
  result.ok = true

proc refreshLease*(S: var Lease) {.role: actor,
    tag: "db|storageIo|write".} =
  ## S: lease whose timestamp is moved forward, called on every save so a
  ## long-lived writer never looks abandoned to anyone else.
  if not S.held:
    return
  S.info.at = getTime().toUnix()
  discard replaceDurable(S.path, encodeLease(S.info))

proc releaseLease*(S: var Lease) {.role: actor,
    tag: "db|lifecycle|storageIo|write".} =
  ## S: lease removed, both from disk and from this process's registry.
  if not S.held:
    return
  dropLockFile(S.path, S.info.pid)
  releaseLocally(S.root)
  S.held = false
