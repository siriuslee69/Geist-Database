## Overlay directory <- administrator-owned aliases and authenticated live leases.
## Ownership persists in configuration; source IP:port and availability expire.
import std/[tables, monotimes, json]
import runePragmas
import ./types
import ./overlay_aliases

export overlay_aliases

const
  overlayLeaseSeconds* = 90'i64
  overlayRenewSeconds* = 30'i64
  maxOverlayIdentities* = 256
  maxOverlayAliases* = 32

type
  OverlayGrant* {.role: configurator.} = object
    subject*: string
    aliases*: seq[string]

  OverlayLease* {.role: truthState, expectedCount: [0, 256],
    lifeCycle: lcSession.} = object
    subject*: string
    endpoint*: string
    expiresAt*: int64
    revision*: uint64

  OverlayDirectory* {.role: truthState, expectedCount: 1,
    lifeCycle: lcForever.} = object
    owners: Table[string, string]
    grants: Table[string, seq[string]]
    leases: Table[string, OverlayLease]
    nextRevision: uint64

  OverlayResolution* {.role: preparedData.} = object
    alias*: string
    subject*: string
    aliases*: seq[string]
    observedEndpoint*: string
    remainingSeconds*: int64
    revision*: uint64

proc overlayNow*(): int64 {.role: dataFetcher.} =
  ## A local monotonic clock; peer clocks cannot extend leases.
  result = getMonoTime().ticks div 1_000_000_000'i64

proc readGrant(n: JsonNode): OverlayGrant {.role: sanitizer.} =
  ## n: one configured owner and its aliases.
  if n.kind != JObject: raise newException(ValueError, "overlay grant must be an object")
  result = OverlayGrant(subject: n{"subject"}.getStr())
  if n{"aliases"}.isNil or n["aliases"].kind != JArray:
    raise newException(ValueError, "overlay aliases must be an array")
  for alias in n["aliases"]: result.aliases.add alias.getStr()

proc overlayGrants*(n: JsonNode): seq[OverlayGrant] {.role: sanitizer.} =
  ## n: administrator configuration, not a peer-supplied ownership claim.
  if n.kind != JArray: raise newException(ValueError, "overlay grants must be an array")
  if n.len > maxOverlayIdentities: raise newException(ValueError, "too many overlay identities")
  for item in n: result.add readGrant(item)

proc addGrant(S: var OverlayDirectory, g: OverlayGrant) {.role: configurator.} =
  ## S/g: one owner; fail rather than choose between conflicting aliases.
  var
    alias: string = ""
    names: seq[string] = @[]
  if g.subject.len == 0 or g.subject.len > 63:
    raise newException(ValueError, "invalid overlay subject")
  if S.grants.hasKey(g.subject): raise newException(ValueError, "duplicate overlay subject")
  if g.aliases.len == 0 or g.aliases.len > maxOverlayAliases:
    raise newException(ValueError, "an identity needs 1..32 overlay aliases")
  for name in g.aliases:
    alias = overlayAlias(name)
    if S.owners.hasKey(alias): raise newException(ValueError, "duplicate overlay alias: " & alias)
    S.owners[alias] = g.subject
    names.add alias
  S.grants[g.subject] = names

proc initOverlayDirectory*(G: openArray[OverlayGrant]): OverlayDirectory {.
    role: configurator.} =
  ## G: grants for pinned subjects; duplicate ownership is rejected at startup.
  if G.len > maxOverlayIdentities: raise newException(ValueError, "too many overlay identities")
  result.owners = initTable[string, string]()
  result.grants = initTable[string, seq[string]]()
  result.leases = initTable[string, OverlayLease]()
  for g in G: result.addGrant(g)

proc renewOverlayLease*(S: var OverlayDirectory, p: PeerContext,
    now: int64): OverlayLease {.role: actor.} =
  ## S/p/now: p is the authenticated socket context, including its full endpoint.
  var
    lease: OverlayLease = default(OverlayLease)
  if prWrite notin p.rights: raise newException(ValueError, "lease renewal needs write rights")
  if not S.grants.hasKey(p.subject): raise newException(ValueError, "identity has no overlay grant")
  if p.address.len == 0: raise newException(ValueError, "missing observed endpoint")
  lease = S.leases.getOrDefault(p.subject)
  if lease.endpoint != p.address or lease.expiresAt <= now:
    inc S.nextRevision
    lease.revision = S.nextRevision
  lease.subject = p.subject
  lease.endpoint = p.address
  lease.expiresAt = now + overlayLeaseSeconds
  S.leases[p.subject] = lease
  result = lease

proc liveOverlayLease*(S: OverlayDirectory, subject: string,
    now: int64): OverlayLease {.role: parser.} =
  ## S/subject/now: fail closed when the owner stopped checking in.
  result = S.leases.getOrDefault(subject)
  if result.subject.len == 0 or result.expiresAt <= now:
    raise newException(ValueError, "overlay identity is offline")

proc resolveOverlayAlias*(S: OverlayDirectory, name: string,
    now: int64): OverlayResolution {.role: dataFetcher.} =
  ## S/name/now: one exact alias; ports never collapse into an IP-only key.
  var
    alias: string = overlayAlias(name)
    owner: string = ""
    lease: OverlayLease = default(OverlayLease)
  if not S.owners.hasKey(alias): raise newException(ValueError, "unknown overlay alias")
  owner = S.owners[alias]
  lease = S.liveOverlayLease(owner, now)
  result = OverlayResolution(alias: alias, subject: owner,
    aliases: S.grants[owner], observedEndpoint: lease.endpoint,
    remainingSeconds: lease.expiresAt - now, revision: lease.revision)

proc resolutionJson*(r: OverlayResolution): JsonNode {.role: helper.} =
  ## r: public address-book metadata; no key or message content.
  result = %*{"alias": r.alias, "subject": r.subject, "aliases": r.aliases,
    "observedEndpoint": r.observedEndpoint, "remainingSeconds": r.remainingSeconds,
    "revision": $r.revision}
