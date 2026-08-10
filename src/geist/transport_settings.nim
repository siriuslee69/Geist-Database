## ---------------------------------------------------------------------
## Transport settings <- the [transport] section of config.toml
## ---------------------------------------------------------------------
##
##   [transport]
##   startTier    = "standard"
##   secretAtMiB  = 64
##   archiveAtMiB = 512
##
## Split out of `settings.nim` for one reason: this is the only settings
## code that needs to know an algorithm tier exists, and knowing that means
## importing `masks`, which means importing Bifrost. A program that only
## writes rows to disk should not compile a post-quantum KEM to find out
## how many backup copies to keep.
##
## Same FILE, different section. An operator still writes one config.toml;
## it is only the reader that is in two halves.
##
## WHAT IS CONFIGURABLE IS WHEN A SESSION CLIMBS, NOT WHAT IT CLIMBS INTO.
## The start tier and the two volume thresholds come from the file; which
## KEMs, signatures and ciphers each tier selects does not. That is the one
## thing about the network Geist owns outright (see masks.nim), and a
## settings file able to weaken a tier's mask would turn a guarantee into a
## deployment detail.

import std/[json, os, strutils]

import ../analysis_pragmas
import ./masks
import ./toml_read

type
  TransportDefaults* {.role: configurator, metaTags: {tagAme, tagConfig,
      tagNetworkSurface, tagTypes}.} = object
    ## startTier: where a session begins.
    ## secretAtMiB / archiveAtMiB: how many mebibytes it has to have moved
    ##   before it rekeys upward into a wider algorithm set -- a
    ##   conversation long enough to be worth attacking earns a stronger
    ##   suite.
    ## loadedFrom: the file these came from, empty when built in.
    startTier*: GeistTier
    secretAtMiB*: uint64
    archiveAtMiB*: uint64
    loadedFrom*: string

proc builtinTransportDefaults*(): TransportDefaults {.role: configurator,
    metaTags: {tagAme, tagConfig}.} =
  ## What the library does with no config.toml at all: exactly the policy
  ## `masks.nim` ships, restated so a reader can see it here.
  result.startTier = defaultTriggerPolicy().startTier
  result.secretAtMiB = defaultTriggerPolicy().rows[gtSecret].threshold
  result.archiveAtMiB = defaultTriggerPolicy().rows[gtArchive].threshold

proc parseTierName*(name: string): tuple[ok: bool, tier: GeistTier] {.
    role: parser, metaTags: {tagAme, tagConfig, tagParsing}.} =
  ## name: a tier as written in the file, case and hyphens forgiven.
  case name.strip().toLowerAscii()
  of "telemetry": result = (true, gtTelemetry)
  of "userdata", "user-data": result = (true, gtUserData)
  of "standard": result = (true, gtStandard)
  of "secret": result = (true, gtSecret)
  of "archive": result = (true, gtArchive)
  of "recovery": result = (true, gtRecovery)
  else: result = (false, gtStandard)

proc loadTransportDefaults*(path: string = libraryConfigName): tuple[ok: bool,
    defaults: TransportDefaults, err: string] {.role: configurator,
    metaTags: {tagAme, tagConfig, tagParsing, tagRead}.} =
  ## path: `config.toml`; only its `[transport]` section is read.
  var
    doc: tuple[ok: bool, node: JsonNode, err: string]
    transport: JsonNode
    complaint: string = ""
    tier: string = ""
  result.defaults = builtinTransportDefaults()
  doc = tomlOf(path)
  if not doc.ok:
    return (false, result.defaults, doc.err)
  transport = doc.node.section("transport")
  complaint = checkKeys(transport,
    ["startTier", "secretAtMiB", "archiveAtMiB"], "[transport]")
  if complaint.len > 0:
    return (false, result.defaults, complaint)
  tier = transport.setting("startTier", "")
  if tier.len > 0:
    var named = parseTierName(tier)
    if not named.ok:
      return (false, builtinTransportDefaults(), path &
        ": unknown startTier '" & tier & "'; known: telemetry, userData, " &
        "standard, secret, archive, recovery")
    result.defaults.startTier = named.tier
  result.defaults.secretAtMiB = transport.setting("secretAtMiB",
    result.defaults.secretAtMiB)
  result.defaults.archiveAtMiB = transport.setting("archiveAtMiB",
    result.defaults.archiveAtMiB)
  result.defaults.loadedFrom = if fileExists(path): path else: ""
  result.ok = true

## ------------------------ the library's own copy --------------------

var
  activeTransport: TransportDefaults = builtinTransportDefaults()

proc useTransportDefaults*(d: TransportDefaults) {.role: stateController,
    metaTags: {tagAme, tagConfig, tagLifecycle}.} =
  ## d: the policy every later `defaultTierPolicy` is built from. Set it
  ## ONCE, before connecting anything.
  {.gcsafe.}:
    activeTransport = d

proc transportDefaults*(): TransportDefaults {.role: parser,
    metaTags: {tagAme, tagConfig, tagRead}.} =
  ## The transport defaults in force, built-in unless a file replaced them.
  {.gcsafe.}:
    result = activeTransport

proc initTransportDefaults*(path: string = libraryConfigName): tuple[ok: bool,
    err: string] {.role: configurator,
    metaTags: {tagAme, tagConfig, tagLifecycle, tagRead}.} =
  ## path: config.toml, read and adopted in one step. A missing file is
  ## success -- the built-in policy IS the answer in that case.
  var
    got: tuple[ok: bool, defaults: TransportDefaults, err: string]
  got = loadTransportDefaults(path)
  if not got.ok:
    return (false, got.err)
  useTransportDefaults(got.defaults)
  result = (true, "")

proc defaultsTriggerPolicy*(d: TransportDefaults): TriggerPolicy {.
    role: configurator, metaTags: {tagAme, tagConfig, tagNetworkSurface}.} =
  ## d: transport defaults turned into the policy a handshake climbs by.
  result = defaultTriggerPolicy()
  result.startTier = d.startTier
  result.rows[gtSecret] = TierTrigger(kind: tkTransferred,
    threshold: d.secretAtMiB)
  result.rows[gtArchive] = TierTrigger(kind: tkTransferred,
    threshold: d.archiveAtMiB)

proc defaultTierPolicy*(): TriggerPolicy {.role: configurator,
    metaTags: {tagAme, tagConfig, tagNetworkSurface}.} =
  ## The tier policy in force, from whatever config.toml was adopted.
  result = defaultsTriggerPolicy(transportDefaults())
