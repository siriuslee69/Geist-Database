## ---------------------------------------------------------
## Meta Pragmas <- enum-backed repo-local Ratatoskr metadata
## ---------------------------------------------------------

type
  MetaRole* = enum
    helper,
    math,
    decryptor,
    encryptor,
    sanitizer,
    parser,
    metaParser,
    actor,
    configurator,
    orchestrator,
    metaOrchestrator,
    truthBuilder,
    truthState,
    wrapper,
    stateController,
    dataFetcher,
    dataWriter,
    other
  MetaInput* = enum
    user,
    llm,
    thirdParty,
    trusted
  MetaRisk* = enum
    low,
    medium,
    high
  MetaIssue* = tuple
    name: string
    id: uint64
  MetaIssues* = seq[MetaIssue]
  MetaTag* = enum
    tagOther,
    tagAdmin,
    tagAppApi,
    tagCli,
    tagCliSurface,
    tagCodecBoundary,
    tagCompat,
    tagCompression,
    tagConfig,
    tagConflict,
    tagCopy,
    tagCryptoBoundary,
    tagDb,
    tagDelete,
    tagDistributedFetch,
    tagDocs,
    tagEmbeddedMode,
    tagEntrypoint,
    tagFormatting,
    tagHealth,
    tagIndex,
    tagLifecycle,
    tagMaintenance,
    tagMigration,
    tagNetworkSurface,
    tagObsCli,
    tagOrchestrator,
    tagParsing,
    tagPeerDirectory,
    tagProtocol,
    tagProtocolBridge,
    tagRead,
    tagRuntime,
    tagSchedulerLoop,
    tagServer,
    tagStateController,
    tagStatus,
    tagStorageIo,
    tagStore,
    tagStream,
    tagSync,
    tagAec,
    tagAme,
    tagBackup,
    tagBatch,
    tagLedger,
    tagSidecar,
    tagKeyLifecycle,
    tagTypes,
    tagWrite
  MetaTags* = set[MetaTag]

template input*(x: MetaInput) {.pragma.}
template role*(x: MetaRole) {.pragma.}
template risk*(x: MetaRisk) {.pragma.}
template issue*(x: MetaIssue) {.pragma.}
template issues*(x: MetaIssues) {.pragma.}
template metaTags*(x: MetaTags) {.pragma.}
