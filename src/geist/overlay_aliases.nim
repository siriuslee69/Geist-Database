## Overlay aliases <- canonical local domains/IPs, with an optional local port.
## No DNS lookup: the address book belongs to one Geist relay.
import std/[strutils, net]
import runePragmas
import var_invariants

const maxOverlayAliasBytes* = 320

proc labelProblem(s: string): string {.role: sanitizer.} =
  ## s: one nonempty ASCII label, bounded and without edge hyphens.
  var
    i: int = 0
  if s.len == 0 or s.len > 63:
    return "local name has an empty or oversized label"
  if s[0] == '-' or s[^1] == '-':
    return "local name label starts or ends with '-'"
  while i < s.len:
    if s[i] notin {'a'..'z', '0'..'9', '-'}:
      return "local names accept ASCII letters, digits and '-'"
    inc i

proc domainProblem(s: string): string {.role: sanitizer.} =
  ## s: lower-case ASCII domain, without a port or final dot.
  var
    labels: seq[string] = s.split('.')
    problem: string = ""
  if s.len == 0 or s.len > 253:
    return "local name must contain 1..253 bytes"
  for label in labels:
    problem = labelProblem(label)
    if problem.len > 0: return problem

proc canonicalHost(s: string): string {.role: sanitizer.} =
  ## s: a domain or IP; numeric/colon forms must be valid IPs.
  var
    h: string = s.toLowerAscii()
    numeric: bool = true
    c: char = '\0'
  if h.len == 0:
    raise newException(ValueError, "local host is empty")
  for item in h:
    c = item
    if c notin {'0'..'9', '.'}: numeric = false
  if ':' in h or numeric:
    return $parseIpAddress(h)
  if h.endsWith("."): h.setLen(h.len - 1)
  result = h

proc aliasParts(s: string): tuple[host: string, port: string] {.role: parser.} =
  ## s: separate brackets and port before canonicalizing the host.
  var
    cut: int = -1
  if s[0] == '[':
    cut = s.find(']')
    if cut < 0: raise newException(ValueError, "unclosed IPv6 alias")
    result.host = s[1 ..< cut]
    if ':' notin result.host: raise newException(ValueError, "brackets require IPv6")
    if cut + 1 == s.len: return
    if s[cut + 1] != ':': raise newException(ValueError, "invalid IPv6 port")
    result.port = s[cut + 2 .. ^1]
    if result.port.len == 0: raise newException(ValueError, "empty local port")
    return
  if s.count(':') != 1: return (s, "")
  cut = s.find(':')
  result = (s[0 ..< cut], s[cut + 1 .. ^1])
  if result.port.len == 0: raise newException(ValueError, "empty local port")

proc overlayAlias*(s: string): string {.role: sanitizer,
    givesRun: result.len > 0 and result.len <= maxOverlayAliasBytes.} =
  ## s: exact alias; normalize case, IP spelling and decimal port.
  var
    parts: tuple[host: string, port: string] = ("", "")
    h: string = ""
    portText: string = ""
    port: int = 0
    problem: string = ""
  if s.len == 0 or s.len > maxOverlayAliasBytes:
    raise newException(ValueError, "local alias must contain 1..320 bytes")
  parts = aliasParts(s)
  h = canonicalHost(parts.host)
  portText = parts.port
  if ':' notin h:
    problem = domainProblem(h)
    if problem.len > 0: raise newException(ValueError, problem)
  result = if ':' in h: "[" & h & "]" else: h
  if portText.len == 0: return
  for c in portText:
    if c notin {'0'..'9'}: raise newException(ValueError, "invalid local port")
  port = parseInt(portText)
  if port < 1 or port > 65535:
    raise newException(ValueError, "local port must be 1..65535")
  result.add ":" & $port
