## ---------------------------------------------------------------------
## Geist Convert <- JSON to TOML and back, text or objects
## ---------------------------------------------------------------------
##
## Run from the repo root:
##   nim c -r examples/geist_convert.nim
##
##   text  --convertDoc(json -> toml)-->  text
##   file  --convertFile("a.json", "a.toml")-->  file   (format by extension)
##   T     --toDocText(x, dfToml)-->  text  --fromDocText-->  T
##
## Nothing is dropped quietly. TOML cannot hold everything JSON can -- a
## `null`, a list that mixes tables with plain values, a document that is
## a list rather than a table -- and a conversion that meets one says
## where, instead of writing a file that is missing it.
##
## From the shell, the same thing:
##   geist convert settings.json settings.toml

import runePragmas
import geist

type
  Server = object
    host: string
    port: int
    tls: bool

  MailSettings = object
    server: Server
    users: seq[string]

const
  jsonText: string = """
{
  "server": {"host": "mail.example", "port": 993, "tls": true},
  "users": ["alice", "bob"]
}
"""

when isMainModule:
  var
    toml: tuple[ok: bool, text: string, err: string] = (false, "", "")
    back: tuple[ok: bool, text: string, err: string] = (false, "", "")
    refused: tuple[ok: bool, text: string, err: string] = (false, "", "")
    read: tuple[value: MailSettings, report: DocReport] =
      (default(MailSettings), default(DocReport))

  ## ── 1. JSON text -> TOML text ──
  toml = convertDoc(jsonText, dfJson, dfToml)
  doAssert toml.ok, toml.err
  echo "--- as TOML"
  echo toml.text

  ## ── 2. And back ──
  back = convertDoc(toml.text, dfToml, dfJson)
  doAssert back.ok, back.err
  echo "--- back to JSON"
  echo back.text

  ## ── 3. A value TOML has no word for is refused, with where it was ──
  refused = convertDoc("""{"server": {"host": null}}""", dfJson, dfToml)
  echo "--- null in TOML: ", refused.err

  ## ── 4. Objects: the text is the object's fields, and nothing else ──
  echo "--- an object as TOML"
  echo toDocText(MailSettings(server: Server(host: "localhost", port: 143),
    users: @["carol"]), dfToml)
  read = fromDocText(jsonText, dfJson, default(MailSettings))
  doAssert read.report.ok, read.report.err
  echo "--- JSON into an object: ", read.value.server.host, ":",
    read.value.server.port, " users=", read.value.users
