## A config file must never win over something visible on the command line.
##
## Both option parsers merge a `userconfig.toml` into what was typed, and
## both used to decide "was this typed?" by comparing the value against the
## default. That works until someone types the default: `--preset app` and
## `--limit 20` and `--listen dac://127.0.0.1:47655` are all things a
## person writes on purpose, and all three were being silently overwritten
## by the file.
##
## It is the same defect the settings loader had with `rowIdentity` -- a
## value cannot answer a question about whether it was set -- so it is
## tested the same way, from both ends.

import std/[os, unittest]

import clients/geist_cli
import server/geistd

proc scratch(name: string): string =
  result = getTempDir() / name
  removeDir(result)
  createDir(result)

proc writeConfig(dir: string): string =
  ## dir: gets a userconfig.toml that disagrees with every default.
  result = dir / "userconfig.toml"
  writeFile(result, """
[database]
path = "/from/the/file"
preset = "secure-app"
passwordFile = "/from/the/file.pw"

[daemon]
listen = "dac://10.0.0.1:9999"
identity = "/from/the/file.id"
trust = ["/from/the/file.pin"]

[client]
remote = "dac://10.0.0.2:8888"
peerPin = "/from/the/file.pin"
limit = 50
""")

suite "the geist CLI: an option beats the file":
  test "a file fills in only what was not typed":
    var
      cfg = writeConfig(scratch("geist_t_prec1"))
      o = withUserConfig(parseOptions(["list", "--config", cfg]))
    check o.path == "/from/the/file"
    check o.preset == "secure-app"
    check o.limit == 50
    check o.remote == "dac://10.0.0.2:8888"

  test "typing the default value still counts as typing it":
    # The regression: `app` and `20` ARE the defaults, so a parser that
    # compares values cannot tell these were asked for.
    var
      cfg = writeConfig(scratch("geist_t_prec2"))
      o = withUserConfig(parseOptions(
        ["list", "--config", cfg, "--preset", "app", "--limit", "20"]))
    check o.preset == "app"
    check o.limit == 20
    # Everything not typed still comes from the file.
    check o.path == "/from/the/file"

  test "a non-default option beats the file too":
    var
      cfg = writeConfig(scratch("geist_t_prec3"))
      o = withUserConfig(parseOptions(
        ["list", "--config", cfg, "--path", "/typed", "--limit", "5"]))
    check o.path == "/typed"
    check o.limit == 5

  test "the options actually typed are recorded":
    var o = parseOptions(["list", "--preset", "app", "--json"])
    check "preset" in o.given
    check "json" in o.given
    check "limit" notin o.given

suite "geistd: an option beats the file":
  test "a file fills in only what was not given":
    var
      cfg = writeConfig(scratch("geist_t_prec4"))
      c = resolveConfig(["--config", cfg])
    check c.path == "/from/the/file"
    check c.preset == "secure-app"
    check c.listen == "dac://10.0.0.1:9999"
    check c.trust == @["/from/the/file.pin"]

  test "typing the default listen address still counts":
    # Binding loopback explicitly is a deployment decision, and a file
    # moving the daemon onto a routable address instead is exactly the
    # surprise this prevents.
    var
      cfg = writeConfig(scratch("geist_t_prec5"))
      c = resolveConfig(
        ["--config", cfg, "--listen", "dac://127.0.0.1:47655",
         "--preset", "app"])
    check c.listen == "dac://127.0.0.1:47655"
    check c.preset == "app"
    check c.path == "/from/the/file"

  test "an empty trust list from the command line is not silently refilled":
    var
      cfg = writeConfig(scratch("geist_t_prec6"))
      c = resolveConfig(["--config", cfg, "--trust", "/typed.pin"])
    check c.trust == @["/typed.pin"]
