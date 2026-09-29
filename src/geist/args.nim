## ---------------------------------------------------------------------
## Args <- one command-line option at a time, the same way in every program
## ---------------------------------------------------------------------
##
##   argv                        nextOption(argv, i, flags)
##   --------------------------  -----------------------------------------
##   --path data                 key "path",  value "data",  last = i + 1
##   --path=data                 key "path",  value "data",  last = i
##   --quiet   ("quiet" a flag)  key "quiet", value "",      last = i
##   list      (not an option)   bare = true, value "list",  last = i
##
## `geist`, `geist-relay`, `geistd`, `geist-relayd` and `geist-routed` all
## read their options this way; each used to carry its own copy of the
## loop, and five copies of one rule are five chances for them to drift.
##
## A caller loops:
##
##   while i < argv.len:
##     step = nextOption(argv, i, ["quiet", "help"])
##     i = step.last
##     case step.key
##     of "path": result.path = step.value
##     ...
##     i = i + 1

import std/strutils

import runePragmas

type
  OptionStep* {.role: truthState, tag: "cli|parsing|types".} = tuple
    ## One option read off the command line.
    ## key: the name without its dashes; "" for a bare word.
    ## value: what follows it -- or the bare word itself.
    ## bare: argv[i] was not an option at all (a command, a file).
    ## last: the index of the last word this option used.
    key: string
    value: string
    bare: bool
    last: int

proc nextOption*(argv: openArray[string], i: int,
    flags: openArray[string]): OptionStep {.role: parser,
    tag: "cli|parsing".} =
  ## argv/i: the command line and where to read.
  ## flags: the option names that take NO value.
  ##
  ## Raises ValueError for an option that needs a value and is the last
  ## word on the line.
  var
    at: int = -1
  if not argv[i].startsWith("--"):
    return ("", argv[i], true, i)
  result = (argv[i][2 .. ^1], "", false, i)
  at = result.key.find('=')
  if at > 0:
    result.value = result.key[at + 1 .. ^1]
    result.key = result.key[0 ..< at]
    return
  if result.key in flags:
    return
  if i + 1 >= argv.len:
    raise newException(ValueError, "option --" & result.key &
      " needs a value")
  result.value = argv[i + 1]
  result.last = i + 1
