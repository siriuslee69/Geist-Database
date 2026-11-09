## ---------------------------------------------------------------------
## Access <- the three rights a subject can hold, and nothing else
## ---------------------------------------------------------------------
##
## On its own so a program that only needs the WORDS (a relay, which keeps no
## data) does not compile the grant table and the store behind it.

import runePragmas

type
  AccessRight* {.role: configurator, tag: "permission|types".} = enum
    ## What a subject may do. Granted by the operator, never asked for.
    ##
    ##   prRead   list, get, find, sync, subscribe, poll
    ##   prWrite  put and delete
    ##   prAdmin  take a copy of everything; change a database's shape
    prRead, prWrite, prAdmin
