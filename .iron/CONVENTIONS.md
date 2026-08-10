# Proto Conventions
The project should always be written in Nim unless stated otherwise. Please follow these guidelines and conventions.

## All functions and custom types need custom pragmas.
These tags and pragma definitions live inside the .iron folder.
The tags type is repo specific and should be extended/fit respectively.

## No let declarations!
Let declarations should ONLY be used for functions that have many if/case statements and where an initialization of
each var for every branch is highly inefficient. Otherwise use var or const at the beginning of a function.
Give variables a default value and reassign later if needed.
Avoid declarations inside loops.

## No loop nesting! No if-statement nesting!
Instead, inline functions via pragma or use templates!

## No unnecessary, repeating "var", "const" or "type" identifiers in each new line!
Always define vars, consts and types in indented blocks!

## No complex logic! Build modular, parallel, multipass logic.
Adhere to the mantra: Perceive data -> build truth state -> act on parsed data
To make this possible, we use roles for data and functions, this also helps greatly with visualization and debugging.

### Type Roles
`rawData` <- Raw data from somewhere (network, input, file, etc.)
`preparedData` <- Prepared data (sanitized + decrypted)
`truthState` <- Truth state of the data
`memory` <- Regularly accessed data that needs to be stored in memory for performance reasons

### Function Roles
`dataFetcher` <- Grabs data from somewhere (network, input, file, etc.) and returns it via the `rawData` role object.
`decryptor` <- Decrypts data (if encrypted) and returns it via the `preparedData` object.
`sanitizer` <- Cleans data (remove invalid characters, etc.) and returns it via the `preparedData` role object.
(both sanitizer and decryptor are optional and can be combined)
`parser` (or `metaParsers`) <- Extracts information from `preparedData` role objects (or the `truthState`) and outputs `primitive` types only.
`truthBuilder` <- Builds a truth state from the parsed data and return `primitives` by calling the parsers and feeding it into the `truthState` object.
`actor` <- Reads the `TruthState` and acts/computes on other data/output. It's decisions are based on information from the `truthState` role object only.
`orchestrator` (/metaOrchestrators) <- Coordinates the above functions (Calling sanitizer, decryptor, parser, truthBuilder, actor etc. in succession or in parallel).
`metaOrchestrator` <- Coordinates the orchestrators
`encryptor` <- Encrypts data (if needed) and hands it to the `dataWriter` or stores it in a `memory` role object.
`dataWriter` <- Writes data to somewhere (network, output, file, etc.)
`helper` <- Helper functions that do not fit into the above categories
`math` <- Math functions that perform complex calculations on any kind of data

## Debugging
For faster debugging, put a when

## Some structural examples

How to avoid nesting with highlevel functions:

```nim
proc myFunc1(): void {.inline.} =
  ...

proc myFunc2(): void {.inline.} =
  ...

proc highLevelFunc(): int =
  myFunc1()
  myFunc2()
  ...
```

## Function Syntax

Avoid colon syntax for function calls.

Good example:
```
funcX(param1, param2)
```
or
```
param1.funcX(param2)
```

Bad example
```
funcX:
  param1, param2
```

## Naming and Parameter Rules

- Parameter names should use the first letter of what they represent.
- Explain parameter meaning below the function declaration with a `##` doc comment.
- Arrays, sequences, openArrays, and tables should use capital letters like `A`.
  - Example: an array of records -> `R`
- Some parameters should always use a special name, like `dir` for directory and `args` for arguments. Do that for the most generic ones. In these cases an uppercase letter is not needed, even though these are arrays.
- State objects to be mutated use `S`. If multiple, use `S0`, `S1`, `S2`, ...
- Math-heavy functions use `a,b,c` or `x,y,z` (then `x1`, `x2`, `x3`, ...).
- For arrays/lists in math functions, use uppercase letters like `X,Y,Z` or `A,B,C`.
- `t` is reserved for temporary variables inside functions.
- `i,j,k` are indices; `l,m,n` are lengths.
- Use `while` for complex loops; use `for` for simple one-call loops.
- If a function has only one parameter, you may use its first letter unless it collides with index identifiers.

## Result Variables

For clarity, you may assign to a temporary variable and set `result` at the end.

```nim
proc myProc(a, b: uint8): uint8 =
  var
    t: uint8 = 0 #this is basically the result, with an initialized default value
  t = callSomeOtherFunc(a, b)
  t = t + callYetAnotherFunc(a)
  result = t
```

## Declarations and Formatting

Always indent `var`, `let`, `const`, and `type` into blocks when declaring multiple values.

```nim
const
  c1: string = "hey" #use const where possible
  c2: int = 23
  c3: uint8 = 4
var
  t1: string = "" #initialize if possible to default values
  t2: int = 0
  t3: uint8 = 0
let
  t4: string = "holla" #avoid let definitions, unless for user inputs
  t5: int = 0
```
## Project Layout

The root of a repo should be structured into
```
/.iron <- folder for Iron-RepoCoordinator
/nix <-nix shell/dependencies (not always needed, only when UI or other dependencies required)
/src/lib <- actual repo content
/src/interfaces <- guis/uis/clis (not always needed, libraries will at max use a cli)
/submodules <- submodules
/tests
```

Order modules by dependency level:

```
src/lib/types.nim
src/lib/level0/moduleX.nim <- depends on types only
src/lib/level1/moduleXY.nim <- depends at least on moduleX
src/lib/level2/moduleTZ.nim <- depends at least on moduleXY
...
```

In some libraries it might make sense to instead sort modules by role/name.
That is especially the case, if a repo is a collection of many tiny algorithms/parsers/helpers.
In these cases, you can group them by module first instead of by dependency level.

Every (`.nim` file) must have a description at the top explaining what it does.
Prefer visual hints like arrows (`<- ->`), ASCII art boxes, and separators (`|`, `-`).

## Reuse and Compression

If you write three similar helper functions across modules, move them into `utils` and overload or use generics (`when`/`case`) instead. Do this regularly to keep the project lean and avoid unneeded bloat.

## Documentation

Update the README when you make bigger project changes.

At the bottom of the README of a project, include a cleaner, more formatted version of these conventions so maintainers can quickly understand the programming style.

## Tools and Tests

- Add a `tools` folder when needed (for submodule builders or other pre-compile time utilities).
- Always include a `test` folder with unit tests for important functions.
- After changing code or dependencies, run tests and fix errors.

## .iron Folder (Repo Coordination)

Every repo must have a `.iron/` folder located next to `src/`.

- Store repo-coordination configs and templates there.
- Use `Proto-RepoTemplate/.iron/` as the template source.
- The local submodule override file lives at `.iron/.local.gitmodules.toml` and should be ignored by git.

## C Bindings (cNimWrapper)

We have a cNimWrapper in the parent directory where all projects live. It should accurately create bindings for C libraries. If you need bindings for a C-only repo, you may use it and clone the repo without asking.

## Shared Utils (Fylgia-Utils)

There is a repo called "Fylgia-Utils" (git URL: https://github.com/siriuslee69/fylgia-utils).
- It may contain tools and other things you will reuse.
- Put generic helper functions there when appropriate.

## Shared SIMD library (SIMD-Nexus)

There is a repo called SIMD-Nexus which exports high-level bindings for nimsimd.
It also features utility functions like simd string searching.
Use where appropriate.

## Nimsuggest

Do not write pre-compile time import statements that prevent nimsuggest from checking functions.

## progress.md

Inside each project, create `progress.md` inside .iron (if it does not exist) and track:

1. Current commit message (update after every change)
2. Features to implement (total)
3. Features already implemented
4. Features in progress

And also:

1. Last big change or problem encountered
2. How you tried to fix it, and whether it worked

## .nimble Tasks

Create a `.nimble` file with tasks for:
1. Test runs (call after each change)
2. Builders
3. Autopushing

## Configs

Every project should have a parser module for a config.toml file which sets global vars inside the lib and an additional parser for the userconfig.toml if it is meant to be used as a client.

## Compatibility

In general, all the projects are meant to run on Linux and Windows. Specifically Windows 11 and NixOS.
Both should have first-class support and run out of the box.
You may follow the general structure of the rest of this Proto-RepoTemplate repo and the example files.

## Issue Playbook

Create an issue playbook at the bottom of the README.md which lists common issues/workaround for bugs and problems that have been encountered and could not be fixed or are only fixed superficially. Some of them may be at risk of greater degradation when they are just patching other imported and broken submodules/repos. The users should know of these in advance.

## Conventions

Keep a copy of this .iron folder and its contents in each repo.
Make sure to change the path in .local.config.toml in the .iron folder accordingly.
