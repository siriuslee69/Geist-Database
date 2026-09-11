# Evaluation

Everything that measures Geist rather than being Geist: the tests, the
benchmarks, and the recorded statistics. All three live under
`evaluation/`, because all three answer "is it still right?" rather than
"what does it do?".

╭⟢ 1. Where each kind of measurement lives 🌊
├⟢ 2. Tests 🐦‍🔥
├⟢ 3. Benchmarks 🍣
├⟢ 4. Statistics ⟡
╰⟢ 5. Known gaps ❖

## 1. Where each kind of measurement lives

```text
  evaluation/
  +-- tests/
  |   +-- test_*.nim         one file per area, found by `nimble test`
  |   +-- modular/           proofs about what is NOT compiled
  +-- benchmarks/
  |   +-- geist_bench.nim    the Otter timing harness, one binary
  +-- statistics/
      +-- otter-stats.txt    the recorded shape of the tree
```

**Def. 1 (a test).** A routine that asserts a fact and fails the build
when the fact stops holding.

**Def. 2 (a benchmark).** A routine that reports how long something takes
and asserts nothing. A benchmark cannot fail; it can only get slower, and
noticing that is a person's job.

**Def. 3 (a statistic).** A number about the SOURCE rather than about a
run of it -- how many routines there are, how deeply they nest, how many
are never called.

## 2. Tests

One file per area of behaviour. `nimble test` walks
`evaluation/tests/` and runs every file whose name starts with `test_`,
so adding a file is the whole of adding a suite.

```text
  task                what it runs                        roughly
  ------------------  ----------------------------------  --------
  nimble test         every test_*.nim                    minutes
  nimble testCore     mapper + format                     seconds
  nimble testCrypto   crypto, key lifecycle, backup       seconds
  nimble testApi      session, transport, settings        seconds
  nimble testDurability  generation swap, lease, restore  seconds
  nimble testExchange    live-socket daemon + identity    minutes
  nimble testApiSurface  collection, seek, column, hash   seconds
```

`testExchange` is the slow one and the important one: it starts real
daemons on real sockets and runs real post-quantum handshakes between
them. Nothing else in the suite would notice a handshake that negotiated
successfully and then could not carry a byte.

### The modular proofs

`evaluation/tests/modular/` holds two files that are not ordinary tests.
They are compiled, and then the names of the GENERATED C FILES are
inspected:

```text
  storage_only.nim  ->  does `import geist` pull in a network stack?
  relay_only.nim    ->  does `import geist/wire` pull in a database?
```

Run by `nimble checkModular`, `nimble checkRelay` and
`nimble checkRouter`. A comment saying "the relay must not open a
database" is a wish; a build that fails when it does is a rule. This is
the mechanism that keeps the three halves in `docs/layout.md` separable
on a small device, where "compiles a post-quantum KEM you never use" is
measured in kilobytes of flash.

### Declaring what a test is for

The conventions ask every evaluation routine to say which kind it is, so
the tooling can report coverage by kind rather than guessing from the
wording:

```nim
proc wideRange() {.testKind: tkEdgeCase, covers: "parseWidth".} =
  ...
```

`test "..."` is a call to a template, so no pragma can hang on it. The
kind goes on the line above, in the same words:

```nim
# {.testKind: tkEdgeCase.}
test "an empty list is refused":
  check mean(@[]) == 0
```

The kinds are `tkUnit`, `tkEdgeCase`, `tkBenchmark`, `tkRegression`,
`tkBugfix`, `tkIntegration`, `tkFuzz`, `tkSmoke`, `tkProperty`,
`tkOther`. `covers` names the routine under test; `pins` names the bug a
regression test holds down. See section 5 for where this repository
currently stands on that.

## 3. Benchmarks

One binary, several groups, built once and run by group:

```text
  nimble bench          every group
  nimble benchCrypto    hash families, digest widths, MAC combiners
  nimble benchIo        write throughput, point reads, column scans
  nimble benchColumns   column kinds and collapsing
  nimble benchRefs      the reference cell encoding
```

The harness warms up before it measures -- first-touch page faults and a
cold allocator otherwise show up as "the first configuration is slow" --
and prints a table per group. Numbers from these runs, with the machine
they came from, are in `docs/measurements/`.

A benchmark that Otter should also count in its coverage picture carries
`testKind: tkBenchmark`. A benchmark whose own body Otter should
instrument for timing carries `otterBench`. Those are different jobs and
a routine may have both.

## 4. Statistics

```text
  nimble stats
```

Runs Otter over the tracked tree and writes
`evaluation/statistics/otter-stats.txt`. The file is committed on
purpose: a number in a file shows up in a diff, and a number somebody
remembers from last month does not.

What the lines mean:

```text
  Files / Lines          size of the tracked tree
  Routines / average     how many, and how long each is
  Nesting                sites at depth 2, 3, and deeper. The house rule
                         is no nested loops and no nested ifs, so triple
                         and deeper are the ones to work off.
  Input handlers         routines taking data from outside the program
  Tests (declared kind)  how many evaluation routines say what they are
  Untested routines      routines no test reaches
  Never called           routines nothing in the tree calls
```

`Never called` overcounts. Otter's call graph does not resolve every
implicit call -- an overloaded `$` used by string interpolation is
reported as dead while being called from four places. Read it as a list
to check, not a list to delete.

### Measuring the tracked tree only

`nimble stats` measures what git tracks. That matters here: an untracked
`.geist-legacy/` folder holds the previous implementation as a reference
copy, and measuring it along with the current tree turns 873 routines
into 1292 and buries every real finding. If you run Otter by hand, point
it at a clean checkout rather than a working folder.

## 5. Known gaps

Honest state of the measurements, from the last `nimble stats`:

```text
  what                              where it stands        what it means
  --------------------------------  ---------------------  -------------
  tests with a declared testKind    0 of 507               every kind is
                                                           guessed from
                                                           the wording
  routines with a role pragma       768 of 873             105 are absent
                                                           from every
                                                           Otter chart
  untested routines                 230 of 873
  triple-or-deeper nesting          135 sites
  benchmark cover                   0 routines             no benchmark
                                                           declares what
                                                           it proves
```

None of these is a defect in what Geist does; all of them are places
where the tooling cannot see what the code is doing. They are listed in
`agents/PROGRESS.md` under "Features (Planned)" in the order worth
attacking them.
