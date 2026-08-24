# The mutation matrix

Every test in this branch's suite is an assertion that some guard in the
gateway does its job. Nothing in a green suite distinguishes a test that
enforces its guard from a test that would pass with the guard deleted. This
directory's `mutation_matrix.py` measures that difference: it turns each guard
off in the source, one at a time, rebuilds, and requires **the test named after
that guard** to fail. A guard whose own test does not notice its removal is
reported by name.

## Why this branch exists

The workflow below is not in PR #2397 and is not proposed for upstream. It is
here so the instrument behind the coverage numbers in that PR can be read and
run by anyone reviewing them, and so a sweep produces a run anyone can open
rather than a number quoted from a local afternoon.

`.gitignore` in this repository ignores `.github`, which is why an earlier
attempt to add this workflow committed nothing while the commit message said
otherwise. It is added here with `git add -f`.

## Running it

From the repository root — `PYTHONPATH` is not decoration, see the module
docstring:

```
PYTHONPATH=$PWD poetry -C tests run python -m tests.mutation_matrix --named
... --named principal          # one guard, by substring
... --named --changed <base>   # only guards whose anchor file the diff touched
... --named --shard 3/8        # this shard's guards, for splitting across jobs
... --named --fail-fast        # stop at the first guard that does not discriminate
```

A full sweep is **over fourteen hours** on one machine: the run rebuilds the
gateway binary for each of the guards pinned by integration tests. A
GitHub-hosted job is killed at six hours, so the workflow shards the sweep
eight ways and a summary job requires the shards to account for every guard in
the table before it will call the result a sweep.

## Reading the artifact

Each run writes `tests/mutation-matrix.json`. Every count in it is a count of
that run:

| field | meaning |
|---|---|
| `guards_defined` | guards in the table |
| `guards_selected` | guards this invocation set out to measure |
| `guards_measured` | guards it reached a verdict on |
| `guards_that_discriminate` | of those, how many failed their own named test when disabled |
| `partial` | true unless the run covered the whole table |
| `shard` | `INDEX/TOTAL`, or null |
| `refused` | why the run declined to produce a number, when it did |

`partial: true` means the run says nothing about the guards it did not hold. A
shard's result is always partial; only the summary job stands for a sweep.

## What it cannot tell you

- A guard with no test named after it is a hole this cannot see. `--named`
  refuses to start when a declared discriminator does not exist, which catches
  the typo, not the omission.
- `--changed` measures only guards whose anchor file the diff touched. It
  cannot see a guard broken in a file the change did not touch.
- A verdict is about the guard's *own* test. A guard caught only by some other
  test still reports as not discriminating, and that is deliberate — a test
  that fails for a reason unrelated to its name is not coverage you can rely
  on later.
