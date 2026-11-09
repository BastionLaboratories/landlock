# landlock

landlock changes one file on a machine safely. It remembers the file's exact bytes, tries the change in a sandbox away from the real file, wants a signed approval that matches those exact bytes, swaps the file in a single move while keeping the old copy, runs the tests that depend on it, and puts the old copy back by itself if any of them fail. Every step leaves one line in an append-only receipt file.

It is plain Python 3.12 with no third-party packages. Repository: `BastionLaboratories/landlock`. License: Apache-2.0.

## The four parts

1. **Pin.** `pin` records a file's sha256, size and modification time. Every later step takes a pin, never a bare path, and refuses if the file's bytes have moved since.
2. **Rehearse.** The candidate's bytes are shown at the target's own path inside a bubblewrap sandbox and the tests run there: nothing is copied, the real filesystem is read-only, a scratch temporary folder is writable, the home folder is a throwaway, there is no network and there is a time limit. The answer is `WOULD LAND` or `WOULD REFUSE`, with the test output. The real file is never written, and a test command that names the real file refuses before anything runs.
3. **Approve.** An approval is a signature (HMAC-SHA256) over the target path, the candidate's sha256, the pin's sha256 and an expiry, made with a secret key file that only you hold (mode 600, kept outside the folders landlock may change). One approval covers exactly one candidate and can be used once: after a landing has been done under an approval, landing again with the same approval refuses, and you approve again. Rolling back and recovering never need an approval. An unsigned, expired, wrong-file or moved-bytes approval refuses.
4. **Land.** With a good approval and a fresh pin, the old copy is laid beside the file as `name.pre_land_<stamp>`, the candidate is written to a temporary name in the same folder, flushed to disk and renamed over the file in one call. Then the tests of every registered dependent run. A failing test, or any crash, restores the old copy by the same rename. After the dependents' tests, the file is measured once more: if its bytes are anything other than the candidate's, the old copy is restored and the run is reported as a fault naming both digests. A small journal lets `recover` finish or undo a run that was killed at any step.

## Install

```
pip install .
```

For the tests: `pip install ".[test]"`. For rehearsal you also need [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) on your PATH, for example `sudo apt install bubblewrap`.

## The sandbox requirement

Rehearsal needs bubblewrap and refuses without it. There is no weaker fallback: if `bwrap` is missing, `landlock rehearse` prints `REFUSED: bubblewrap is required ...` and exits 2. Landing does not rehearse for you; run `rehearse` first as your policy decides.

## The config file

One TOML file names where landlock may work. Every path must be absolute.

```toml
roots = ["/srv/app"]
receipts = "/var/lib/landlock/receipts.jsonl"
secret = "/etc/landlock/secret.key"

[tests]
default = ["python3", "-m", "pytest", "-q"]

[tests.by_path]
"/srv/app/billing/rates.py" = ["python3", "-m", "pytest", "-q", "tests/test_rates.py"]

[dependents]
"/srv/app/billing/rates.py" = ["/srv/app/billing/invoice.py"]

[walls]
test_wall_s = 300
load_max = 48.0
approval_ttl_s = 86400
rehearse_ro_dirs = ["/srv/shared/lib"]
```

- `roots`: the folders files may be landed into. A path outside them refuses.
- `receipts` and `secret`: must be outside every root, and must be two different files.
- `tests`: the command that tests a file; `default` for all, `by_path` for particular files.
- `dependents`: for a file, the other files whose tests run after it lands.
- `walls`: the test time limit in seconds, a machine load limit, how long an approval lives, and two lists of folders a rehearsal shows read-only (never copied): `rehearse_ro_dirs`, folders anywhere on the machine, and `rehearse_extra_dirs`, the older list, folders inside a root.

## The command line

Give the config with `--config <path>`, or set `LANDLOCK_CONFIG`, or keep `./landlock.toml`.

```
landlock pin <path>
landlock rehearse <path> <candidate>
landlock approve <path> <candidate> [--ttl SECONDS] [--out FILE]
landlock land <path> <candidate> --approval <file>
landlock rollback <path>
landlock recover <journal>
landlock receipts [path]
landlock verify [path]
```

Every command prints one verdict line first, for example `PINNED <path> <sha>`, `WOULD LAND`, `WOULD REFUSE: <why>`, `APPROVED <id>`, `LANDED <path> <sha_after>`, `ROLLED BACK <path> <sha_after>`, `RECOVERED <path> <sha_after>`, `VERIFIED <n> rows` or `REFUSED: <why>`, then any detail.

Exit codes: `0` an act was done, `2` a refusal, `3` a fault.

A normal run:

```
landlock rehearse /srv/app/billing/rates.py new_rates.py
landlock approve  /srv/app/billing/rates.py new_rates.py
landlock land     /srv/app/billing/rates.py new_rates.py --approval new_rates.py.approval.json
landlock verify
```

## One lock per target

While a landing, a rollback or a recovery is running, landlock keeps one lock file beside the target, named `.landlock_lock_<name>`, and removes it when the act ends. If a lock is already standing, the act refuses and says how old the lock is, so two acts never work on one file at once. After a crash a lock can be left behind; once it is older than the test time limit plus a minute it is called stale, but it still refuses. A person looks, makes sure nothing is running, and removes it by hand.

## What a rehearsal sees

The candidate is shown at the live file's own path inside the sandbox, so imports and paths in your tests that use the file's real location see the candidate, not the old file. Nothing is copied: the target's folder is shown read-only at its own path, and only the candidate's bytes, kept in a scratch file with the live file's mode, are laid over the live file. A big folder rehearses as fast as a small one, and a file beside the target that you cannot read does no harm. Your tests may write to the live path (the write goes to the scratch file and is thrown away), to the folder named by `TMPDIR`, and to the throwaway home folder (an empty memory folder, gone after the run); any other write is refused by the kernel as a read-only file system. The rest of the machine is read-only. A target that is a symbolic link is refused, as a landing refuses one.

The sandbox also hides your home folder. Tools that are installed only under your home, such as a pytest installed with `pip install --user`, are not seen unless you show them again: install the test tool system-wide, put its full path in the test command, or list its folder in `walls.rehearse_ro_dirs`.

`walls.rehearse_ro_dirs` lists folders a rehearsal shows read-only at their own paths, never copied. They may lie anywhere on the machine, outside every root, because nothing can be written through them; that includes folders inside your hidden home, such as a per-user package folder or a link to a data folder. A link inside your hidden home is shown at the path you wrote, so code that reaches a folder through the link finds it; the folder the link points to is not shown at its own path unless you list it too. A link that the sandbox can already see (outside your home, or inside another listed folder or the target's folder) stays a link, and the folder it points to is shown so the link leads somewhere. Every entry must be an absolute path to an existing folder, written without `..`, and a rehearsal refuses one that is not, naming it. Your home folder itself is never listed whole (a rehearsal refuses it, and refuses a link that would show it through another path); list the entries of it your tests need. An entry whose path, and the path its links lead to, both lie at or inside the target's folder is skipped, since that folder already shows it, and a repeated entry is shown once. The secret and receipts files stay masked by an empty file wherever the sandbox shows them, a listed folder and a link to it included.

`walls.rehearse_extra_dirs`, the older list of folders inside a root, still works; since version 0.1.1 its folders are shown read-only the same way instead of copied, so a test can no longer write into them.

Since version 0.1.2 one more folder is writable: when the shared record-lock folder `/tmp/bastion_record_locks` stands on the machine, the sandbox shows an empty memory folder at that path (`landlock.rehearse.RECORD_LOCK_FOLDER`), so a test whose code locks a record there can make its lock. The lock is thrown away with the run and the machine's own folder is never written. When the folder does not stand on the machine, nothing is shown there and the path stays read-only, as before.

The candidate is shown at the target's real path and at every other path a listed folder gives it: if a listed folder is a link that leads into the target's folder, the target read, run or imported through that link is the candidate too.

## Receipts

Each act appends one JSON line to the receipts file: time, request id, act, path, sha before, sha after, verdict, why, the old copy's path and the approval id. `landlock verify` walks the file and refuses on a gap, meaning a land, rollback or recover whose sha-before is not the sha-after of the previous one for that path.

## Policy hooks

`landlock.policy` runs your own checks. In the library, `rehearse(...)` and `land(...)` each take an optional `policies` list and run it just before they act (a rehearsal and a landing each send their own event). A check is a function that takes an event dictionary and returns `(allow, why)`; the first `(False, why)` refuses with that why. The command line installs none, so policies are a library feature: call the functions from your own program to use them. Nothing is installed by default.

## Where the dependents' tests run

Rehearsal tests run inside the sandbox. The dependents' tests that run after a landing do not: they run unsandboxed, in the live folders, with the calling process's environment, under the time limit. Write those test commands as you would any command you run yourself.

## Tests

```
python3 -m pytest -q
```

To run them the way a stranger's machine would, with an empty home, the folder read-only and no network:

```
bash tools/clean_machine.sh
```

The exit code is pytest's. The script refuses with exit 2 if bubblewrap is missing. The GitHub workflow in `.github/workflows/tests.yml` runs the same suite on every push.

## License

Apache-2.0. See `LICENSE`.
