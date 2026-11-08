# landlock

landlock changes one file on a machine safely. It remembers the file's exact bytes, tries the change in a sandbox away from the real file, wants a signed approval that matches those exact bytes, swaps the file in a single move while keeping the old copy, runs the tests that depend on it, and puts the old copy back by itself if any of them fail. Every step leaves one line in an append-only receipt file.

It is plain Python 3.12 with no third-party packages. Repository: `BastionLaboratories/landlock`. License: Apache-2.0.

## The four parts

1. **Pin.** `pin` records a file's sha256, size and modification time. Every later step takes a pin, never a bare path, and refuses if the file's bytes have moved since.
2. **Rehearse.** The candidate file is placed in a scratch copy of the target's folder and the tests run there, inside a bubblewrap sandbox: the real filesystem read-only, the scratch folder writable, a throwaway home, no network, a time limit. The answer is `WOULD LAND` or `WOULD REFUSE`, with the test output. The real file is never written, and a test command that names the real file refuses before anything runs.
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
```

- `roots`: the folders files may be landed into. A path outside them refuses.
- `receipts` and `secret`: must be outside every root.
- `tests`: the command that tests a file; `default` for all, `by_path` for particular files.
- `dependents`: for a file, the other files whose tests run after it lands.
- `walls`: the test time limit in seconds, a machine load limit, how long an approval lives, and `rehearse_extra_dirs`, the other folders a rehearsal's tests need copied in.

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

The candidate is shown at the live file's own path inside the sandbox, so imports and paths in your tests that use the file's real location see the candidate, not the old file. The rest of the machine is read-only. The sandbox gets a copy of the target's whole folder (siblings included). If a test needs another folder, list it in `walls.rehearse_extra_dirs` (absolute paths inside a root); each is copied and shown the same way.

The sandbox also hides your home folder. Tools that are installed only under your home, such as a pytest installed with `pip install --user`, are not seen. Install the test tool system-wide, or put its full path in the test command in the config.

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
