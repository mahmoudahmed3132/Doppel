# Upload and first release: owner steps

The private repository `mahmoudahmed3132/Doppel` already exists, and every
merge branch is pushed to it (the cloud session pushed them, Q66 approval).
The task plan's "create an empty repository, add origin, push main" steps are
therefore done. What remains:

1. **Review and merge** the merge branches into `main`, in this order (each
   builds on the previous one). `docs/merge/REPORT.md` §2 lists them.
   Either merge the last branch (`docs/merge-report`, which contains all the
   others) in one PR, or merge them one by one. A **squash merge** keeps the
   ~35 MB of sensor binaries committed by mistake in `ad9b896` (removed in
   `227707d`) out of `main`'s history; a merge commit keeps the per-step
   history. `PROVENANCE.md` records every import either way.
2. **Before the first tag**, in `mahmoudahmed3132/Doppel` Settings:
   - Rulesets → tags `hub/v*`, `cli/v*`, `sensor/**`: block update and
     deletion; restrict creation to maintainers (`docs/operations.md` §9).
   - Actions variable `RELEASES_APP_CLIENT_ID` and secret
     `RELEASES_APP_PRIVATE_KEY` for the releases GitHub App, and install that
     App on `truesignal-releases` (`docs/operations.md` §9.1, §9.2 step 2).
   - Dependabot: enabled by `.github/dependabot.yml`; 17 Dependabot PRs
     opened when `main` was first pushed. Review them after the merge.
   - Code scanning stays off; CodeQL is gated in the job (Q65).
3. **Confirm CI is green on GitHub** for `main` (CI, CodeQL, SIEM rules).
4. **Republish** per `docs/operations.md` §9.2: sensors at `1.0.1` (six now,
   with `token-receiver` at `1.0.0` as its first release), a new CLI release
   (the `doppel` binary), then Hub `3.0.0-rc.2` or `3.0.0`. You push the
   tags; nothing was tagged or released by the merge session.
5. **Delete the merge workspace sources**: the cloud session's
   `doppel-merge/sources/` is deleted at the end of the merge. Never copy,
   zip or upload it with Doppel.
