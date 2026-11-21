## Runner policy — owner directive, 2026-11-13

Use compatible GitHub-hosted runners by default for build, test, scan,
packaging and release jobs (owner directive, 2026-11-13). Preserve native OS and
architecture. Use private ephemeral JIT only when a job needs private network,
storage, hardware or tooling that hosted runners lack; missing private capacity
is not a blocker when a compatible hosted runner exists. Keep public
pull-request code secret-free with minimal permissions on disposable hosted
runners.
CodeQL is allowed (owner directive, 2026-11-21); the 2026-10-30 disable is
withdrawn.

Keep untrusted pull-request code isolated in a disposable environment without
secrets, with minimal permissions and restricted egress. Do not widen trusted
runner-group access to make untrusted code run. Preserve active builds and other
agents' work. Do not restart the broker while it owns running guests. Rerunning
an old run uses its original workflow revision.

For a job that genuinely needs private JIT, the shared inventory governs it;
verify source routing, broker policy, runner-group access and live capacity.

Commit focused milestones and push them promptly to the repository's default
branch. Stage only task-owned changes, preserve unrelated work, and never
rewrite published history.

