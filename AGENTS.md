## Runner policy — owner directive, 2026-10-26

All build, test, scan, packaging, and release jobs require compatible private
ephemeral JIT runners. Preserve native OS and architecture. Do not use hosted
runners or hosted fallbacks; missing private capacity is a provisioning blocker.
CodeQL is disabled organization-wide and must not be restored or rerouted unless
the owner explicitly reverses that directive.

Keep untrusted pull-request code isolated in a disposable environment without
secrets, with minimal permissions and restricted egress. Do not widen trusted
runner-group access to make untrusted code run. Preserve active builds and other
agents' work. Do not restart the broker while it owns running guests. Rerunning
an old run uses its original workflow revision.

The shared inventory governs private JIT jobs. Verify source routing, broker
policy, runner-group access, and live capacity before relying on a workflow.

Commit focused milestones and push them promptly to the repository's default
branch. Stage only task-owned changes, preserve unrelated work, and never
rewrite published history.

