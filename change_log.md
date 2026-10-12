# Change Log

## Unreleased

* Reject unsupported and empty validation profiles with an actionable configuration error and nonzero exit in both validate and dogfood. Do not create fresh evidence or continue proposing on that failure.
* Load the authority policy beside the resolved executable, including symlinked installations and source builds. Preserve the legacy sidecar filename without allowing caller working directory policies to shadow an installation.
* Add public command regressions for validation failure, preserved prior evidence, installed sidecar selection, executable symlinks, and missing installed policy.
