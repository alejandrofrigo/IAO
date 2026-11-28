# IAO candidate execution sandbox

The static evolution evaluator never executes candidate code. Functional
qualification is an explicit second step using tools/iao_candidate_sandbox.py.
It requires Docker and a prebuilt dependency image:

    docker build -f Dockerfile.candidate-sandbox -t iao-candidate-sandbox:local .
    python tools/iao_candidate_sandbox.py <proposal-id>

The runner exports the committed baseline with git archive, creates a
separate candidate workspace, overlays only the manifest-listed files that
passed static integrity checks, and runs the existing test suite twice: once
against baseline and once against candidate. Each suite runs in its own Docker
container with network disabled, read-only root filesystem, read-only workspace
mount, non-root UID, dropped Linux capabilities, no-new-privileges, bounded
memory/CPU/PIDs/file descriptors, and a small no-exec temporary filesystem.

The baseline must pass before a candidate can receive
FUNCTIONAL_TESTS_PASSED. Candidate failures, errors, or increased skipped
tests block that result. Missing Docker/image, workspace preparation errors,
or timeouts fail closed. The runner does not build images automatically and
does not contact a registry; image construction is a separate operator step.
Dependency installation happens at image-build time, not while candidate code
is running.

A functional pass is still not a security audit, approval for staging, merge,
or deployment. The runner returns promotion_eligible=false unconditionally.
The Docker boundary reduces exposure but does not prove resistance to kernel,
container-runtime, or Docker-daemon vulnerabilities. Never mount secrets,
the Docker socket, host home directories, production state, or writable host
paths into the candidate container.

The sandbox image and execution path have not been qualified by CI until the
dedicated build and test jobs complete successfully. Global/persistent network
connectivity is intentionally absent from candidate execution; it is not a
network-capable production sandbox.