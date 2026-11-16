#!/bin/sh
# SAST with Semgrep CE (ADR 0012). One invocation for CI and for `pnpm sast`, so a local run is the
# CI run. The image digest lives only in .github/workflows/ci.yml (job `sast`, env SEMGREP_IMAGE);
# CI hands it over as the environment variable of the same name.
#
#   sh scripts/sast.sh        scan the repository; any finding fails (exit 1)
#   sh scripts/sast.sh test   check the local rules in .semgrep/ against their fixtures
#
# Without `semgrep` on PATH (CI and developer machines) the script re-runs itself inside the pinned
# image with Docker, mounting the repository read-only. Inside that image `semgrep` exists.
set -eu

cd "$(dirname "$0")/.."

if ! command -v semgrep >/dev/null 2>&1; then
  image=${SEMGREP_IMAGE:-$(sed -n 's|^ *SEMGREP_IMAGE: *\(semgrep/semgrep@sha256:[0-9a-f]\{64\}\).*|\1|p' .github/workflows/ci.yml)}
  case "$image" in
    semgrep/semgrep@sha256:*) ;;
    *)
      echo "sast: SEMGREP_IMAGE must be semgrep/semgrep@sha256:<digest> (see .github/workflows/ci.yml)" >&2
      exit 2
      ;;
  esac
  # Same uid as the checkout owner (Git refuses a repository owned by someone else); HOME must be writable.
  exec docker run --rm --user "$(id -u):$(id -g)" --env HOME=/tmp \
    --volume "$PWD:/src:ro" --workdir /src "$image" sh scripts/sast.sh "$@"
fi

if [ "${1:-}" = "test" ]; then
  # From inside .semgrep/ so the root .semgrepignore (which hides the fixtures from the scan) is not applied.
  cd .semgrep
  exec semgrep --test --metrics=off --disable-version-check .
fi

# Registry packs: TypeScript/JavaScript, Node.js, Next.js, OWASP Top 10 and GitHub Actions workflows.
# Secrets are gitleaks' job. `--metrics=off`: nothing is sent to Semgrep. `--error`: any finding fails.
exec semgrep scan \
  --config p/typescript \
  --config p/javascript \
  --config p/nodejs \
  --config p/nextjs \
  --config p/owasp-top-ten \
  --config p/github-actions \
  --config .semgrep/rules.yml \
  --metrics=off \
  --disable-version-check \
  --error
