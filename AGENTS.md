# Repository instructions

## GitHub Actions cost-control policy (mandatory)

- Do not create or enable automatically triggered GitHub Actions workflows. This includes `push`, `pull_request`, `pull_request_target`, `schedule`, `workflow_run`, `merge_group`, releases and other event-based or cron triggers.
- All existing and future GitHub Actions workflows must be manually invoked with `workflow_dispatch` only. A reusable workflow may additionally expose `workflow_call` if it is only called from manually invoked workflows.
- Never introduce GitHub-hosted CI checks, builds, deployments, scheduled automation or recurring jobs without explicit prior user authorization to change this policy.
- Keep automated test commands and existing test suites available for local execution or manual GitHub Actions dispatch. Do not delete tests or bypass test requirements; explicitly report checks that were not run.
- On workflow or tooling changes inspect `.github/workflows/` and ensure no automatic triggers have been introduced. This requirement also applies to feature branches and pull requests; do not copy older auto-triggering workflows forward.
