---
name: review-pr
description: Review a PR on crl-operator (a Go Kubernetes operator managing Certificate Revocation Lists via cert-manager)
argument-hint: <pr-number-or-url>
disable-model-invocation: true
allowed-tools: Read, Bash(gh repo view *), Bash(gh pr view *), Bash(gh pr diff *), Bash(gh pr comment *), Bash(gh api *), Bash(git diff *), Bash(git log *), Bash(git show *)
---

# Review GitHub PR

You are an expert code reviewer. Review this PR: $ARGUMENTS

## Determine PR target

Parse `$ARGUMENTS` to extract the repo and PR number:

- If arguments contain `REPO:` and `PR_NUMBER:` (CI mode), use those values directly.
- If the argument is a GitHub URL (starts with `https://github.com/`), extract `owner/repo` and the PR number from it.
- If the argument is just a number, use the current repo from `gh repo view --json nameWithOwner -q .nameWithOwner`.

## Output mode

- **CI mode** (arguments contain `REPO:` and `PR_NUMBER:`): post inline comments and summary to GitHub.
- **Local mode** (all other cases): output the review as text directly. Do NOT post anything to GitHub.

## Steps

1. **Fetch PR details:**

```bash
gh pr view <number> --repo <owner/repo> --json title,body,headRefOid,author,files
gh pr diff <number> --repo <owner/repo>
```

2. **Read changed files** to understand the full context around each change (not just the diff hunks).

3. **Analyze the changes** against these criteria:

| Area | What to check |
|------|---------------|
| Reconciler idempotency | Reconcile must be safe to run repeatedly; no assumptions about being called once. Derive desired state from spec, converge, and avoid side effects that don't tolerate retries. |
| Requeue & error handling | Return errors (not swallowed) so the queue retries with backoff; use `RequeueAfter` for periodic CRL refresh rather than blocking. Don't requeue on terminal/validation errors that will never succeed. |
| Error wrapping | Wrap errors with `fmt.Errorf("...: %w", err)`, not `%v`, so callers can `errors.Is`/`errors.As`. |
| Status subresource | Update `.status` via the status writer; set meaningful conditions/observedGeneration. Don't mutate spec from the controller. |
| RBAC scoping | New API access needs matching `+kubebuilder:rbac` markers and regenerated `config/rbac`. Keep permissions least-privilege; flag cluster-wide grants that could be namespaced. |
| cert-manager integration | Patches to `ClusterIssuer`/`Issuer` must be additive and not clobber unrelated fields; use server-side apply or patch, not full replace. Handle missing/!ready issuers gracefully. |
| Context propagation | Pass `ctx` through call chains; respect cancellation; don't use `context.Background()` inside reconcile paths. |
| Goroutine leaks | Goroutines must have clear exit conditions tied to the manager's context; prefer `errgroup` / runnables registered with the manager. |
| API/CRD changes | Changes to `api/v1alpha1` types require regenerated deepcopy + CRD manifests (`make generate manifests`). Flag breaking field changes to a served CRD version. |
| Webhook validation | Validating webhook logic must reject invalid `ManagedCRL` specs clearly and stay consistent with CRD/OpenAPI validation. Watch for nil derefs on optional fields. |
| Interface compliance | Implementations should assert interface satisfaction at compile time (e.g. `var _ reconcile.Reconciler = ...`). |
| Security | No secrets/keys logged or hardcoded; CRL/certificate material handled safely; generated NGINX/Service/Ingress resources don't over-expose. |
| Breaking changes | Anything changing the CRD schema, public API types, or operator flags/config defaults. |

4. **Deliver your review:**

### If CI mode: post to GitHub

#### Part A: Inline file comments

For each issue, post a comment on the exact file and line. Keep comments short (1-3 sentences), end with `— Claude Code`. Use line numbers from the **new version** of the file.

**Without suggestion block** — single-line command, `<br>` for line breaks:
```bash
gh api -X POST -H "Accept: application/vnd.github+json" "repos/<owner/repo>/pulls/<number>/comments" -f body="Issue description.<br><br>— Claude Code" -f path="file" -F line=42 -f side="RIGHT" -f commit_id="<headRefOid>"
```

**With suggestion block** — use a heredoc (`-F body=@-`) so code renders correctly:
```bash
gh api -X POST -H "Accept: application/vnd.github+json" "repos/<owner/repo>/pulls/<number>/comments" -F body=@- -f path="file" -F line=42 -f side="RIGHT" -f commit_id="<headRefOid>" <<'COMMENT_BODY'
Issue description.

```suggestion
first line of suggested code
second line of suggested code
```

— Claude Code
COMMENT_BODY
```

Only suggest when you can show the exact replacement. For architectural or design issues, just describe the problem.

#### Part B: Summary comment

Single-line command, `<br>` for line breaks. No markdown headings — they render as giant bold text. Flat bullet list only:

```bash
gh pr comment <number> --repo <owner/repo> --body "- file:line — issue<br>- file:line — issue<br><br>Review by Claude Code"
```

If no issues: just say "LGTM". End with: `Review by Claude Code`

### If local mode: output the review as text

Do NOT post anything to GitHub. Instead, output the review directly as text.

For each issue found, output:

```
**<file_path>:<line_number>** — <what's wrong and how to fix it>
```

When the fix is a concrete line change, include a fenced code block showing the suggested replacement.

At the end, output a summary section listing all issues. If no issues: just say "LGTM".

End with: `Review by Claude Code`

## What NOT to do

- Do not comment on markdown formatting preferences
- Do not suggest refactors unrelated to the PR's purpose
- Do not praise code — only flag problems or stay silent
- If no issues are found, post only a summary saying "LGTM"
- Do not flag style issues already covered by the project's linter (golangci-lint)
