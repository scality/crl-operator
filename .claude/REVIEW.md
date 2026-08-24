# Review criteria

Read by the `/review-pr` skill (Scality agent hub) and by anyone reviewing by hand.
Flag problems only — see "What not to flag" at the end.

## What this repo is

`crl-operator` is a kubebuilder operator that maintains Certificate Revocation Lists
for cert-manager `Issuer`/`ClusterIssuer` resources, driven by the `ManagedCRL`
custom resource (`api/v1alpha1`). The reconciler in `internal/controller` regenerates
a CRL and reschedules itself with `RequeueAfter`. Tests are Ginkgo: integration under
`test/integration` (envtest), plus `test/e2e`. Design notes: `DESIGN.md`.

## Criteria

| Area | What to check |
|------|---------------|
| Reconcile idempotency | Reconciling the same `ManagedCRL` twice must not produce a new CRL, a new Secret revision or a status flap. Regeneration happens only when the revocation set, the issuer or the validity window actually changed. |
| Requeue scheduling | `RequeueAfter` drives CRL freshness: it must be derived from the CRL's own validity (renew before `nextUpdate`), bounded, never zero or negative, and never a hot loop on a permanent error. Watch for a transient error path that returns both an error and a `RequeueAfter`. |
| CRL correctness | `thisUpdate`/`nextUpdate` consistent and in UTC; the revoked-serial set preserved across regenerations (no silent truncation); signature produced with the issuer's CA key and algorithm; DER encoding unchanged for consumers. |
| cert-manager integration | `Issuer` versus `ClusterIssuer` resolution respects namespace scoping; a missing, unready or rotated issuer is surfaced in status instead of crashing; CA Secret references read with least privilege. |
| Key material handling | CA private keys are read, never logged, never copied outside the Secret they came from, never written to a volume or a temp file without cleanup. Flag any new log line that could carry key or DER bytes. |
| Status conventions | Status written through the status subresource only, once per reconcile, with standard `metav1.Condition` fields (type/status/reason/message/lastTransitionTime). Condition types are a consumed contract — renames are breaking. |
| RBAC scoping | `+kubebuilder:rbac` markers grant exactly the verbs the code uses on the resources it touches; `config/rbac` regenerated and committed. |
| CRD compatibility | `v1alpha1` changes stay additive (no removed field, no newly required field, no narrowed validation) unless the PR explains how existing objects migrate; kubebuilder validation markers preferred over Go-only checks. |
| Generated code in sync | After editing `api/` types or markers, `zz_generated.deepcopy.go` and `config/crd` are regenerated (`make generate manifests`) and committed in the same PR. |
| Error handling & context | Wrap with `fmt.Errorf("...: %w", err)`; return errors so controller-runtime can requeue instead of swallowing them; thread the reconcile `ctx` through every client call and respect cancellation. |
| Tests | Controller behaviour covered by the envtest integration suite, user-visible behaviour by e2e. `Eventually` blocks need bounded timeouts and a real assertion — no sleep-and-hope. New logic paths have a test. |
| Manager manifests | Resource requests/limits set, security context minimal, metrics endpoint behind authn/authz, network policy still consistent with what the controller talks to. |
| Docs | Behaviour, CRD or flag changes update `README.md`; a design decision updates `DESIGN.md`; conventions update `CONTRIBUTING.md`. |
| Breaking changes | Call out changes to the CRD schema, condition types, the produced Secret's name or layout, flags and env vars. |

## What not to flag

- Anything the linters already own: `golangci-lint` (`.golangci.yml`), `gofmt`,
  `goimports` — formatting, import order, unused variables, naming.
- Generated files (`zz_generated.*`, `config/crd`) except when they are stale with
  respect to the sources changed in the same PR.
- Markdown or comment wording preferences.
- Refactors unrelated to the PR's purpose.
