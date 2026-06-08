# crl-operator

This is a **Kubernetes operator written in Go** (built with Kubebuilder / Operator SDK and
controller-runtime). It manages Certificate Revocation Lists (CRLs) in a cluster based on
cert-manager `ClusterIssuer`/`Issuer` resources. It contains:

- A `ManagedCRL` Custom Resource Definition and its API types (`api/v1alpha1/`)
- A reconciler controller (`internal/controller/`)
- A validating admission webhook (`internal/webhook/v1alpha1/`)
- The operator entrypoint (`cmd/main.go`)
- Kustomize deployment manifests, RBAC, and CRDs (`config/`)
- Ginkgo/Gomega tests (`*_test.go`, `test/`)

Key dependencies: `sigs.k8s.io/controller-runtime`, `k8s.io/client-go`, `k8s.io/apimachinery`,
`github.com/cert-manager/cert-manager`. Linted with golangci-lint (`.golangci.yml`).
Expect Go source (`.go`), YAML manifests, a `Makefile`, and a `Dockerfile`.

