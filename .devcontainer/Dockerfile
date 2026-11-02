FROM mcr.microsoft.com/devcontainers/go:1.27-trixie@sha256:32aad7e9eefed4fe99987cc4efef2f9723bd57c556f171143ecf65e0ba855ff3

USER vscode

# renovate: datasource=github-releases depName=kubernetes-sigs/kubebuilder extractVersion=^v(?<version>.*)$
ARG KUBEBUILDER_VERSION=4.16.0

RUN curl -sSfLO https://github.com/kubernetes-sigs/kubebuilder/releases/download/v${KUBEBUILDER_VERSION}/kubebuilder_linux_amd64 && \
    chmod +x kubebuilder_linux_amd64 && \
    sudo mv kubebuilder_linux_amd64 /usr/local/bin/kubebuilder

# renovate: datasource=github-releases depName=golangci/golangci-lint extractVersion=^v(?<version>.*)$
ARG GOLANGCI_VERSION=2.15.0

RUN curl -sSfL  https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sudo sh -s -- v${GOLANGCI_VERSION}

# renovate: datasource=github-releases depName=kubernetes-sigs/kind extractVersion=^v(?<version>.*)$
ARG KIND_VERSION=0.33.0

RUN curl -sSfLO https://kind.sigs.k8s.io/dl/v${KIND_VERSION}/kind-linux-amd64 && \
    chmod +x kind-linux-amd64 && \
    sudo mv kind-linux-amd64 /usr/local/bin/kind

# renovate: datasource=github-releases depName=kubernetes/kubernetes extractVersion=^v(?<version>.*)$
ARG KUBECTL_VERSION=1.37.1

RUN curl -sSfLO https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl && \
    chmod +x kubectl && \
    sudo mv kubectl /usr/local/bin/kubectl
