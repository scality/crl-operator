FROM mcr.microsoft.com/devcontainers/go:2.1-trixie@sha256:c249440b024e82a569726ab41e60400237665d1f259fb575fd707b04b1b44e55

USER vscode

# renovate: datasource=github-releases depName=operator-framework/operator-sdk extractVersion=^v(?<version>.*)$
ARG OPERATOR_SDK_VERSION=1.41.1

RUN curl -sSfLO https://github.com/operator-framework/operator-sdk/releases/download/v${OPERATOR_SDK_VERSION}/operator-sdk_linux_amd64 && \
    chmod +x operator-sdk_linux_amd64 && \
    sudo mv operator-sdk_linux_amd64 /usr/local/bin/operator-sdk

# renovate: datasource=github-releases depName=golangci/golangci-lint extractVersion=^v(?<version>.*)$
ARG GOLANGCI_VERSION=2.5.0

RUN curl -sSfL  https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sudo sh -s -- v${GOLANGCI_VERSION}

# renovate: datasource=github-releases depName=kubernetes-sigs/kind extractVersion=^v(?<version>.*)$
ARG KIND_VERSION=0.30.0

RUN curl -sSfLO https://kind.sigs.k8s.io/dl/v${KIND_VERSION}/kind-linux-amd64 && \
    chmod +x kind-linux-amd64 && \
    sudo mv kind-linux-amd64 /usr/local/bin/kind

# renovate: datasource=github-releases depName=kubernetes/kubernetes extractVersion=^v(?<version>.*)$
ARG KUBECTL_VERSION=1.36.1

RUN curl -sSfLO https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl && \
    chmod +x kubectl && \
    sudo mv kubectl /usr/local/bin/kubectl
