FROM mcr.microsoft.com/devcontainers/go:1.25-trixie@sha256:036dd67659b3df71971185a1737e4a17f87b4bdeb0854245300a7206935015f8

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
