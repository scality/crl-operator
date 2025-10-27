FROM mcr.microsoft.com/devcontainers/go:1.25-trixie

USER vscode

ARG OPERATOR_SDK_VERSION=1.41.1

RUN curl -sSfLO https://github.com/operator-framework/operator-sdk/releases/download/v${OPERATOR_SDK_VERSION}/operator-sdk_linux_amd64 && \
    chmod +x operator-sdk_linux_amd64 && \
    sudo mv operator-sdk_linux_amd64 /usr/local/bin/operator-sdk

ARG GOLANGCI_VERSION=2.5.0

RUN curl -sSfL  https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sudo sh -s -- v${GOLANGCI_VERSION}
