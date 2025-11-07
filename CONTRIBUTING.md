# Contributing to the Project

This document contains and defines the rules that have to be followed by any
contributor to the project, in order for any change to be merged into the
stable branches.

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## Workflow Guidelines

### Committing Guidelines

No restrictions are placed at this time on individual commits passing in the
CI and/or maintaining full functionality of the repository.

Commit messages should:

* have a short (< 50 characters) summary as title
* contain more explanations, if necessary, in the body
* contain a reference to the issue being tackled in the body

A commit message should *not* contain a reference to the issue in the title.

### Pull Request Guidelines

Pull requests should contain in their body a reference to the GitHub issue 
being targeted by the changeset introduced.

### Signing your work

In order to contribute to the project, you must sign your work. By signing your
work, you certify to the statements set out in the Developer Certificate of
Origin ([developercertificate.org](https://developercertificate.org/))

Signing your work is easy. Just add the following line at the end of each of
your commit messages. You must use your real name in your sign-off.

```
Signed-off-by: Jane Doe <jane.doe@email.com>
```

If your `user.name` and `user.email` are set in your git configs, you can sign
each commit automatically by using the `git commit -s` command.

## Reporting an issue

This project uses Github issues to manage the issues.

Before creating an issue:

1. upgrade the operator to the latest supported release version, and check whether your bug is still present,
2. ensure the operator version is supported by the PowerDNS version you are using,
3. have a look in the opened issues if your problem is already known/tracked, and possibly contribute to the thread with your own information.

If none of the above was met, open an issue directly in Github, select the appropriate issue template and fill-in each section when applicable.

## Development Setup

### Prerequisites

- go version v1.25.0+
- docker
- kubectl
- make
- operator-sdk
- Docker (for building)
- Kind (for running e2e tests)

We recommend using the [devcontainer](https://code.visualstudio.com/docs/devcontainers/containers)
provided here that come with all necessary tools pre-installed.

## Testing & Linting

Run linting:
```sh
make lint
```

Run tests:
```sh
make test
```

Run e2e tests:
```sh
make test-e2e
```

**NOTE:** Run `make help` for more information on all potential `make` targets
