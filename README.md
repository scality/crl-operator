[![Post Merge](https://github.com/scality/crl-operator/actions/workflows/post-merge.yaml/badge.svg)](https://github.com/scality/crl-operator/actions/workflows/post-merge.yaml)

# crl-operator

A Kubernetes operator for managing Certificate Revocation Lists (CRLs) in your cluster
based on ClusterIssuer/Issuer resources from cert-manager.

## Description

The CRL Operator provides automated management of Certificate Revocation Lists within
Kubernetes environments. It enables cluster administrators to deploy, update, and maintain
CRLs as custom resources.

The CRL can also be exposed in a Pod via an NGINX server, allowing clients to retrieve
the CRL using HTTP requests internally using a Kubernetes Service or externally via
an Ingress resource (that can be managed by the operator as well).

The operator handles CRL lifecycle management, periodic updates, and patch of ClusterIssuer/Issuer
resources from cert-manager to include CRL distribution points.

## Getting Started

### Prerequisites
- go version v1.25.0+
- docker
- kubectl
- Access to a Kubernetes v1.32+ cluster

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/crl-operator:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don't work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/crl-operator:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure to update the sample CRs to fit your needs before applying them to the cluster.

### To Uninstall

**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Contributing

See [contributing](CONTRIBUTING.md) for details.

## License

Copyright 2025 Scality.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

