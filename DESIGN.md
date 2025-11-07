# Design

## Goal

The goal of the CRL Operator is to provide automated management of
Certificate Revocation Lists (CRLs) within Kubernetes environments. It aims to simplify the
deployment, updating, and maintenance of CRLs as custom resources as well as
patching ClusterIssuer/Issuer resources from cert-manager to include CRL distribution points.

## Technical Details

The CRL Operator is built using the Operator SDK and follows the
Kubernetes Operator pattern. It defines a Custom Resource Definition (CRD) for
ManagedCRL resources, which represent individual CRLs to be managed by the operator. The operator
watches for changes to ManagedCRL resources and performs the necessary actions to
ensure that the CRLs are correctly deployed and updated within the cluster.
