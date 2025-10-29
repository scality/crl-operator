/*
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
*/

package controller

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	crloperatorv1alpha1 "github.com/scality/crl-operator/api/v1alpha1"
	"github.com/scality/crl-operator/internal"
)

const (
	// renewBefore is the duration before expiry when the CRL should be renewed.
	renewBefore = 1 * time.Hour
	// secretCRLKey is the key in the Secret data where the CRL is stored.
	secretCRLKey = "ca.crl"

	// Common labels
	labelManagedByName  = "app.kubernetes.io/managed-by"
	labelManagedByValue = "crl-operator"

	labelComponentName  = "app.kubernetes.io/component"
	labelComponentValue = "managed-crl"
	labelAppName        = "app.kubernetes.io/name"
	labelInstanceName   = "app.kubernetes.io/instance"

	labelVersionName = "app.kubernetes.io/version"
)

// ManagedCRLReconciler reconciles a ManagedCRL object
type ManagedCRLReconciler struct {
	client.Client
	Scheme               *runtime.Scheme
	CertManagerNamespace string
}

// +kubebuilder:rbac:groups=crl-operator.scality.com,resources=managedcrls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=crl-operator.scality.com,resources=managedcrls/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=crl-operator.scality.com,resources=managedcrls/finalizers,verbs=update

// +kubebuilder:rbac:groups=cert-manager.io,resources=issuers;clusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ManagedCRL object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
// nolint:gocyclo // It's the main reconciliation loop
func (r *ManagedCRLReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	logger.Info("reconcile started")

	instance := &crloperatorv1alpha1.ManagedCRL{}
	if err := r.Get(ctx, req.NamespacedName, instance); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Apply defaults
	instance.WithDefaults()

	needRenewal := false
	original := instance.DeepCopy()

	// Ensure we update the status in case of early return
	defer func() {
		if err := r.Status().Patch(ctx, instance, client.MergeFrom(original)); err != nil {
			logger.Error(err, "failed to update ManagedCRL status")
		}
	}()

	// Simple helper to handle errors and update status
	handleError := func(err error, reason, message string) (ctrl.Result, error) { // nolint:unparam // It's clearer
		instance.SetSecretNotReady(reason, message)
		logger.Error(err, message)
		return ctrl.Result{}, fmt.Errorf("%s: %w", message, err)
	}

	var nextCRLNumber int64
	if instance.Status.CRLNumber == 0 {
		// NOTE: We do not start from 1 to avoid potential conflicts when we delete and re-create the
		// exact same ManagedCRL resource.
		nextCRLNumber = time.Now().Unix()
		needRenewal = true
	} else {
		nextCRLNumber = instance.Status.CRLNumber + 1
	}

	revokedList, err := instance.Spec.GetRevokedListEntries()
	if err != nil {
		return handleError(
			err,
			"FailedToGetRevokedListEntries",
			"failed to get revoked list entries from spec",
		)
	}

	// Get the Secret containing the CA certificate and private key
	caSecret, err := r.getIssuerSecret(ctx, instance.Namespace, instance.Spec.IssuerRef)
	if err != nil {
		return handleError(
			err,
			"FailedToGetIssuerSecret",
			"failed to get issuer secret",
		)
	}
	if instance.Status.ObservedCASecretRef == nil ||
		caSecret.Name != instance.Status.ObservedCASecretRef.Name ||
		caSecret.Namespace != instance.Status.ObservedCASecretRef.Namespace {

		needRenewal = true
	}

	// Extract the CA certificate and private key from the Secret
	caCert, caKey, err := r.extractCACertAndKey(caSecret)
	if err != nil {
		return handleError(
			err,
			"FailedToExtractCACertAndKey",
			"failed to extract CA certificate and key from secret",
		)
	}

	// Generate the CRL
	crl, err := r.generateCRL(caCert, caKey, revokedList, instance.Spec.Duration.Duration, big.NewInt(nextCRLNumber))
	if err != nil {
		return handleError(
			err,
			"FailedToGenerateCRL",
			"failed to generate CRL",
		)
	}

	secret := instance.GetSecret()

	// Get the current CRL to check if it needs to be updated
	var currentCRL *x509.RevocationList

	// If we still don't need renewal, check the current CRL validity
	if !needRenewal {
		var isWrong bool
		currentCRL, isWrong, err = r.getCurrentCRL(ctx, secret.Namespace, secret.Name)
		if isWrong {
			needRenewal = true
			if err != nil {
				logger.Info("current CRL is invalid, will renew", "error", err)
			}
		} else if err != nil {
			return handleError(
				err,
				"FailedToGetCurrentCRL",
				"failed to get current CRL",
			)
		} else if r.crlNeedRenewal(currentCRL, revokedList, caCert, instance.Spec.Duration.Duration) {
			needRenewal = true
		}
	}
	if currentCRL == nil {
		needRenewal = true
	}

	// If we do not need renewal, keep the current CRL
	if !needRenewal {
		crl = currentCRL
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		err := r.stdMutate(secret, instance)
		if err != nil {
			return err
		}

		secret.Data = map[string][]byte{
			secretCRLKey: crl.Raw,
		}
		return nil
	})
	if err != nil {
		return handleError(
			err,
			"FailedToCreateOrUpdateCRLSecret",
			"failed to create or update Secret for CRL",
		)
	}
	if op != controllerutil.OperationResultNone {
		logger.Info("Secret for CRL reconciled", "operation", op)
	}

	// Update status
	instance.Status.CRLNumber = crl.Number.Int64()
	instance.Status.CRLValidUntil = metav1.Time{Time: crl.NextUpdate.UTC()}
	instance.Status.ObservedCASecretRef = &corev1.SecretReference{
		Name:      caSecret.Name,
		Namespace: caSecret.Namespace,
	}
	instance.Status.ObservedCASecretVersion = caSecret.ResourceVersion

	instance.SetSecretReady()

	// All good
	// We still have to requeue before expiry to renew the CRL
	requeueAfter := time.Until(crl.NextUpdate.Add(-renewBefore))
	logger.Info("reconcile completed successfully", "requeueAfter", requeueAfter.String())
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// getIssuerSecret retrieves the Secret containing the CA certificate and private key
func (r *ManagedCRLReconciler) getIssuerSecret(ctx context.Context, namespace string, issuerRef cmmetav1.IssuerReference) (*corev1.Secret, error) {
	var secretRef client.ObjectKey

	switch issuerRef.Kind {
	case "Issuer":
		issuer := &cmv1.Issuer{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: issuerRef.Name}, issuer); err != nil {
			return nil, err
		}
		if issuer.Spec.CA == nil {
			return nil, errors.New("issuer is not a CA issuer")
		}
		secretRef = client.ObjectKey{
			Name:      issuer.Spec.CA.SecretName,
			Namespace: namespace,
		}
	case "ClusterIssuer":
		issuer := &cmv1.ClusterIssuer{}
		if err := r.Get(ctx, client.ObjectKey{Name: issuerRef.Name}, issuer); err != nil {
			return nil, err
		}
		if issuer.Spec.CA == nil {
			return nil, errors.New("cluster issuer is not a CA issuer")
		}
		secretRef = client.ObjectKey{
			Name: issuer.Spec.CA.SecretName,
			// For ClusterIssuer, the secret is in the cert-manager namespace
			Namespace: r.CertManagerNamespace,
		}
	default:
		return nil, errors.New("unsupported issuer kind")
	}

	secret := &corev1.Secret{}
	if err := r.Get(ctx, secretRef, secret); err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", secretRef.Namespace, secretRef.Name, err)
	}

	return secret, nil
}

// extractCACertAndKey retrieves the CA certificate and private key from the given Secret
func (r *ManagedCRLReconciler) extractCACertAndKey(secret *corev1.Secret) (*x509.Certificate, crypto.Signer, error) {
	caCertPEM, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, nil, fmt.Errorf("secret %s/%s does not contain a certificate", secret.Namespace, secret.Name)
	}
	caKeyPEM, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return nil, nil, fmt.Errorf("secret %s/%s does not contain a private key", secret.Namespace, secret.Name)
	}

	certBlock, _ := pem.Decode(caCertPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	if !caCert.IsCA {
		return nil, nil, fmt.Errorf("the provided certificate is not a CA certificate")
	}

	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA private key PEM")
	}
	var caKey crypto.Signer
	if key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, nil, fmt.Errorf("CA private key is not a crypto.Signer")
		}
		caKey = signer
	} else if key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
		caKey = key
	} else if key, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
		caKey = key
	} else {
		return nil, nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	return caCert, caKey, nil
}

// generateCRL generates a CRL signed by the given CA certificate and private key
func (r *ManagedCRLReconciler) generateCRL(caCert *x509.Certificate, caKey crypto.Signer, revokedList []x509.RevocationListEntry, duration time.Duration, crlNumber *big.Int) (*x509.RevocationList, error) {
	now := time.Now().UTC()
	nextUpdate := now.Add(duration).UTC()

	crlTemplate := &x509.RevocationList{
		ThisUpdate:                now,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: revokedList,
		Number:                    crlNumber,
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL: %w", err)
	}
	return x509.ParseRevocationList(crlBytes)
}

// getCurrentCRL retrieves the current CRL from the Secret
func (r *ManagedCRLReconciler) getCurrentCRL(ctx context.Context, namespace, name string) (*x509.RevocationList, bool, error) {
	secret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, secret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("failed to get Secret %s/%s: %w", namespace, name, err)
	}

	crlBytes, ok := secret.Data[secretCRLKey]
	if !ok {
		return nil, true, fmt.Errorf("secret %s/%s does not contain a CRL", namespace, name)
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, true, fmt.Errorf("failed to parse CRL from Secret %s/%s: %w", namespace, name, err)
	}

	return crl, false, nil
}

// crlNeedRenewal check if the CRL needs to be renewed
func (r *ManagedCRLReconciler) crlNeedRenewal(currentCRL *x509.RevocationList, revokedList []x509.RevocationListEntry, caCert *x509.Certificate, duration time.Duration) bool {
	// Check if the CRL is about to expire or if duration is shorter than nextUpdate
	// (i.e. the duration has been reduced)
	if currentCRL.NextUpdate.Before(time.Now().Add(2*renewBefore)) || currentCRL.NextUpdate.After(time.Now().Add(duration)) {
		return true
	}

	// Check if the CRL is signed by the current CA
	err := currentCRL.CheckSignatureFrom(caCert)
	if err != nil {
		return true
	}

	// Check if the CRL contains all revoked certificates
	// NOTE: We manage the full list so we expect a match in the same order
	for i, revoked := range revokedList {
		if i >= len(currentCRL.RevokedCertificateEntries) {
			return true
		}
		currentRevoked := currentCRL.RevokedCertificateEntries[i]
		// NOTE: We do not compare revocation time since it default to now if not set
		if revoked.SerialNumber.Cmp(currentRevoked.SerialNumber) != 0 ||
			revoked.ReasonCode != currentRevoked.ReasonCode {

			return true
		}
	}

	// Current CRL is valid, no need to renew
	return false
}

// stdMutate applies the standard mutations to the managed resources
// (The one we manage with `CreateOrUpdate`)
func (r *ManagedCRLReconciler) stdMutate(obj metav1.Object, instance *crloperatorv1alpha1.ManagedCRL) error {
	labels := obj.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}
	// Add default labels
	labels[labelManagedByName] = labelManagedByValue
	labels[labelComponentName] = labelComponentValue
	labels[labelAppName] = obj.GetName()
	labels[labelInstanceName] = instance.Name
	labels[labelVersionName] = internal.Version

	obj.SetLabels(labels)

	err := controllerutil.SetControllerReference(instance, obj, r.Scheme)
	if err != nil {
		return fmt.Errorf("failed to set owner reference on Secret: %w", err)
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ManagedCRLReconciler) SetupWithManager(mgr ctrl.Manager) error {
	mapIssuerToCRL := func(ctx context.Context, obj client.Object) []ctrl.Request {
		logger := logf.FromContext(ctx)
		var indexKey string

		switch obj := obj.(type) {
		case *cmv1.Issuer:
			indexKey = fmt.Sprintf("Issuer/%s/%s", obj.Namespace, obj.Name)
		case *cmv1.ClusterIssuer:
			indexKey = fmt.Sprintf("ClusterIssuer/%s", obj.Name)
		case *corev1.Secret:
			indexKey = fmt.Sprintf("Secret/%s/%s", obj.Namespace, obj.Name)
		default:
			logger.Error(nil, "unknown type in mapIssuerToCRL: %T", obj)
			return nil
		}

		mcrlList := &crloperatorv1alpha1.ManagedCRLList{}
		err := r.List(ctx, mcrlList, client.MatchingFields{
			"IssuerRef": indexKey,
		})
		if err != nil {
			logger.Error(err, "failed to list ManagedCRLs", "IssuerRef", indexKey)
			return nil
		}

		requests := make([]ctrl.Request, 0, len(mcrlList.Items))
		for _, mcrl := range mcrlList.Items {
			requests = append(requests, ctrl.Request{
				NamespacedName: client.ObjectKey{
					Name:      mcrl.Name,
					Namespace: mcrl.Namespace,
				},
			})
		}

		if len(requests) > 0 {
			logger.Info(
				"Issuer/ClusterIssuer change detected, enqueueing ManagedCRLs",
				"IssuerRef", indexKey,
				"count", len(requests),
			)
		}
		return requests
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&crloperatorv1alpha1.ManagedCRL{}).
		Owns(&corev1.Secret{}).
		Watches(&cmv1.ClusterIssuer{}, handler.EnqueueRequestsFromMapFunc(mapIssuerToCRL)).
		Watches(&cmv1.Issuer{}, handler.EnqueueRequestsFromMapFunc(mapIssuerToCRL)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(mapIssuerToCRL)).
		Named("managedcrl").
		Complete(r)
}
