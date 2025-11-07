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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	crloperatorv1alpha1 "github.com/scality/crl-operator/api/v1alpha1"
	"github.com/scality/crl-operator/internal"
	"github.com/scality/crl-operator/internal/utils"
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

	// server configuration
	nginxConfig = `
server {
  listen 8080;
  server_name _;

  location = /ca.crl {
    root /srv;

    types { }
    default_type application/pkix-crl;
  }

	location / {
		return 404;
	}
}`
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

// +kubebuilder:rbac:groups=cert-manager.io,resources=issuers;clusterissuers,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups="",resources=configmaps;secrets;services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete
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
	if err := instance.Validate(); err != nil {
		return ctrl.Result{}, fmt.Errorf("validation failed: %w", err)
	}

	needRenewal := false
	original := instance.DeepCopy()

	// Ensure we update the status in case of early return
	defer func() {
		if err := r.Status().Patch(ctx, instance, client.MergeFrom(original)); err != nil {
			logger.Error(err, "failed to update ManagedCRL status")
		}
	}()

	// Simple helper to handle errors and update status
	// Create variable to track what need to be set unavailable
	secretReady := false
	podReady := false
	ingressReady := false
	handleError := func(err error, reason, message string) (ctrl.Result, error) { // nolint:unparam // It's clearer
		nextReason := reason
		nextMessage := message

		if !secretReady {
			instance.SetSecretNotReady(nextReason, nextMessage)
			nextReason = "SecretNotReady"
			nextMessage = "secret is not ready"
		}
		if instance.IsExposed() && !podReady {
			instance.SetPodNotExposed(nextReason, nextMessage)
			nextReason = "PodNotExposed"
			nextMessage = "pod is not exposed"
		}
		if instance.IsIngressManaged() && !ingressReady {
			instance.SetIngressNotExposed(nextReason, nextMessage)
			nextReason = "IngressNotExposed"
			nextMessage = "ingress is not exposed"
		}
		if instance.NeedsIssuerConfiguration() {
			instance.SetIssuerNotConfigured(nextReason, nextMessage)
		}

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
	issuer, err := r.getIssuer(ctx, instance.Namespace, instance.Spec.IssuerRef)
	if err != nil {
		return handleError(
			err,
			"FailedToGetIssuer",
			"failed to get issuer",
		)
	}
	caSecret, err := r.getIssuerSecret(ctx, instance.Namespace, issuer)
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
	secretReady = true

	// Handle expose if specified
	if instance.IsExposed() {
		// Handle server Configuration
		cm := instance.GetConfigMap()
		op, err = controllerutil.CreateOrUpdate(ctx, r.Client, cm, func() error {
			err := r.stdMutate(cm, instance)
			if err != nil {
				return err
			}

			cm.Data = map[string]string{
				"default.conf": nginxConfig,
			}
			return nil
		})
		if err != nil {
			return handleError(
				err,
				"FailedToCreateOrUpdateServerConfigMap",
				"failed to create or update ConfigMap for the server",
			)
		}
		if op != controllerutil.OperationResultNone {
			logger.Info("ConfigMap for the server reconciled", "operation", op)
		}

		// Handle Deployment for the server
		selector := map[string]string{
			labelAppName:      instance.Name,
			labelInstanceName: instance.Name,
		}
		deploy := instance.GetDeployment()
		op, err = controllerutil.CreateOrUpdate(ctx, r.Client, deploy, func() error {
			err := r.stdMutate(deploy, instance)
			if err != nil {
				return err
			}

			// Add selector labels
			utils.UpdateLabels(&deploy.Spec.Template.ObjectMeta, selector)
			deploy.Spec.Selector = &metav1.LabelSelector{
				MatchLabels: selector,
			}

			// Add replicas
			deploy.Spec.Replicas = ptr.To[int32](2)

			// Add NodeSelector and Tolerations and ImagePullSecrets
			deploy.Spec.Template.Spec.NodeSelector = instance.Spec.Expose.NodeSelector
			deploy.Spec.Template.Spec.Tolerations = instance.Spec.Expose.Tolerations
			deploy.Spec.Template.Spec.ImagePullSecrets = instance.Spec.Expose.Image.PullSecrets

			// Add volumes
			deploy.Spec.Template.Spec.Volumes = []corev1.Volume{
				{
					Name: "config",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: cm.GetName(),
							},
						},
					},
				}, {
					Name: "crl",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: secret.GetName(),
						},
					},
				},
			}

			// If we have more than 1 container we clean up the containers list
			if len(deploy.Spec.Template.Spec.Containers) != 1 {
				deploy.Spec.Template.Spec.Containers = []corev1.Container{{}}
			}
			container := &deploy.Spec.Template.Spec.Containers[0]

			// Handle container definition
			container.Name = "server"
			container.Image = instance.Spec.Expose.Image.GetImage()
			container.Ports = []corev1.ContainerPort{
				{
					Name:          "http",
					ContainerPort: 8080,
				},
			}
			container.VolumeMounts = []corev1.VolumeMount{
				{
					Name:      "config",
					MountPath: "/etc/nginx/conf.d/default.conf",
					SubPath:   "default.conf",
					ReadOnly:  true,
				}, {
					Name:      "crl",
					MountPath: "/srv/",
					ReadOnly:  true,
				},
			}

			return nil
		})
		if err != nil {
			return handleError(
				err,
				"FailedToCreateOrUpdateServerDeployment",
				"failed to create or update Deployment for the server",
			)
		}
		if op != controllerutil.OperationResultNone {
			logger.Info("Deployment for the server reconciled", "operation", op)
		}

		// Handle Service for the server
		svc := instance.GetService()
		op, err = controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
			err := r.stdMutate(svc, instance)
			if err != nil {
				return err
			}

			svc.Spec.Selector = selector
			svc.Spec.Ports = []corev1.ServicePort{
				{
					Name:       "http",
					Port:       80,
					TargetPort: intstr.FromInt(8080),
				},
			}
			svc.Spec.Type = corev1.ServiceTypeClusterIP

			return nil
		})
		if err != nil {
			return handleError(
				err,
				"FailedToCreateOrUpdateServerService",
				"failed to create or update Service for the server",
			)
		}
		if op != controllerutil.OperationResultNone {
			logger.Info("Service for the server reconciled", "operation", op)
		}

		// Check if the Deployment is ready
		if deploy.Status.ReadyReplicas != deploy.Status.Replicas || deploy.Status.ReadyReplicas == 0 {
			return handleError(
				errors.New("deployment not ready"),
				"ServerPodNotReady",
				"server pod is not ready",
			)
		}

		instance.SetPodExposed()
		podReady = true

		// Handle Ingress if enabled
		if instance.IsIngressManaged() {
			ingress := instance.GetIngress()
			op, err = controllerutil.CreateOrUpdate(ctx, r.Client, ingress, func() error {
				err := r.stdMutate(ingress, instance)
				if err != nil {
					return err
				}

				ingress.Spec.IngressClassName = instance.Spec.Expose.Ingress.ClassName

				ingressRule := &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{
						{
							Path:     "/ca.crl",
							PathType: ptr.To(networkingv1.PathTypePrefix),
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: fmt.Sprintf("%s-server", instance.Name),
									Port: networkingv1.ServiceBackendPort{
										Number: 80,
									},
								},
							},
						},
					},
				}

				ingress.Spec.Rules = []networkingv1.IngressRule{{}}
				if instance.Spec.Expose.Ingress.Hostname != nil {
					ingress.Spec.Rules[0].Host = *instance.Spec.Expose.Ingress.Hostname
				}
				ingress.Spec.Rules[0].HTTP = ingressRule

				// If we have some IPAddress let's add an entry without host
				// to support direct access
				if len(instance.Spec.Expose.Ingress.IPAddresses) > 0 {
					ingress.Spec.Rules = append(ingress.Spec.Rules, networkingv1.IngressRule{})
					ingress.Spec.Rules[1].HTTP = ingressRule
				}

				return nil
			})
			if err != nil {
				return handleError(
					err,
					"FailedToCreateOrUpdateServerIngress",
					"failed to create or update Ingress for the server",
				)
			}
			if op != controllerutil.OperationResultNone {
				logger.Info("Ingress for the server reconciled", "operation", op)
			}

			instance.SetIngressExposed()
			ingressReady = true
		}

		// Update the Issuer to add CRL Distribution points
		if instance.NeedsIssuerConfiguration() {
			var originalIssuer client.Object
			desiredDP := instance.GetCRLDistributionPoint()

			switch issuer := issuer.(type) {
			case *cmv1.Issuer:
				originalIssuer = issuer.DeepCopy()
				issuer.Spec.CA.CRLDistributionPoints = desiredDP
			case *cmv1.ClusterIssuer:
				originalIssuer = issuer.DeepCopy()
				issuer.Spec.CA.CRLDistributionPoints = desiredDP
			default:
				return handleError(
					errors.New("unsupported issuer kind for updating CRL Distribution Points"),
					"UnsupportedIssuerKind",
					"unsupported issuer kind for updating CRL Distribution Points",
				)
			}

			err = r.Patch(ctx, issuer, client.MergeFrom(originalIssuer))
			if err != nil {
				return handleError(
					err,
					"FailedToPatchIssuer",
					"failed to patch issuer",
				)
			}

			instance.SetIssuerConfigured()
		}
	}

	// All good
	// We still have to requeue before expiry to renew the CRL
	requeueAfter := time.Until(crl.NextUpdate.Add(-renewBefore))
	logger.Info("reconcile completed successfully", "requeueAfter", requeueAfter.String())
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// getIssuer retireves the Issuer or ClusterIssuer specified in the IssuerReference
func (r *ManagedCRLReconciler) getIssuer(ctx context.Context, namespace string, issuerRef cmmetav1.IssuerReference) (client.Object, error) {
	switch issuerRef.Kind {
	case "Issuer":
		issuer := &cmv1.Issuer{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: issuerRef.Name}, issuer); err != nil {
			return nil, err
		}
		return issuer, nil
	case "ClusterIssuer":
		issuer := &cmv1.ClusterIssuer{}
		if err := r.Get(ctx, client.ObjectKey{Name: issuerRef.Name}, issuer); err != nil {
			return nil, err
		}
		return issuer, nil
	default:
		return nil, errors.New("unsupported issuer kind")
	}
}

// getIssuerSecret retrieves the Secret containing the CA certificate and private key
func (r *ManagedCRLReconciler) getIssuerSecret(ctx context.Context, namespace string, issuer client.Object) (*corev1.Secret, error) {
	var secretRef client.ObjectKey

	switch issuer := issuer.(type) {
	case *cmv1.Issuer:
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: issuer.Name}, issuer); err != nil {
			return nil, err
		}
		if issuer.Spec.CA == nil {
			return nil, errors.New("issuer is not a CA issuer")
		}
		secretRef = client.ObjectKey{
			Name:      issuer.Spec.CA.SecretName,
			Namespace: namespace,
		}
	case *cmv1.ClusterIssuer:
		if err := r.Get(ctx, client.ObjectKey{Name: issuer.Name}, issuer); err != nil {
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
	utils.UpdateLabels(obj, map[string]string{
		labelManagedByName: labelManagedByValue,
		labelComponentName: labelComponentValue,
		labelAppName:       obj.GetName(),
		labelInstanceName:  instance.Name,
		labelVersionName:   internal.Version,
	})

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
		Owns(&corev1.ConfigMap{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Watches(&cmv1.ClusterIssuer{}, handler.EnqueueRequestsFromMapFunc(mapIssuerToCRL)).
		Watches(&cmv1.Issuer{}, handler.EnqueueRequestsFromMapFunc(mapIssuerToCRL)).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(mapIssuerToCRL)).
		Named("managedcrl").
		Complete(r)
}
