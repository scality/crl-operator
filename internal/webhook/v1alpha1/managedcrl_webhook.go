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

package v1alpha1

import (
	"context"
	"fmt"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/go-logr/logr"
	crloperatorv1alpha1 "github.com/scality/crl-operator/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var managedcrllog = logf.Log.WithName("managedcrl-resource")

// SetupManagedCRLWebhookWithManager registers the webhook for ManagedCRL in the manager.
func SetupManagedCRLWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&crloperatorv1alpha1.ManagedCRL{}).
		WithValidator(&ManagedCRLCustomValidator{
			client: mgr.GetClient(),
		}).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-crl-operator-scality-com-v1alpha1-managedcrl,mutating=false,failurePolicy=fail,sideEffects=None,groups=crl-operator.scality.com,resources=managedcrls,verbs=create;update,versions=v1alpha1,name=vmanagedcrl-v1alpha1.kb.io,admissionReviewVersions=v1

// ManagedCRLCustomValidator struct is responsible for validating the ManagedCRL resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type ManagedCRLCustomValidator struct {
	client client.Client
}

var _ webhook.CustomValidator = &ManagedCRLCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type ManagedCRL.
func (v *ManagedCRLCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	managedcrl, ok := obj.(*crloperatorv1alpha1.ManagedCRL)
	if !ok {
		return nil, fmt.Errorf("expected a ManagedCRL object but got %T", obj)
	}
	logger := managedcrllog.WithValues("name", managedcrl.GetName()).WithValues("namespace", managedcrl.GetNamespace())

	logger.Info("Validation for ManagedCRL upon creation")

	return nil, validationManagedCRL(logger, ctx, v.client, managedcrl)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type ManagedCRL.
func (v *ManagedCRLCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	managedcrl, ok := newObj.(*crloperatorv1alpha1.ManagedCRL)
	if !ok {
		return nil, fmt.Errorf("expected a ManagedCRL object for the newObj but got %T", newObj)
	}
	logger := managedcrllog.WithValues("name", managedcrl.GetName()).WithValues("namespace", managedcrl.GetNamespace())
	logger.Info("Validation for ManagedCRL upon update")

	return nil, validationManagedCRL(logger, ctx, v.client, managedcrl)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type ManagedCRL.
func (v *ManagedCRLCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	managedcrl, ok := obj.(*crloperatorv1alpha1.ManagedCRL)
	if !ok {
		return nil, fmt.Errorf("expected a ManagedCRL object but got %T", obj)
	}
	managedcrllog.Info("Validation for ManagedCRL upon deletion", "name", managedcrl.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}

// validationManagedCRL validates the ManagedCRL fields.
func validationManagedCRL(logger logr.Logger, ctx context.Context, c client.Client, managedcrl *crloperatorv1alpha1.ManagedCRL) error {
	managedcrl.WithDefaults()
	if err := managedcrl.Validate(); err != nil {
		logger.Error(err, "Validation failed")
		return err
	}

	// Ensure the specified Issuer or ClusterIssuer exists
	issuerLogger := logger.WithValues("issuer_name", managedcrl.Spec.IssuerRef.Name, "issuer_kind", managedcrl.Spec.IssuerRef.Kind)
	issuerRef := managedcrl.Spec.IssuerRef
	switch issuerRef.Kind {
	case "Issuer":
		var issuer cmv1.Issuer
		err := c.Get(ctx, client.ObjectKey{Namespace: managedcrl.Namespace, Name: issuerRef.Name}, &issuer)
		if err != nil {
			issuerLogger.Error(err, "Issuer not found")
			return fmt.Errorf("issuer %s not found in namespace %s", issuerRef.Name, managedcrl.Namespace)
		}
		if issuer.Spec.CA == nil || issuer.Spec.CA.SecretName == "" {
			err := fmt.Errorf("issuer %s in namespace %s is not a CA issuer", issuerRef.Name, managedcrl.Namespace)
			issuerLogger.Error(err, "Issuer is not a CA issuer")
			return err
		}
	case "ClusterIssuer":
		var issuer cmv1.ClusterIssuer
		err := c.Get(ctx, client.ObjectKey{Name: issuerRef.Name}, &issuer)
		if err != nil {
			issuerLogger.Error(err, "ClusterIssuer not found")
			return fmt.Errorf("clusterissuer %s not found", issuerRef.Name)
		}
		if issuer.Spec.CA == nil || issuer.Spec.CA.SecretName == "" {
			err := fmt.Errorf("clusterissuer %s is not a CA issuer", issuerRef.Name)
			issuerLogger.Error(err, "Issuer is not a CA issuer")
			return err
		}
	default:
		err := fmt.Errorf("invalid IssuerRef kind: %s", issuerRef.Kind)
		issuerLogger.Error(err, "IssuerRef kind must be either 'Issuer' or 'ClusterIssuer'")
		return err
	}

	logger.Info("Validation successful")
	return nil
}
