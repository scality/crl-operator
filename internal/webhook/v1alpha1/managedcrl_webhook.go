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

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	crloperatorv1alpha1 "github.com/scality/crl-operator/api/v1alpha1"
)

// nolint:unused
// log is for logging in this package.
var managedcrllog = logf.Log.WithName("managedcrl-resource")

// SetupManagedCRLWebhookWithManager registers the webhook for ManagedCRL in the manager.
func SetupManagedCRLWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&crloperatorv1alpha1.ManagedCRL{}).
		WithValidator(&ManagedCRLCustomValidator{}).
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
	// TODO(user): Add more fields as needed for validation
}

var _ webhook.CustomValidator = &ManagedCRLCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type ManagedCRL.
func (v *ManagedCRLCustomValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	managedcrl, ok := obj.(*crloperatorv1alpha1.ManagedCRL)
	if !ok {
		return nil, fmt.Errorf("expected a ManagedCRL object but got %T", obj)
	}
	managedcrllog.Info("Validation for ManagedCRL upon creation", "name", managedcrl.GetName())

	// TODO(user): fill in your validation logic upon object creation.

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type ManagedCRL.
func (v *ManagedCRLCustomValidator) ValidateUpdate(_ context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	managedcrl, ok := newObj.(*crloperatorv1alpha1.ManagedCRL)
	if !ok {
		return nil, fmt.Errorf("expected a ManagedCRL object for the newObj but got %T", newObj)
	}
	managedcrllog.Info("Validation for ManagedCRL upon update", "name", managedcrl.GetName())

	// TODO(user): fill in your validation logic upon object update.

	return nil, nil
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
