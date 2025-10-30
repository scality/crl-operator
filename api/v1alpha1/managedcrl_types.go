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
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"

	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// ImageSpec defines information about the image to expose the CRL.
type ImageSpec struct {
	// Repository is the container image repository.
	// +kubebuilder:validation:MinLength=1
	// +optional
	Repository *string `json:"repository"`

	// Name is the container image name.
	// (default: "nginx")
	// +kubebuilder:validation:MinLength=1
	// +optional
	Name *string `json:"name"`

	// Tag is the container image tag.
	// (default: "1.29.3-alpine3.22")
	// +kubebuilder:validation:MinLength=1
	// +optional
	Tag *string `json:"tag"`

	// PullSecretRef is a reference to a Secret containing the image pull
	// credentials.
	// +optional
	PullSecrets []corev1.LocalObjectReference `json:"pullSecrets,omitempty"`
}

// CRLExposeSpec defines how the CRL should be exposed.
type CRLExposeSpec struct {
	// Enabled indicates whether the CRL should be exposed.
	Enabled bool `json:"enabled"`

	// Image specifies the container image to use for exposing the CRL.
	// +optional
	Image *ImageSpec `json:"image"`
	// Node Selector to deploy the CRL server
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Tolerations to deploy the CRL server
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

// RevocationSpec defines a certificate to be revoked.
type RevocationSpec struct {
	// SerialNumber is the serial number of the certificate to be revoked.
	// +kubebuilder:validation:MinLength=1
	SerialNumber string `json:"serialNumber"`

	// RevocationTime is the time at which the certificate was revoked.
	// If not specified, the current time will be used.
	// +optional
	RevocationTime *metav1.Time `json:"revocationTime,omitempty"`

	// Reason is the reason for revocation (refer to RFC 5280 Section 5.3.1.).
	// +optional
	ReasonCode *int `json:"reasonCode,omitempty"`
}

// ManagedCRLSpec defines the desired state of ManagedCRL.
type ManagedCRLSpec struct {
	// IssuerRef is a reference to the cert-manager Issuer or ClusterIssuer
	// that will sign the CRL.
	IssuerRef cmmetav1.ObjectReference `json:"issuerRef"`

	// Duration is the duration for which the CRL is valid.
	// (default: 168h = 7 days)
	// +optional
	Duration *metav1.Duration `json:"duration,omitempty"`

	// Revocations is a list of certificates to be revoked.
	// +optional
	Revocations []RevocationSpec `json:"revocations,omitempty"`

	// Expose specifies how the CRL should be exposed.
	// +optional
	Expose *CRLExposeSpec `json:"expose,omitempty"`
}

// ManagedCRLStatus defines the observed state of ManagedCRL.
type ManagedCRLStatus struct {
	// SecretReady indicates whether the CRL is built and available in the Secret.
	SecretReady *bool `json:"secretReady,omitempty"`
	// PodExposed indicates whether the CRL expose Pod is running.
	PodExposed *bool              `json:"podExposed,omitempty"`
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// CRLValidUntil is the time until which the CRL is valid.
	CRLValidUntil metav1.Time `json:"crlValidUntil,omitempty"`

	// CRLNumber is the number of the CRL.
	CRLNumber int64 `json:"crlNumber,omitempty"`

	// ObservedCASecretRef is a reference to the Secret containing the last
	// CA certificate and private key used to sign the CRL.
	ObservedCASecretRef *corev1.SecretReference `json:"observedCASecretRef,omitempty"`
	// ObservedCASecretVersion is the resource version of the Secret
	// containing the last CA certificate and private key used to sign the CRL.
	ObservedCASecretVersion string `json:"observedCASecretVersion,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=mcrl
// +kubebuilder:printcolumn:name="Issuer",type=string,JSONPath=`.spec.issuerRef.name`
// +kubebuilder:printcolumn:name="Expires",type=string,JSONPath=`.status.crlValidUntil`
// +kubebuilder:printcolumn:name="CRL Number",type=integer,JSONPath=`.status.crlNumber`

// ManagedCRL is the Schema for the managedcrls API.
type ManagedCRL struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ManagedCRLSpec   `json:"spec,omitempty"`
	Status ManagedCRLStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ManagedCRLList contains a list of ManagedCRL.
type ManagedCRLList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ManagedCRL `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ManagedCRL{}, &ManagedCRLList{})
}

// IsExposed returns true if the CRL is configured to be exposed.
func (mcrl *ManagedCRL) IsExposed() bool {
	return mcrl.Spec.Expose != nil && mcrl.Spec.Expose.Enabled
}

// GetSecret returns the name of the Secret used to store the CRL.
func (mcrl *ManagedCRL) GetSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-crl", mcrl.Name),
			Namespace: mcrl.Namespace,
		},
	}
}

// GetConfigMap returns the name of the ConfigMap used to configure the CRL expose Pod.
func (mcrl *ManagedCRL) GetConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-server-config", mcrl.Name),
			Namespace: mcrl.Namespace,
		},
	}
}

// GetDeployment returns the name of the Deployment used to expose the CRL.
func (mcrl *ManagedCRL) GetDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-server", mcrl.Name),
			Namespace: mcrl.Namespace,
		},
	}
}

// GetService returns the name of the Service used to expose the CRL.
func (mcrl *ManagedCRL) GetService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-server", mcrl.Name),
			Namespace: mcrl.Namespace,
		},
	}
}

// WithDefaults sets default values on the ManagedCRL resource.
func (mcrl *ManagedCRL) WithDefaults() {
	mcrl.Spec.withDefaults()
}

func (mcrls *ManagedCRLSpec) withDefaults() {
	if mcrls.Duration == nil {
		mcrls.Duration = &metav1.Duration{Duration: 7 * 24 * 60 * 60 * 1e9} // 7 days
	}

	for i := range mcrls.Revocations {
		mcrls.Revocations[i].withDefaults()
	}

	if mcrls.Expose != nil {
		mcrls.Expose.withDefaults()
	}
}

func (rs *RevocationSpec) withDefaults() {
	if rs.RevocationTime == nil {
		rs.RevocationTime = &metav1.Time{Time: metav1.Now().Time}
	}
	if rs.ReasonCode == nil {
		rs.ReasonCode = ptr.To(0) // Unspecified
	}
}

func (ces *CRLExposeSpec) withDefaults() {
	if ces.Image == nil {
		ces.Image = &ImageSpec{}
	}
	ces.Image.withDefaults()
}

func (is *ImageSpec) withDefaults() {
	if is.Name == nil {
		is.Name = ptr.To("nginx")
	}
	if is.Tag == nil {
		is.Tag = ptr.To("1.29.3-alpine3.22")
	}
}

// Validate validates the ManagedCRL resource.
func (mcrl *ManagedCRL) Validate() error {
	err := mcrl.Spec.validate()
	if err != nil {
		return fmt.Errorf("spec validation failed: %w", err)
	}
	return nil
}

func (mcrls *ManagedCRLSpec) validate() error {
	// IssuerRef kind supported is only ClusterIssuer or Issuer
	if mcrls.IssuerRef.Kind != "Issuer" && mcrls.IssuerRef.Kind != "ClusterIssuer" {
		return fmt.Errorf("issuerRef kind must be either 'Issuer' or 'ClusterIssuer', got '%s'", mcrls.IssuerRef.Kind)
	}

	// Ensure duration is at least a day
	if mcrls.Duration.Hours() < 24 {
		return fmt.Errorf("duration must be at least 24h")
	}

	for i, revocation := range mcrls.Revocations {
		err := revocation.validate()
		if err != nil {
			return fmt.Errorf("invalid revocation at index %d: %w", i, err)
		}
	}

	// Ensure we can get the revoked list entries
	_, err := mcrls.GetRevokedListEntries()
	if err != nil {
		return fmt.Errorf("failed to get revoked list entries: %w", err)
	}

	if mcrls.Expose != nil {
		err := mcrls.Expose.validate()
		if err != nil {
			return fmt.Errorf("invalid expose configuration: %w", err)
		}
	}

	return nil
}

func (rs *RevocationSpec) validate() error {
	// Nothing to validate for now, it's validated by the GetRevokedListEntries method
	return nil
}

func (ces *CRLExposeSpec) validate() error {
	if !ces.Enabled {
		return nil
	}

	err := ces.Image.validate()
	if err != nil {
		return fmt.Errorf("invalid image configuration: %w", err)
	}
	return nil
}

func (is *ImageSpec) validate() error {
	// Nothing to validate for now
	return nil
}

// ToRevocationListEntry converts a RevocationSpec to an x509.RevocationListEntry.
func (rs RevocationSpec) ToRevocationListEntry() (x509.RevocationListEntry, error) {
	cleanSerial := strings.ReplaceAll(rs.SerialNumber, ":", "")

	// First try base 16 if not working try 0 to auto detect
	serial, ok := big.NewInt(0).SetString(cleanSerial, 16)
	if !ok {
		serial, ok = big.NewInt(0).SetString(cleanSerial, 0)
		if !ok {
			return x509.RevocationListEntry{}, fmt.Errorf("invalid serial number: %s", rs.SerialNumber)
		}
	}

	return x509.RevocationListEntry{
		SerialNumber:   serial,
		RevocationTime: rs.RevocationTime.Time,
		ReasonCode:     *rs.ReasonCode,
	}, nil
}

// GetRevokedListEntries converts the Revocations in ManagedCRLSpec to a slice of x509.RevocationListEntry.
func (mcrls *ManagedCRLSpec) GetRevokedListEntries() ([]x509.RevocationListEntry, error) {
	if mcrls.Revocations == nil {
		return []x509.RevocationListEntry{}, nil
	}

	revokedCerts := make([]x509.RevocationListEntry, 0, len(mcrls.Revocations))
	for _, revocation := range mcrls.Revocations {
		revocationEntry, err := revocation.ToRevocationListEntry()
		if err != nil {
			return nil, fmt.Errorf("invalid revocation entry for serial number %s: %w", revocation.SerialNumber, err)
		}
		revokedCerts = append(revokedCerts, revocationEntry)
	}
	return revokedCerts, nil
}

// GetImage returns the full image string in the format "repository/name:tag".
func (is *ImageSpec) GetImage() string {
	image := fmt.Sprintf("%s:%s", *is.Name, *is.Tag)
	if is.Repository != nil {
		image = fmt.Sprintf("%s/%s", *is.Repository, image)
	}
	return image
}

// SetSecretReady sets the ManagedCRL status to SecretReady.
func (mcrl *ManagedCRL) SetSecretReady() {
	condition := metav1.Condition{
		Type:               "SecretReady",
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "CRLSecretReady",
		Message:            "The secret containing the CRL is ready",
		ObservedGeneration: mcrl.Generation,
	}
	meta.SetStatusCondition(&mcrl.Status.Conditions, condition)
	mcrl.Status.SecretReady = ptr.To(true)
}

// SetSecretNotReady sets the ManagedCRL status to NotReady with the given reason and message.
func (mcrl *ManagedCRL) SetSecretNotReady(reason, message string) {
	condition := metav1.Condition{
		Type:               "SecretReady",
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
		ObservedGeneration: mcrl.Generation,
	}
	meta.SetStatusCondition(&mcrl.Status.Conditions, condition)
	mcrl.Status.SecretReady = ptr.To(false)
}

// SetPodExposed sets the ManagedCRL status to PodExposed.
func (mcrl *ManagedCRL) SetPodExposed() {
	condition := metav1.Condition{
		Type:               "PodExposed",
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "CRLPodExposed",
		Message:            "The pod exposing the CRL is running",
		ObservedGeneration: mcrl.Generation,
	}
	meta.SetStatusCondition(&mcrl.Status.Conditions, condition)
	mcrl.Status.PodExposed = ptr.To(true)
}

// SetPodNotExposed sets the ManagedCRL status to PodNotExposed with the given reason and message.
func (mcrl *ManagedCRL) SetPodNotExposed(reason, message string) {
	condition := metav1.Condition{
		Type:               "PodExposed",
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
		ObservedGeneration: mcrl.Generation,
	}
	meta.SetStatusCondition(&mcrl.Status.Conditions, condition)
	mcrl.Status.PodExposed = ptr.To(false)
}
