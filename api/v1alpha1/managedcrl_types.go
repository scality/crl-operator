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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// RevocationSpec defines a certificate to be revoked.
type RevocationSpec struct {
	// SerialNumber is the serial number of the certificate to be revoked.
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
}

// ManagedCRLStatus defines the observed state of ManagedCRL.
type ManagedCRLStatus struct {
	// SecretReady indicates whether the CRL is built and available in the Secret.
	SecretReady *bool              `json:"secretReady,omitempty"`
	Conditions  []metav1.Condition `json:"conditions,omitempty"`

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
}

func (rs *RevocationSpec) withDefaults() {
	if rs.RevocationTime == nil {
		rs.RevocationTime = &metav1.Time{Time: metav1.Now().Time}
	}
	if rs.ReasonCode == nil {
		rs.ReasonCode = ptr.To(0) // Unspecified
	}
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
