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

package integration

import (
	"context"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crloperatorv1alpha1 "github.com/scality/crl-operator/api/v1alpha1"
)

type mcrlTestCase struct {
	name                  string
	spec                  crloperatorv1alpha1.ManagedCRLSpec
	shouldError           bool
	shouldExposePod       bool
	shouldExposeIngress   bool
	shouldConfigureIssuer bool
}

var (
	testCases = []mcrlTestCase{
		{
			name: "nominal-secret-only-issuer",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				IssuerRef: cmmetav1.IssuerReference{
					Name: "test-issuer",
					Kind: "Issuer",
				},
			},
			shouldError:           false,
			shouldExposePod:       false,
			shouldExposeIngress:   false,
			shouldConfigureIssuer: false,
		}, {
			name: "nominal-secret-only-clusterissuer",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				IssuerRef: cmmetav1.IssuerReference{
					Name: "test-issuer",
					Kind: "ClusterIssuer",
				},
			},
			shouldError:           false,
			shouldExposePod:       false,
			shouldExposeIngress:   false,
			shouldConfigureIssuer: false,
		},
	}
)

func toTableEntry(tcs []mcrlTestCase) []TableEntry {
	entries := make([]TableEntry, len(tcs))
	for i, tc := range tcs {
		entries[i] = Entry(fmt.Sprintf("ManagedCRL %s", tc.name), tc)
	}
	return entries
}

var _ = Describe("ManagedCRL Controller", func() {
	Context("When reconciling a resource", func() {
		var testNamespace string
		ctx := context.Background()

		BeforeEach(func() {
			testNamespace = fmt.Sprintf("test-mcrl-%d", time.Now().UnixNano())
			Expect(k8sClient.Create(
				ctx,
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNamespace,
					},
				},
			)).To(Succeed())

			By("creating issuers required for the tests")
			Expect(k8sClient.Create(
				ctx,
				&cmv1.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-issuer",
					},
					Spec: cmv1.IssuerSpec{
						IssuerConfig: cmv1.IssuerConfig{
							CA: &cmv1.CAIssuer{
								SecretName: "ca-key-pair",
							},
						},
					},
				},
			)).To(Succeed())
			Expect(k8sClient.Create(
				ctx,
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ca-key-pair",
						Namespace: testNamespace,
					},
					Data: map[string][]byte{
						"tls.key": []byte(caKeyPem),
						"tls.crt": []byte(caCrtPem),
					},
					Type: corev1.SecretTypeTLS,
				},
			)).To(Succeed())
			Expect(k8sClient.Create(
				ctx,
				&cmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-issuer",
						Namespace: testNamespace,
					},
					Spec: cmv1.IssuerSpec{
						IssuerConfig: cmv1.IssuerConfig{
							CA: &cmv1.CAIssuer{
								SecretName: "ca-key-pair",
							},
						},
					},
				},
			)).To(Succeed())
		})

		AfterEach(func() {
			Expect(k8sClient.Delete(ctx, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: testNamespace,
				},
			})).To(Succeed())

			Expect(k8sClient.Delete(ctx, &cmv1.ClusterIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-issuer",
				},
			})).To(Succeed())
		})

		DescribeTableSubtree("should reconcile various ManagedCRL resources as expected", func(tc mcrlTestCase) {
			It("should successfully reconcile a norminal secret only resource", func() {
				typeNamespacedName := types.NamespacedName{
					Name:      tc.name,
					Namespace: testNamespace,
				}
				managedcrl := &crloperatorv1alpha1.ManagedCRL{
					ObjectMeta: metav1.ObjectMeta{
						Name:      typeNamespacedName.Name,
						Namespace: typeNamespacedName.Namespace,
					},
					Spec: tc.spec,
				}

				By("creating the ManagedCRL")
				err := k8sClient.Create(ctx, managedcrl)
				if tc.shouldError {
					Expect(err).To(HaveOccurred())
					return
				}
				Expect(err).ToNot(HaveOccurred())
				checkAllReady(typeNamespacedName, tc)

				By("adding a revoked certificate to the CRL and checking the update is reflected")
				retrieved := &crloperatorv1alpha1.ManagedCRL{}
				Expect(k8sClient.Get(ctx, typeNamespacedName, retrieved)).To(Succeed())
				retrieved.Spec.Revocations = []crloperatorv1alpha1.RevocationSpec{
					{
						SerialNumber: "123456789",
						ReasonCode:   ptr.To(2),
					},
				}
				Expect(k8sClient.Update(ctx, retrieved)).To(Succeed())
				checkAllReady(typeNamespacedName, tc)

				By("changing the reason code of a revoked certificate")
				Expect(k8sClient.Get(ctx, typeNamespacedName, retrieved)).To(Succeed())
				retrieved.Spec.Revocations = []crloperatorv1alpha1.RevocationSpec{
					{
						SerialNumber: "123456789",
						ReasonCode:   ptr.To(1),
					},
				}
				Expect(k8sClient.Update(ctx, retrieved)).To(Succeed())
				checkAllReady(typeNamespacedName, tc)

				By("removing all revoked certificates from the CRL")
				Expect(k8sClient.Get(ctx, typeNamespacedName, retrieved)).To(Succeed())
				retrieved.Spec.Revocations = nil
				Expect(k8sClient.Update(ctx, retrieved)).To(Succeed())
				checkAllReady(typeNamespacedName, tc)

				By("deleting the ManagedCRL")
				Expect(k8sClient.Delete(ctx, retrieved)).To(Succeed())
				Eventually(func() bool {
					return errors.IsNotFound(
						k8sClient.Get(ctx, typeNamespacedName, &crloperatorv1alpha1.ManagedCRL{}),
					)
				}, 10*time.Second, time.Second).Should(BeTrue())
			})
		}, toTableEntry(testCases))
	})
})

func checkAllReady(mcrlRef types.NamespacedName, tc mcrlTestCase) {
	By("checking the ManagedCRL becomes Secret properly setup")
	checkSecret(mcrlRef)

	if tc.shouldExposePod {
		Expect(false).To(BeTrue()) // TODO
	} else {
		By("checking no PodExposed status is set")
		retrieved := &crloperatorv1alpha1.ManagedCRL{}
		Expect(k8sClient.Get(ctx, mcrlRef, retrieved)).To(Succeed())
		Expect(retrieved.Status.PodExposed).To(BeNil())
	}
	if tc.shouldExposeIngress {
		Expect(false).To(BeTrue()) // TODO
	} else {
		By("checking no IngressExposed status is set")
		retrieved := &crloperatorv1alpha1.ManagedCRL{}
		Expect(k8sClient.Get(ctx, mcrlRef, retrieved)).To(Succeed())
		Expect(retrieved.Status.IngressExposed).To(BeNil())
	}
	if tc.shouldConfigureIssuer {
		Expect(false).To(BeTrue()) // TODO
	} else {
		By("checking no IssuerConfigured status is set")
		retrieved := &crloperatorv1alpha1.ManagedCRL{}
		Expect(k8sClient.Get(ctx, mcrlRef, retrieved)).To(Succeed())
		Expect(retrieved.Status.IssuerConfigured).To(BeNil())
	}
}

// Check if the given Secret matches the expected values from the ManagedCRL
func checkSecret(mcrlRef types.NamespacedName) {
	retrieved := &crloperatorv1alpha1.ManagedCRL{}

	// Wait until the ManagedCRL is SecretReady
	Eventually(func() bool {
		Expect(k8sClient.Get(ctx, mcrlRef, retrieved)).To(Succeed())
		for _, cond := range retrieved.Status.Conditions {
			if cond.Type == "SecretReady" {
				return cond.Status == metav1.ConditionTrue && cond.ObservedGeneration == retrieved.Generation
			}
		}
		return false
	}, 10*time.Second, time.Second).Should(BeTrue())
	retrieved.WithDefaults()

	expectedSecretNs := mcrlRef.Namespace
	if retrieved.Spec.IssuerRef.Kind == "ClusterIssuer" {
		expectedSecretNs = certManagerNamespace
	}
	Expect(retrieved.Status.SecretReady).To(PointTo(BeTrue()))
	Expect(retrieved.Status.ObservedCASecretRef).To(PointTo(MatchFields(IgnoreExtras, Fields{
		"Name":      Equal("ca-key-pair"),
		"Namespace": Equal(expectedSecretNs),
	})))
	Expect(retrieved.Status.ObservedCASecretVersion).ToNot(BeEmpty())

	// Check secret content
	expectedRevokedCerts, err := retrieved.Spec.GetRevokedListEntries()
	Expect(err).ToNot(HaveOccurred())
	createdSecret := retrieved.GetSecret()
	Expect(k8sClient.Get(
		ctx,
		client.ObjectKeyFromObject(createdSecret),
		createdSecret,
	)).To(Succeed())
	Expect(createdSecret.Data).To(HaveKey("ca.crl"))
	Expect(createdSecret.OwnerReferences).To(ContainElement(MatchFields(IgnoreExtras, Fields{
		"APIVersion": Equal(crloperatorv1alpha1.GroupVersion.String()),
		"Kind":       Equal("ManagedCRL"),
		"Name":       Equal(retrieved.Name),
		"UID":        Equal(retrieved.UID),
	})))

	// Check CRL content
	crl, err := x509.ParseRevocationList(createdSecret.Data["ca.crl"])
	Expect(err).ToNot(HaveOccurred())
	Expect(crl).ToNot(BeNil())
	Expect(crl.Number).To(Equal(big.NewInt(retrieved.Status.CRLNumber)))
	Expect(crl.CheckSignatureFrom(caCert)).ToNot(HaveOccurred())
	if len(expectedRevokedCerts) == 0 {
		Expect(crl.RevokedCertificateEntries).To(BeEmpty())
	} else {
		for i, revokedCert := range expectedRevokedCerts {
			Expect(crl.RevokedCertificateEntries[i].SerialNumber).To(Equal(revokedCert.SerialNumber))
			Expect(crl.RevokedCertificateEntries[i].ReasonCode).To(Equal(revokedCert.ReasonCode))
		}
	}
}
