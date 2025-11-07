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
	"strings"
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
	errorMessage          string
	shouldExposePod       bool
	shouldExposeIngress   bool
	shouldConfigureIssuer bool
}

var (
	testCases = []mcrlTestCase{
		{
			name: "secret-only",
			spec: crloperatorv1alpha1.ManagedCRLSpec{},
		}, {
			name: "exposed-only",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				Expose: &crloperatorv1alpha1.CRLExposeSpec{
					Enabled:  true,
					Internal: ptr.To(false),
				},
			},
			shouldExposePod: true,
		}, {
			name: "exposed-with-custom-im",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				Expose: &crloperatorv1alpha1.CRLExposeSpec{
					Enabled:  true,
					Image:    crloperatorv1alpha1.ImageSpec{Repository: ptr.To("custom/repo"), Tag: ptr.To("v1.2.3")},
					Internal: ptr.To(false),
				},
			},
			shouldExposePod: true,
		}, {
			name: "exposed-only-explicit-ingress-false",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				Expose: &crloperatorv1alpha1.CRLExposeSpec{
					Enabled:  true,
					Internal: ptr.To(false),
					Ingress: &crloperatorv1alpha1.IngressSpec{
						Enabled: ptr.To(false),
					},
				},
			},
			shouldExposePod: true,
		}, {
			name: "ingress-only-hostname",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				Expose: &crloperatorv1alpha1.CRLExposeSpec{
					Enabled:  true,
					Internal: ptr.To(false),
					Ingress: &crloperatorv1alpha1.IngressSpec{
						Hostname: ptr.To("test.local"),
					},
				},
			},
			shouldExposePod:       true,
			shouldExposeIngress:   true,
			shouldConfigureIssuer: true,
		}, {
			name: "ingress-only-ip",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				Expose: &crloperatorv1alpha1.CRLExposeSpec{
					Enabled:  true,
					Internal: ptr.To(false),
					Ingress: &crloperatorv1alpha1.IngressSpec{
						IPAddresses: []crloperatorv1alpha1.IPAddress{
							"10.11.12.13",
							"20.21.22.23",
						},
					},
				},
			},
			shouldExposePod:       true,
			shouldExposeIngress:   true,
			shouldConfigureIssuer: true,
		}, {
			name: "ingress-only-both",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				Expose: &crloperatorv1alpha1.CRLExposeSpec{
					Enabled:  true,
					Internal: ptr.To(false),
					Ingress: &crloperatorv1alpha1.IngressSpec{
						Hostname: ptr.To("test.local"),
						IPAddresses: []crloperatorv1alpha1.IPAddress{
							"10.11.12.13",
							"20.21.22.23",
						},
					},
				},
			},
			shouldExposePod:       true,
			shouldExposeIngress:   true,
			shouldConfigureIssuer: true,
		}, {
			name: "exposed-with-internal",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				Expose: &crloperatorv1alpha1.CRLExposeSpec{
					Enabled:  true,
					Internal: ptr.To(true),
				},
			},
			shouldExposePod:       true,
			shouldConfigureIssuer: true,
		}, {
			name: "ingress-not-managed",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				Expose: &crloperatorv1alpha1.CRLExposeSpec{
					Enabled:  true,
					Internal: ptr.To(false),
					Ingress: &crloperatorv1alpha1.IngressSpec{
						Managed:  ptr.To(false),
						Hostname: ptr.To("test.local"),
						IPAddresses: []crloperatorv1alpha1.IPAddress{
							"10.11.12.13",
							"20.21.22.23",
						},
					},
				},
			},
			shouldExposePod:       true,
			shouldConfigureIssuer: true,
		}, {
			name: "all-in-one",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				Expose: &crloperatorv1alpha1.CRLExposeSpec{
					Enabled: true,
					Ingress: &crloperatorv1alpha1.IngressSpec{
						Hostname: ptr.To("test.local"),
						IPAddresses: []crloperatorv1alpha1.IPAddress{
							"10.11.12.13",
							"20.21.22.23",
						},
					},
				},
			},
			shouldExposePod:       true,
			shouldExposeIngress:   true,
			shouldConfigureIssuer: true,
		}, {
			name: "error-invalid-issuer-kind",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				IssuerRef: cmmetav1.IssuerReference{
					Kind: "InvalidKind",
				},
			},
			shouldError:  true,
			errorMessage: "issuerRef kind must be either 'Issuer' or 'ClusterIssuer', got 'InvalidKind'",
		}, {
			name: "error-non-existent-issuer",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				IssuerRef: cmmetav1.IssuerReference{
					Name: "non-existent-issuer",
				},
			},
			shouldError:  true,
			errorMessage: "issuer non-existent-issuer not found",
		}, {
			name: "error-non-ca-issuer",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				IssuerRef: cmmetav1.IssuerReference{
					Name: "test-issuer-non-ca",
				},
			},
			shouldError:  true,
			errorMessage: "issuer test-issuer-non-ca .*is not a CA issuer",
		}, {
			name: "error-too-small-duration",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				Duration: &metav1.Duration{Duration: time.Hour},
			},
			shouldError:  true,
			errorMessage: "duration must be at least 24h",
		}, {
			name: "error-invalid-serial-number",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				Revocations: []crloperatorv1alpha1.RevocationSpec{
					{
						SerialNumber: "invalid-serial",
					},
				},
			},
			shouldError:  true,
			errorMessage: "invalid serial number: invalid-serial",
		}, {
			name: "error-empty-ingress",
			spec: crloperatorv1alpha1.ManagedCRLSpec{
				Expose: &crloperatorv1alpha1.CRLExposeSpec{
					Enabled: true,
					Ingress: &crloperatorv1alpha1.IngressSpec{},
				},
			},
			shouldError:  true,
			errorMessage: "invalid ingress configuration: either hostname or ipAddresses must be specified",
		},
	}
)

func toTableEntry(tcs []mcrlTestCase) []TableEntry {
	entries := []TableEntry{}
	for _, tc := range tcs {
		// Always add one entry for Issuer and one for ClusterIssuer
		name := tc.name
		if tc.spec.IssuerRef.Name == "" {
			tc.spec.IssuerRef.Name = "test-issuer"
		}
		issuerKindToTest := []string{"Issuer", "ClusterIssuer"}
		if tc.spec.IssuerRef.Kind != "" {
			issuerKindToTest = []string{tc.spec.IssuerRef.Kind}
		}

		for _, kind := range issuerKindToTest {
			tc.name = fmt.Sprintf("%s-%s", name, strings.ToLower(kind))
			tc.spec.IssuerRef.Kind = kind
			entries = append(entries, Entry(fmt.Sprintf("ManagedCRL %s", tc.name), tc))
		}
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
				&cmv1.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-issuer-non-ca",
					},
					Spec: cmv1.IssuerSpec{
						IssuerConfig: cmv1.IssuerConfig{
							SelfSigned: &cmv1.SelfSignedIssuer{},
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
			Expect(k8sClient.Create(
				ctx,
				&cmv1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-issuer-non-ca",
						Namespace: testNamespace,
					},
					Spec: cmv1.IssuerSpec{
						IssuerConfig: cmv1.IssuerConfig{
							SelfSigned: &cmv1.SelfSignedIssuer{},
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
			Expect(k8sClient.Delete(ctx, &cmv1.ClusterIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-issuer-non-ca",
				},
			})).To(Succeed())
		})

		DescribeTableSubtree("should reconcile various ManagedCRL resources as expected", func(tc mcrlTestCase) {
			It("should successfully reconcile resource", func() {
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
					Expect(err).To(MatchError(MatchRegexp(tc.errorMessage)))
					return
				}
				Expect(err).ToNot(HaveOccurred())
				checkAllReady(typeNamespacedName, tc, true)

				By("adding a revoked certificate to the CRL and checking the update is reflected")
				retrieved := &crloperatorv1alpha1.ManagedCRL{}
				Expect(k8sClient.Get(ctx, typeNamespacedName, retrieved)).To(Succeed())
				retrieved.Spec.Revocations = []crloperatorv1alpha1.RevocationSpec{
					{
						SerialNumber: "123456789",
						ReasonCode:   2,
					},
				}
				Expect(k8sClient.Update(ctx, retrieved)).To(Succeed())
				checkAllReady(typeNamespacedName, tc, false)

				By("changing the reason code of a revoked certificate")
				Expect(k8sClient.Get(ctx, typeNamespacedName, retrieved)).To(Succeed())
				retrieved.Spec.Revocations = []crloperatorv1alpha1.RevocationSpec{
					{
						SerialNumber: "123456789",
						ReasonCode:   1,
					},
				}
				Expect(k8sClient.Update(ctx, retrieved)).To(Succeed())
				checkAllReady(typeNamespacedName, tc, false)

				By("removing all revoked certificates from the CRL")
				Expect(k8sClient.Get(ctx, typeNamespacedName, retrieved)).To(Succeed())
				retrieved.Spec.Revocations = nil
				Expect(k8sClient.Update(ctx, retrieved)).To(Succeed())
				checkAllReady(typeNamespacedName, tc, false)

				By("deleting the ManagedCRL")
				Expect(k8sClient.Delete(ctx, retrieved)).To(Succeed())
				Eventually(func() bool {
					return errors.IsNotFound(
						k8sClient.Get(ctx, typeNamespacedName, &crloperatorv1alpha1.ManagedCRL{}),
					)
				}, 10*time.Second, time.Second).Should(BeTrue())

				By("checking the CRL Distribution Points have been removed from the Issuer/ClusterIssuer")
				switch tc.spec.IssuerRef.Kind {
				case "Issuer":
					issuer := &cmv1.Issuer{}
					Expect(k8sClient.Get(
						ctx,
						types.NamespacedName{
							Name:      tc.spec.IssuerRef.Name,
							Namespace: typeNamespacedName.Namespace,
						},
						issuer,
					)).To(Succeed())
					Expect(issuer.Spec.CA.CRLDistributionPoints).To(BeEmpty())
				case "ClusterIssuer":
					clusterIssuer := &cmv1.ClusterIssuer{}
					Expect(k8sClient.Get(
						ctx,
						types.NamespacedName{
							Name: tc.spec.IssuerRef.Name,
						},
						clusterIssuer,
					)).To(Succeed())
					Expect(clusterIssuer.Spec.CA.CRLDistributionPoints).To(BeEmpty())
				default:
					Fail("unexpected IssuerRef.Kind")
				}
			})
		}, toTableEntry(testCases))
	})
})

func checkAllReady(mcrlRef types.NamespacedName, tc mcrlTestCase, podShouldRestart bool) {
	By("checking the ManagedCRL becomes Secret properly setup")
	checkSecret(mcrlRef)

	if tc.shouldExposePod {
		By("checking the ManagedCRL becomes PodExposed properly setup")
		checkExposePod(mcrlRef, podShouldRestart)
	} else {
		By("checking no PodExposed status is set")
		retrieved := &crloperatorv1alpha1.ManagedCRL{}
		Expect(k8sClient.Get(ctx, mcrlRef, retrieved)).To(Succeed())
		Expect(retrieved.Status.PodExposed).To(BeNil())
	}
	if tc.shouldExposeIngress {
		By("checking the ManagedCRL becomes IngressExposed properly setup")
		checkIngress(mcrlRef)
	} else {
		By("checking no IngressExposed status is set")
		retrieved := &crloperatorv1alpha1.ManagedCRL{}
		Expect(k8sClient.Get(ctx, mcrlRef, retrieved)).To(Succeed())
		Expect(retrieved.Status.IngressExposed).To(BeNil())
	}
	if tc.shouldConfigureIssuer {
		By("checking the ManagedCRL becomes IssuerConfigured properly setup")
		checkIssuerConfigured(mcrlRef)
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

	Expect(retrieved.ObjectMeta.Finalizers).To(ContainElement("crl-operator.scality.com/finalizer"))

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

// checkExposePod is a helper to check if the PodExposed condition is set as expected
func checkExposePod(mcrlRef types.NamespacedName, shouldRestart bool) {
	retrieved := &crloperatorv1alpha1.ManagedCRL{}

	if shouldRestart {
		By("checking the deployment is restarted when already present")
		// Wait until the ManagedCRL is PodExposed False since the deployment is not ready yet
		Eventually(func() bool {
			Expect(k8sClient.Get(ctx, mcrlRef, retrieved)).To(Succeed())
			for _, cond := range retrieved.Status.Conditions {
				if cond.Type == "PodExposed" {
					return cond.Status == metav1.ConditionFalse &&
						cond.ObservedGeneration == retrieved.Generation &&
						cond.Reason == "ServerPodNotReady"
				}
			}
			return false
		}, 10*time.Second, time.Second).Should(BeTrue())
		Expect(retrieved.Status.PodExposed).To(PointTo(BeFalse()))

		// Check the deployment
		createdDeployment := retrieved.GetDeployment()
		Expect(k8sClient.Get(
			ctx,
			client.ObjectKeyFromObject(createdDeployment),
			createdDeployment,
		)).To(Succeed())
		Expect(createdDeployment.Spec.Replicas).To(PointTo(BeEquivalentTo(2)))
		Expect(createdDeployment.OwnerReferences).To(ContainElement(MatchFields(IgnoreExtras, Fields{
			"APIVersion": Equal(crloperatorv1alpha1.GroupVersion.String()),
			"Kind":       Equal("ManagedCRL"),
			"Name":       Equal(retrieved.Name),
			"UID":        Equal(retrieved.UID),
		})))
		Expect(createdDeployment.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(createdDeployment.Spec.Template.Spec.Containers[0].Image).To(Equal(retrieved.Spec.Expose.Image.GetImage()))

		// Set the deployment as ready
		createdDeployment.Status.Replicas = 2
		createdDeployment.Status.ReadyReplicas = 2
		Expect(k8sClient.Status().Update(
			ctx,
			createdDeployment,
		)).To(Succeed())
	}

	// Wait until the ManagedCRL is PodExposed
	Eventually(func() bool {
		Expect(k8sClient.Get(ctx, mcrlRef, retrieved)).To(Succeed())
		for _, cond := range retrieved.Status.Conditions {
			if cond.Type == "PodExposed" {
				return cond.Status == metav1.ConditionTrue && cond.ObservedGeneration == retrieved.Generation
			}
		}
		return false
	}, 10*time.Second, time.Second).Should(BeTrue())

	Expect(retrieved.Status.PodExposed).To(PointTo(BeTrue()))

	// Check ConfigMap existence
	createdConfigMap := retrieved.GetConfigMap()
	Expect(k8sClient.Get(
		ctx,
		client.ObjectKeyFromObject(createdConfigMap),
		createdConfigMap,
	)).To(Succeed())
	Expect(createdConfigMap.Data).To(HaveKey("default.conf"))
	Expect(createdConfigMap.OwnerReferences).To(ContainElement(MatchFields(IgnoreExtras, Fields{
		"APIVersion": Equal(crloperatorv1alpha1.GroupVersion.String()),
		"Kind":       Equal("ManagedCRL"),
		"Name":       Equal(retrieved.Name),
		"UID":        Equal(retrieved.UID),
	})))

	// Check Service existence
	createdService := retrieved.GetService()
	Expect(k8sClient.Get(
		ctx,
		client.ObjectKeyFromObject(createdService),
		createdService,
	)).To(Succeed())
	Expect(createdService.OwnerReferences).To(ContainElement(MatchFields(IgnoreExtras, Fields{
		"APIVersion": Equal(crloperatorv1alpha1.GroupVersion.String()),
		"Kind":       Equal("ManagedCRL"),
		"Name":       Equal(retrieved.Name),
		"UID":        Equal(retrieved.UID),
	})))
}

// checkIngress is a helper to check if the IngressExposed condition is set as expected
func checkIngress(mcrlRef types.NamespacedName) {
	retrieved := &crloperatorv1alpha1.ManagedCRL{}

	// Wait until the ManagedCRL is IngressExposed
	Eventually(func() bool {
		Expect(k8sClient.Get(ctx, mcrlRef, retrieved)).To(Succeed())
		for _, cond := range retrieved.Status.Conditions {
			if cond.Type == "IngressExposed" {
				return cond.Status == metav1.ConditionTrue && cond.ObservedGeneration == retrieved.Generation
			}
		}
		return false
	}, 10*time.Second, time.Second).Should(BeTrue())

	Expect(retrieved.Status.IngressExposed).To(PointTo(BeTrue()))

	// Check Ingress existence
	createdIngress := retrieved.GetIngress()
	Expect(k8sClient.Get(
		ctx,
		client.ObjectKeyFromObject(createdIngress),
		createdIngress,
	)).To(Succeed())
	Expect(createdIngress.OwnerReferences).To(ContainElement(MatchFields(IgnoreExtras, Fields{
		"APIVersion": Equal(crloperatorv1alpha1.GroupVersion.String()),
		"Kind":       Equal("ManagedCRL"),
		"Name":       Equal(retrieved.Name),
		"UID":        Equal(retrieved.UID),
	})))
	Expect(createdIngress.Spec.IngressClassName).To(Equal(retrieved.Spec.Expose.Ingress.ClassName))
	index := 0
	if retrieved.Spec.Expose.Ingress.Hostname != nil {
		Expect(len(createdIngress.Spec.Rules)).To(BeNumerically(">", index))
		Expect(createdIngress.Spec.Rules[index].Host).To(Equal(*retrieved.Spec.Expose.Ingress.Hostname))
		index += 1
	}
	if len(retrieved.Spec.Expose.Ingress.IPAddresses) > 0 {
		Expect(len(createdIngress.Spec.Rules)).To(BeNumerically(">", index))
		Expect(createdIngress.Spec.Rules[index].Host).To(BeEmpty())
	}
}

// checkIssuerConfigured is a helper to check if the IssuerConfigured condition is set as expected
func checkIssuerConfigured(mcrlRef types.NamespacedName) {
	retrieved := &crloperatorv1alpha1.ManagedCRL{}

	// Wait until the ManagedCRL is IssuerConfigured
	Eventually(func() bool {
		Expect(k8sClient.Get(ctx, mcrlRef, retrieved)).To(Succeed())
		for _, cond := range retrieved.Status.Conditions {
			if cond.Type == "IssuerConfigured" {
				return cond.Status == metav1.ConditionTrue && cond.ObservedGeneration == retrieved.Generation
			}
		}
		return false
	}, 10*time.Second, time.Second).Should(BeTrue())

	Expect(retrieved.Status.IssuerConfigured).To(PointTo(BeTrue()))

	// Retrieve the Issuer/ClusterIssuer and check it
	switch retrieved.Spec.IssuerRef.Kind {
	case "Issuer":
		issuer := &cmv1.Issuer{}
		Expect(k8sClient.Get(
			ctx,
			types.NamespacedName{
				Name:      retrieved.Spec.IssuerRef.Name,
				Namespace: mcrlRef.Namespace,
			},
			issuer,
		)).To(Succeed())
		Expect(issuer.Spec.CA.CRLDistributionPoints).To(Equal(retrieved.GetCRLDistributionPoint()))
	case "ClusterIssuer":
		clusterIssuer := &cmv1.ClusterIssuer{}
		Expect(k8sClient.Get(
			ctx,
			types.NamespacedName{
				Name: retrieved.Spec.IssuerRef.Name,
			},
			clusterIssuer,
		)).To(Succeed())
		Expect(clusterIssuer.Spec.CA.CRLDistributionPoints).To(Equal(retrieved.GetCRLDistributionPoint()))
	default:
		Fail("unexpected IssuerRef.Kind")
	}
}
