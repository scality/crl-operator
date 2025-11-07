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
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	crloperatorv1alpha1 "github.com/scality/crl-operator/api/v1alpha1"
	"github.com/scality/crl-operator/internal/controller"
	// +kubebuilder:scaffold:imports
)

const (
	certManagerNamespace = "cert-manager"

	caKeyPem = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCrc62n/+wkhl1e
s20//KOB8Ce1ZiTUOnmJ40YiH05bgNyN4myjYxLASq+pmp4eVUqgEOUWU1ESPzwv
M+ZkaaHv77xXWh/pQgdaaTmSJsZf6PQAitNR1/zR/GjZfgGAHXxF3+d2t8MYwG9i
3q+Vh0ERKTaK89PYhqvoGiyxpDZT06QxLTHuR0RP12FfPvFREL0B5qp+7CAyoWbG
kDAWEl2HSVTOnMeS1zwJdgXElKxh0c6ABuOU6QIInQ+eWzz8HqusweruseG8AI9x
j6sL+etQH8JzQ0ewl10v5bA5mwMIa8aILBCKrAsA6YCtIThu/dh/8lCaGfq+Xsbh
4gxsYJy1AgMBAAECggEAB+H9LCS28Y+gmlqLMtka7BNObWeBWPqenOmEpMv7WSH/
F0zqQXGBgAgkXxq7RgTA4MQgwZqEtzSOFVOAYRcpjrO0h/BJAvtPWueh8dIeO8mk
8k4aXNXJNh8HSRH4irCQW/wT6HWWyZFgwv3JuokUmO/j+0EuTnMT/fYPc6lrpVtE
j2LSfw6JCuLksYxui+J7zI94vROS8HWY/ZVyktmL81Q47y9yC9uNI/bpXzFrLWLA
qAfTE99hZfO2bBWe0AWMcadpDWap9wvk3TJSa6L8xOr8gRp1FbQzM1TFy5K+hFnm
NZEor9Z5FSQ7nYni8jBK+ywFaS9RQfYOLyNHyMmaIQKBgQDf8k6ItA9N0rFoxf6G
BPoqSlVDOGyxmkFmN6xHygeFpKho8A1yHZdeIedtuUdENEpbnlm6U3ulwrRr687X
V03nn7sos3HG1TrTnh4wi/Zxt/+TcR5qUmWHa2bYuFtSWlG7RV7fX+YBz8yDDJkV
43Fr5vV60tzHuEgrEh/aNFDUUQKBgQDD/eYwpoa9tq+oKQIbUpIpKgPZGqjysRTJ
weZtvqEvAjR9TRqJNzS1dkWgdeOOpzoL1CtYt7IZSCaZt7o2sOuEYlbNYJYYsFMh
MLMr28dYWrv3GMZqShsLoT06OlTvz89Q7m7OyH00B89QpyFVh3bbr7bglD5PBd0M
vGP+7OjdJQKBgQCCMCftmtemw0x1f1zW5n/UJABrIps1qFpKpSTXWyCCVdW9o4f9
hixgAc+7XtGKWee8WVMKWcvw8j7W2nAVieB1Pcuc/qyvDXi0WyBr0oIDXBcMzN8E
qj/xuMNCS/Jy7qTC/LIJo4NgHEBlEubP7bgbJVoh/AFzbbMursurm2w98QKBgDlU
9Vg37mRio2G6lT4u2kimXLfOf6t2t5EJYoGp6PaaW4Zn3qJS/t0yOs3kjmt1aZp6
Ny/dlICmxXvj7dn/yPVR2vh7D40rTzX/S/pBcT/cUu3GVoxTHzQ4t3NoCt6X2Jph
FRLyPQXSXwfFzA977/31mbZ6RvvQyEfoeAvje37tAoGBAI0myzA1fKF9K0tlWYzV
Csy3pOoSLXv+eaKixOuqVWQYjaXQWGKxY0hl4nuHsh9lHVa/JBETn6O6vKdpAAsY
2cvph0eTThY7L6y1i0qobbD+f1e9AMzlU7n0x6XuqNaSe0Clnu2o8VZ7zt4d+zBE
EZ1JXNWdFMRmhUDeQwcfTNlE
-----END PRIVATE KEY-----`
	caCrtPem = `-----BEGIN CERTIFICATE-----
MIIDojCCAoqgAwIBAgIUVZMAZoG4MAmmYCREGR6B9L3CnSswDQYJKoZIhvcNAQEL
BQAwPDELMAkGA1UEBhMCRlIxFzAVBgNVBAoMDk1vbiBFbnRyZXByaXNlMRQwEgYD
VQQDDAtNYSBTdXBlciBDQTAeFw0yNTExMDMxNzE0NDRaFw0zNTExMDExNzE0NDRa
MDwxCzAJBgNVBAYTAkZSMRcwFQYDVQQKDA5Nb24gRW50cmVwcmlzZTEUMBIGA1UE
AwwLTWEgU3VwZXIgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCr
c62n/+wkhl1es20//KOB8Ce1ZiTUOnmJ40YiH05bgNyN4myjYxLASq+pmp4eVUqg
EOUWU1ESPzwvM+ZkaaHv77xXWh/pQgdaaTmSJsZf6PQAitNR1/zR/GjZfgGAHXxF
3+d2t8MYwG9i3q+Vh0ERKTaK89PYhqvoGiyxpDZT06QxLTHuR0RP12FfPvFREL0B
5qp+7CAyoWbGkDAWEl2HSVTOnMeS1zwJdgXElKxh0c6ABuOU6QIInQ+eWzz8Hqus
weruseG8AI9xj6sL+etQH8JzQ0ewl10v5bA5mwMIa8aILBCKrAsA6YCtIThu/dh/
8lCaGfq+Xsbh4gxsYJy1AgMBAAGjgZswgZgwHQYDVR0OBBYEFGr9A0Zqcirk9vvE
Voq7MQ9OnKPGMB8GA1UdIwQYMBaAFGr9A0Zqcirk9vvEVoq7MQ9OnKPGMA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMDUGA1UdHwQuMCwwKqAooCaGJGh0
dHA6Ly9jcmwubW9uLWRvbWFpbmUuY29tL21hLWNhLmNybDANBgkqhkiG9w0BAQsF
AAOCAQEAX8c4XgK0tg+QLyPM/kLrz2h53WhEa+z+7izW6pqIR3YUFzkUycLe/QVJ
y2n3W/tUbsrLpNP6dmfkm8NkjN7ZGskPyKYQQcXqrJtjIo+r63rDiU1IJhe07DjE
rd3247MUw1bfp0XPPWb7my8VXsqJoeC7PwyAaX6suoxodIEYJRiXRpJexYYwrHqQ
n55blja5iPPo57dS/T104wnltGs5/K6IEfOlkh7nS3W6ARem3f+7ZSHRiHOmX24U
w0dqPg3kDiskjn2q+XUt4IKyPYDTdz14p9EwKW+cHkarJdkZyYzbm8219YD4wQF9
nhNoSJevD/qFbmZF6z6QTxUbDXLHEw==
-----END CERTIFICATE-----`
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	ctx       context.Context
	cancel    context.CancelFunc
	testEnv   *envtest.Environment
	cfg       *rest.Config
	k8sClient client.Client
	caCert    *x509.Certificate
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())

	var err error
	err = crloperatorv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())
	err = cmv1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd", "bases"),
			filepath.Join("..", "..", "testdata", "crds"),
		},
		ErrorIfCRDPathMissing: true,
	}

	// Retrieve the first found binary directory to allow running tests from IDEs
	if getFirstFoundEnvTestBinaryDir() != "" {
		testEnv.BinaryAssetsDirectory = getFirstFoundEnvTestBinaryDir()
	}

	// cfg is defined in this file globally.
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	Expect(err).ToNot(HaveOccurred())

	// Create default cert-manager namespace
	Expect(k8sClient.Create(
		ctx,
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: certManagerNamespace,
			},
		},
	)).To(Succeed())

	// Create default CA secret
	Expect(k8sClient.Create(
		ctx,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ca-key-pair",
				Namespace: certManagerNamespace,
			},
			Data: map[string][]byte{
				"tls.key": []byte(caKeyPem),
				"tls.crt": []byte(caCrtPem),
			},
			Type: corev1.SecretTypeTLS,
		},
	)).To(Succeed())

	// Parse CA cert
	certBlock, _ := pem.Decode([]byte(caCrtPem))
	Expect(certBlock).ToNot(BeNil())
	Expect(certBlock.Type).To(Equal("CERTIFICATE"))
	caCert, err = x509.ParseCertificate(certBlock.Bytes)
	Expect(err).ToNot(HaveOccurred())

	// Start the controller
	err = (&controller.ManagedCRLReconciler{
		Client:               k8sManager.GetClient(),
		Scheme:               k8sManager.GetScheme(),
		CertManagerNamespace: certManagerNamespace,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = k8sManager.GetFieldIndexer().IndexField(
		context.Background(),
		&crloperatorv1alpha1.ManagedCRL{},
		"IssuerRef",
		func(rawObj client.Object) []string {
			mcrl := rawObj.(*crloperatorv1alpha1.ManagedCRL)
			var indexKeys []string
			switch mcrl.Spec.IssuerRef.Kind {
			case "Issuer": // nolint:goconst // "Issuer" string is clearer
				indexKeys = append(indexKeys, fmt.Sprintf("Issuer/%s/%s", mcrl.Namespace, mcrl.Spec.IssuerRef.Name))
			case "ClusterIssuer": // nolint:goconst // "ClusterIssuer" string is clearer
				indexKeys = append(indexKeys, fmt.Sprintf("ClusterIssuer/%s", mcrl.Spec.IssuerRef.Name))
			default:
				return nil
			}

			// Add a reference to the Secret containing the CA certificate and private key
			// used to sign the CRL.
			if mcrl.Status.ObservedCASecretRef != nil {
				indexKeys = append(
					indexKeys,
					fmt.Sprintf("Secret/%s/%s", mcrl.Status.ObservedCASecretRef.Namespace, mcrl.Status.ObservedCASecretRef.Name),
				)
			}

			return indexKeys
		},
	)
	Expect(err).ToNot(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		err = k8sManager.Start(ctx)
		Expect(err).ToNot(HaveOccurred())
	}()
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	cancel()
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

// getFirstFoundEnvTestBinaryDir locates the first binary in the specified path.
// ENVTEST-based tests depend on specific binaries, usually located in paths set by
// controller-runtime. When running tests directly (e.g., via an IDE) without using
// Makefile targets, the 'BinaryAssetsDirectory' must be explicitly configured.
//
// This function streamlines the process by finding the required binaries, similar to
// setting the 'KUBEBUILDER_ASSETS' environment variable. To ensure the binaries are
// properly set up, run 'make setup-envtest' beforehand.
func getFirstFoundEnvTestBinaryDir() string {
	basePath := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(basePath)
	if err != nil {
		logf.Log.Error(err, "Failed to read directory", "path", basePath)
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(basePath, entry.Name())
		}
	}
	return ""
}
