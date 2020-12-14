package cmd

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
)

func TestLoadCertficate(t *testing.T) {
	tmp, err := ioutil.TempDir("", "TestFakeLoadCertficate")
	if err != nil {
		t.Fatalf("unable to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmp)

	goodCertFile, _ := ioutil.TempFile(tmp, "good-cert-*")
	_, _ = goodCertFile.Write([]byte(`-----BEGIN CERTIFICATE-----
MIICyDCCAbCgAwIBAgIBADANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwprdWJl
cm5ldGVzMB4XDTE5MTEwODAxNDAwMFoXDTI5MTEwNTAxNDAwMFowFTETMBEGA1UE
AxMKa3ViZXJuZXRlczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMn6
wjvhMc9e0MDwpQNhp8SPxmv1DsYJ4Btp1GeScIgKKDwppuoOmVizLiMNdV5+70yI
MgNfm/gwFRNDOtN3R7msfZDD5Dd1vI6qRTP21DFOGVdysFdwqJTs0nGcmfvZEOtw
9cjcsXrBi2Mg54v+X/pq2w51xajCGBt2+bpxJJ3WBiWqKYv0RQdNL0WZGm+V9BuP
pHRWPBeLxuCzt5K3Gx+1QDy8o6Y4sSRPssWC4RhD9Hs5/9eeGRyZslLs+AuqdDLQ
aziiSjHVtgCfRXE9nYVxaDIwTFuh+Q1IvtB36NRLyX47oya+BbX3PoCtSjA36RBb
tcJfulr3oNHnb2ZlfcUCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgKkMA8GA1UdEwEB
/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAAeQDkbM6DilLkIVQDyxauETgJDV
2AaVzYaAgDApQGAoYV6WIY7Exk4TlmLeKQjWt2s/GtthQWuzUDKTcEvWcG6gNdXk
gzuCRRDMGu25NtG3m67w4e2RzW8Z/lzvbfyJZGoV2c6dN+yP9/Pw2MXlrnMWugd1
jLv3UYZRHMpuNS8BJU74BuVzVPHd55RAl+bV8yemdZJ7pPzMvGbZ7zRXWODTDlge
CQb9lY+jYErisH8Sq7uABFPvi7RaTh8SS7V7OxqHZvmttNTdZs4TIkk45JK7Y+Xq
FAjB57z2NcIgJuVpQnGRYtr/JcH2Qdsq8bLtXaojUIWOOqoTDRLYozdMOOQ=
-----END CERTIFICATE-----`))
	badCertFile, _ := ioutil.TempFile(tmp, "bad-cert-*")

	cases := []struct {
		file string
		fail bool
	}{
		{
			file: "missing cert file",
			fail: true,
		},
		{
			file: badCertFile.Name(),
			fail: true,
		},
		{
			file: goodCertFile.Name(),
			fail: false,
		},
	}

	for id, c := range cases {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			tlsCert, err := loadCertficate(c.file)
			if !c.fail {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}

				if tlsCert == nil {
					t.Errorf("missing returned TLS Certificate")
				}
			} else {
				if err == nil {
					t.Errorf("Expected error")
				}
			}

		})
	}
}

func TestGetWebData(t *testing.T) {
	okfn := func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, `{
			"major": "1",
			"minor": "15"}`)
	}
	errfn := func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
	}
	token := "dummyToken"
	var tlsCert tls.Certificate

	cases := []struct {
		fn   http.HandlerFunc
		fail bool
	}{
		{
			fn:   okfn,
			fail: false,
		},
		{
			fn:   errfn,
			fail: true,
		},
	}

	for id, c := range cases {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			ts := httptest.NewServer(c.fn)
			defer ts.Close()
			data, err := getWebData(ts.URL, token, &tlsCert)
			if !c.fail {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}

				if len(data) == 0 {
					t.Errorf("missing data")
				}
			} else {
				if err == nil {
					t.Errorf("Expected error")
				}
			}
		})
	}

}
func TestGetWebDataWithRetry(t *testing.T) {
	okfn := func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, `{
			"major": "1",
			"minor": "15"}`)
	}
	errfn := func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
	}
	token := "dummyToken"
	var tlsCert tls.Certificate

	cases := []struct {
		fn   http.HandlerFunc
		fail bool
	}{
		{
			fn:   okfn,
			fail: false,
		},
		{
			fn:   errfn,
			fail: true,
		},
	}

	for id, c := range cases {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			ts := httptest.NewServer(c.fn)
			defer ts.Close()
			data, err := getWebDataWithRetry(ts.URL, token, &tlsCert)
			if !c.fail {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}

				if len(data) == 0 {
					t.Errorf("missing data")
				}
			} else {
				if err == nil {
					t.Errorf("Expected error")
				}
			}
		})
	}

}
func TestExtractVersion(t *testing.T) {
	okJSON := []byte(`{
	"major": "1",
	"minor": "15",
	"gitVersion": "v1.15.3",
	"gitCommit": "2d3c76f9091b6bec110a5e63777c332469e0cba2",
	"gitTreeState": "clean",
	"buildDate": "2019-08-20T18:57:36Z",
	"goVersion": "go1.12.9",
	"compiler": "gc",
	"platform": "linux/amd64"
    }`)

	invalidJSON := []byte(`{
	"major": "1",
	"minor": "15",
	"gitVersion": "v1.15.3",
	"gitCommit": "2d3c76f9091b6bec110a5e63777c332469e0cba2",
	"gitTreeState": "clean",`)

	cases := []struct {
		data        []byte
		fail        bool
		expectedVer string
	}{
		{
			data:        okJSON,
			fail:        false,
			expectedVer: "1.15",
		},
		{
			data: invalidJSON,
			fail: true,
		},
	}

	for id, c := range cases {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			ver, err := extractVersion(c.data)
			if !c.fail {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if c.expectedVer != ver.BaseVersion() {
					t.Errorf("Expected %q but Got %q", c.expectedVer, ver)
				}
			} else {
				if err == nil {
					t.Errorf("Expected error")
				}
			}
		})
	}
}

func TestGetKubernetesURL(t *testing.T) {

	resetEnvs := func() {
		os.Unsetenv("KUBE_BENCH_K8S_ENV")
		os.Unsetenv("KUBERNETES_SERVICE_HOST")
		os.Unsetenv("KUBERNETES_SERVICE_PORT_HTTPS")
	}

	setEnvs := func() {
		os.Setenv("KUBE_BENCH_K8S_ENV", "1")
		os.Setenv("KUBERNETES_SERVICE_HOST", "testHostServer")
		os.Setenv("KUBERNETES_SERVICE_PORT_HTTPS", "443")
	}

	cases := []struct {
		useDefault bool
		expected   string
	}{
		{
			useDefault: true,
			expected:   "https://kubernetes.default.svc/version",
		},
		{
			useDefault: false,
			expected:   "https://testHostServer:443/version",
		},
	}
	for id, c := range cases {
		t.Run(strconv.Itoa(id), func(t *testing.T) {
			resetEnvs()
			defer resetEnvs()
			if !c.useDefault {
				setEnvs()
			}
			k8sURL := getKubernetesURL()

			if !c.useDefault {
				if k8sURL != c.expected {
					t.Errorf("Expected %q but Got %q", k8sURL, c.expected)
				}
			} else {
				if k8sURL != c.expected {
					t.Errorf("Expected %q but Got %q", k8sURL, c.expected)
				}
			}
		})
	}

}
