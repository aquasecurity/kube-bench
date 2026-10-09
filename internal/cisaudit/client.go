package cisaudit

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// APIClient uses explicit KUBECONFIG first, pod credentials second, and the
// standard local kubeconfig outside a pod. It never defaults to localhost:8080.
func APIClient() (Fetch, error) {
	config, err := loadConfig(clientcmd.NewDefaultClientConfigLoadingRules(), rest.InClusterConfig)
	if err != nil {
		return nil, err
	}
	return newAPIFetch(config)
}

func loadConfig(rules *clientcmd.ClientConfigLoadingRules, inCluster func() (*rest.Config, error)) (*rest.Config, error) {
	if os.Getenv("KUBECONFIG") == "" {
		config, err := inCluster()
		if err == nil {
			return config, nil
		}
		if err != rest.ErrNotInCluster {
			return nil, fmt.Errorf("load in-cluster credentials: %w", err)
		}
	}
	raw, err := rules.Load()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	if len(raw.Clusters) == 0 {
		return nil, fmt.Errorf("no Kubernetes configuration: provide KUBECONFIG or mount a pod service-account token and CA")
	}
	config, err := clientcmd.NewNonInteractiveClientConfig(*raw, raw.CurrentContext, &clientcmd.ConfigOverrides{}, rules).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig context: %w", err)
	}
	return config, nil
}

func newAPIFetch(config *rest.Config) (Fetch, error) {
	config = rest.CopyConfig(config)
	config.Timeout = 60 * time.Second
	client, err := rest.HTTPClientFor(config)
	if err != nil {
		return nil, fmt.Errorf("configure Kubernetes API transport: %w", err)
	}
	base, err := url.Parse(config.Host)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") {
		return nil, fmt.Errorf("invalid Kubernetes API server address")
	}
	// Do not follow redirects with service-account credentials.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return func(path string) ([]byte, error) {
		relative, err := url.Parse(path)
		if err != nil || relative.IsAbs() || relative.Host != "" || !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("invalid API resource path")
		}
		endpoint := *base
		endpoint.Path = strings.TrimRight(base.Path, "/") + relative.Path
		endpoint.RawQuery = relative.RawQuery
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "application/json")
		response, err := client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("API query %s failed: %w", path, err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			// Keep error reports short; do not echo credentials or arbitrary server bodies.
			return nil, fmt.Errorf("API query %s failed: HTTP %d %s", path, response.StatusCode, http.StatusText(response.StatusCode))
		}
		data, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("read API query %s: %w", path, err)
		}
		return data, nil
	}, nil
}
