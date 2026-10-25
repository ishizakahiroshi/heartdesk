// Package httpx exposes the shared bounded HTTP client helpers.
package httpx

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"time"

	shared "github.com/ishizakahiroshi/heartdesk/internal/httpx"
)

type Options = shared.Options

const DefaultMaxBodyBytes = shared.DefaultMaxBodyBytes

func Client(timeout time.Duration, tlsConfig *tls.Config) *http.Client {
	return shared.Client(timeout, tlsConfig)
}

func Get(ctx context.Context, url string, options Options) (int, []byte, error) {
	return shared.Get(ctx, url, options)
}

func PostJSON(ctx context.Context, url string, payload any, options Options) (int, []byte, error) {
	return shared.PostJSON(ctx, url, payload, options)
}

func Do(ctx context.Context, method, url string, body io.Reader, options Options) (int, []byte, error) {
	return shared.Do(ctx, method, url, body, options)
}

func GetJSON(ctx context.Context, url string, out any, options Options) error {
	return shared.GetJSON(ctx, url, out, options)
}
