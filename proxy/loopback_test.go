package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"

	"testing"
)

func testLoopback(
	t *testing.T,
	routes string,
	params Params,
	expectedStatus int,
	expectedHeader http.Header,
) {
	p, err := newTestProxyWithFiltersAndParams(nil, routes, params)
	if err != nil {
		t.Error(err)
		return
	}

	defer p.close()

	u, err := url.ParseRequestURI("https://www.example.org/hello")
	if err != nil {
		t.Error(err)
		return
	}

	r := &http.Request{
		URL:    u,
		Method: "GET",
		Header: make(http.Header),
	}
	w := httptest.NewRecorder()

	p.proxy.ServeHTTP(w, r)

	if w.Code != expectedStatus {
		t.Error("failed to set status")
		return
	}

	for k, v := range expectedHeader {
		rv := w.Header()[k]
		if len(rv) != len(v) {
			t.Error("unexpected headers", k)
			return
		}

		for _, vi := range v {
			var found bool
			for _, rvi := range rv {
				if rvi == vi {
					found = true
					break
				}
			}

			if !found {
				t.Error("expected header not found", k, vi)
				return
			}
		}
	}
}

func TestLoopbackShunt(t *testing.T) {
	routes := `
		entry: *
			-> appendResponseHeader("X-Entry-Route-Done", "true")
			-> setRequestHeader("X-Loop-Route", "1")
			-> <loopback>;

		loopRoute1: Header("X-Loop-Route", "1")
			-> appendResponseHeader("X-Loop-Route-Done", "1")
			-> setRequestHeader("X-Loop-Route", "2")
			-> <loopback>;

		loopRoute2: Header("X-Loop-Route", "2")
			-> status(418)
			-> appendResponseHeader("X-Loop-Route-Done", "2")
			-> <shunt>;
	`

	testLoopback(t, routes, Params{}, http.StatusTeapot, http.Header{
		"X-Entry-Route-Done": []string{"true"},
		"X-Loop-Route-Done":  []string{"1", "2"},
	})
}
