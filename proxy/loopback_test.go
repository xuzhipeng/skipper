package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"testing"
)

func testLoopback(
	t *testing.T,
	routes string,
	params Params,
	expectedStatus int,
	expectedHeader http.Header,
) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Backend-Done", "true")
	}))

	routes = strings.Replace(routes, "$backend", backend.URL, -1)

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
			for i, rvi := range rv {
				if rvi == vi {
					rv = append(rv[:i], rv[i+1:]...)
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

func times(n int, f func()) {
	if n == 0 {
		return
	}

	f()
	times(n-1, f)
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

func TestLoopbackWithBackend(t *testing.T) {
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
			-> appendResponseHeader("X-Loop-Route-Done", "2")
			-> "$backend";
	`

	testLoopback(t, routes, Params{}, http.StatusOK, http.Header{
		"X-Entry-Route-Done": []string{"true"},
		"X-Loop-Route-Done":  []string{"1", "2"},
		"X-Backend-Done":     []string{"true"},
	})
}

func TestLoopbackReachLimit(t *testing.T) {
	routes := `
		entry: *
			-> appendResponseHeader("X-Entry-Route-Done", "true")
			-> setRequestHeader("X-Loop-Route", "1")
			-> <loopback>;

		loopRoute1: Header("X-Loop-Route", "1")
			-> appendResponseHeader("X-Loop-Route-Done", "1")
			-> <loopback>;
	`

	var done []string
	times(3, func() { done = append(done, "1") })

	testLoopback(t, routes, Params{MaxLoopbacks: 3}, http.StatusNotFound, http.Header{
		"X-Entry-Route-Done": []string{"true"},
		"X-Loop-Route-Done":  done,
	})
}

func TestLoopbackReachDefaultLimit(t *testing.T) {
	routes := `
		entry: *
			-> appendResponseHeader("X-Entry-Route-Done", "true")
			-> setRequestHeader("X-Loop-Route", "1")
			-> <loopback>;

		loopRoute1: Header("X-Loop-Route", "1")
			-> appendResponseHeader("X-Loop-Route-Done", "1")
			-> <loopback>;
	`

	var done []string
	times(DefaultMaxLoopbacks, func() { done = append(done, "1") })

	testLoopback(t, routes, Params{}, http.StatusNotFound, http.Header{
		"X-Entry-Route-Done": []string{"true"},
		"X-Loop-Route-Done":  done,
	})
}
