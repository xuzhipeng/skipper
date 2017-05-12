package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/zalando/skipper/eskip"
	"github.com/zalando/skipper/filters"
	"github.com/zalando/skipper/metrics"
	"github.com/zalando/skipper/routing"
)

const (
	proxyBufferSize = 8192
	proxyErrorFmt   = "proxy: %s"
	unknownRouteId  = "_unknownroute_"

	// The default value set for http.Transport.MaxIdleConnsPerHost.
	DefaultIdleConnsPerHost = 64

	// The default period at which the idle connections are forcibly
	// closed.
	DefaultCloseIdleConnsPeriod = 20 * time.Second
)

// Flags control the behavior of the proxy.
type Flags uint

const (
	FlagsNone Flags = 0

	// Insecure causes the proxy to ignore the verification of
	// the TLS certificates of the backend services.
	Insecure Flags = 1 << iota

	// PreserveOriginal indicates that filters require the
	// preserved original metadata of the request and the response.
	PreserveOriginal

	// PreserveHost indicates whether the outgoing request to the
	// backend should use by default the 'Host' header of the incoming
	// request, or the host part of the backend address, in case filters
	// don't change it.
	PreserveHost

	// Debug indicates that the current proxy instance will be used as a
	// debug proxy. Debug proxies don't forward the request to the
	// route backends, but they execute all filters, and return a
	// JSON document with the changes the filters make to the request
	// and with the approximate changes they would make to the
	// response.
	Debug
)

// Options are deprecated alias for Flags.
type Options Flags

const (
	OptionsNone             = Options(FlagsNone)
	OptionsInsecure         = Options(Insecure)
	OptionsPreserveOriginal = Options(PreserveOriginal)
	OptionsPreserveHost     = Options(PreserveHost)
	OptionsDebug            = Options(Debug)
)

// Proxy initialization options.
type Params struct {
	// The proxy expects a routing instance that is used to match
	// the incoming requests to routes.
	Routing *routing.Routing

	// Control flags. See the Flags values.
	Flags Flags

	// Same as net/http.Transport.MaxIdleConnsPerHost, but the default
	// is 64. This value supports scenarios with relatively few remote
	// hosts. When the routing table contains different hosts in the
	// range of hundreds, it is recommended to set this options to a
	// lower value.
	IdleConnectionsPerHost int

	// Defines the time period of how often the idle connections are
	// forcibly closed. The default is 12 seconds. When set to less than
	// 0, the proxy doesn't force closing the idle connections.
	CloseIdleConnsPeriod time.Duration

	// And optional list of priority routes to be used for matching
	// before the general lookup tree.
	PriorityRoutes []PriorityRoute

	// The Flush interval for copying upgraded connections
	FlushInterval time.Duration

	// Enable the expiremental upgrade protocol feature
	ExperimentalUpgrade bool
}

// When set, the proxy will skip the TLS verification on outgoing requests.
func (f Flags) Insecure() bool { return f&Insecure != 0 }

// When set, the filters will recieve an unmodified clone of the original
// incoming request and response.
func (f Flags) PreserveOriginal() bool { return f&(PreserveOriginal|Debug) != 0 }

// When set, the proxy will set the, by default, the Host header value
// of the outgoing requests to the one of the incoming request.
func (f Flags) PreserveHost() bool { return f&PreserveHost != 0 }

// When set, the proxy runs in debug mode.
func (f Flags) Debug() bool { return f&Debug != 0 }

// Priority routes are custom route implementations that are matched against
// each request before the routes in the general lookup tree.
type PriorityRoute interface {

	// If the request is matched, returns a route, otherwise nil.
	// Additionally it may return a parameter map used by the filters
	// in the route.
	Match(*http.Request) (*routing.Route, map[string]string)
}

type flusherWriter interface {
	http.Flusher
	io.Writer
}

// a byte buffer implementing the Closer interface
type bodyBuffer struct {
	*bytes.Buffer
}

// Proxy instances implement Skipper proxying functionality. For
// initializing, see the WithParams the constructor and Params.
type Proxy struct {
	routing             *routing.Routing
	roundTripper        *http.Transport
	priorityRoutes      []PriorityRoute
	flags               Flags
	metrics             *metrics.Metrics
	quit                chan struct{}
	flushInterval       time.Duration
	experimentalUpgrade bool
	maxLoops            int
}

type filterContext struct {
	responseWriter     http.ResponseWriter
	request            *http.Request
	response           *http.Response
	deprecatedServed   bool
	servedWithResponse bool // to support the deprecated way independently
	pathParams         map[string]string
	stateBag           map[string]interface{}
	originalRequest    *http.Request
	originalResponse   *http.Response
	backendURL         string
	outgoingHost       string
	loopCounter        int
}

func (sb bodyBuffer) Close() error {
	return nil
}

func copyHeader(to, from http.Header) {
	for k, v := range from {
		to[http.CanonicalHeaderKey(k)] = v
	}
}

func cloneHeader(h http.Header) http.Header {
	hh := make(http.Header)
	copyHeader(hh, h)
	return hh
}

// copies a stream with flushing on every successful read operation
// (similar to io.Copy but with flushing)
func copyStream(to flusherWriter, from io.Reader) error {
	b := make([]byte, proxyBufferSize)

	for {
		l, rerr := from.Read(b)
		if rerr != nil && rerr != io.EOF {
			return rerr
		}

		if l > 0 {
			_, werr := to.Write(b[:l])
			if werr != nil {
				return werr
			}

			to.Flush()
		}

		if rerr == io.EOF {
			return nil
		}
	}
}

// creates an outgoing http request to be forwarded to the route endpoint
// based on the augmented incoming request
func mapRequest(r *http.Request, rt *routing.Route, host string) (*http.Request, error) {
	u := r.URL
	u.Scheme = rt.Scheme
	u.Host = rt.Host

	body := r.Body
	if r.ContentLength == 0 {
		body = nil
	}

	rr, err := http.NewRequest(r.Method, u.String(), body)
	if err != nil {
		return nil, err
	}

	rr.Header = cloneHeader(r.Header)
	rr.Host = host

	// If there is basic auth configured int the URL we add them as headers
	if u.User != nil {
		up := u.User.String()
		upBase64 := base64.StdEncoding.EncodeToString([]byte(up))
		rr.Header.Add("Authorization", fmt.Sprintf("Basic %s", upBase64))
	}

	return rr, nil
}

// Deprecated, see WithParams and Params instead.
func New(r *routing.Routing, options Options, pr ...PriorityRoute) *Proxy {
	return WithParams(Params{
		Routing:              r,
		Flags:                Flags(options),
		PriorityRoutes:       pr,
		CloseIdleConnsPeriod: -time.Second})
}

// Creates a proxy with the provided parameters.
func WithParams(o Params) *Proxy {
	if o.IdleConnectionsPerHost <= 0 {
		o.IdleConnectionsPerHost = DefaultIdleConnsPerHost
	}

	if o.CloseIdleConnsPeriod == 0 {
		o.CloseIdleConnsPeriod = DefaultCloseIdleConnsPeriod
	}

	tr := &http.Transport{MaxIdleConnsPerHost: o.IdleConnectionsPerHost}
	quit := make(chan struct{})
	if o.CloseIdleConnsPeriod > 0 {
		go func() {
			for {
				select {
				case <-time.After(o.CloseIdleConnsPeriod):
					tr.CloseIdleConnections()
				case <-quit:
					return
				}
			}
		}()
	}

	if o.Flags.Insecure() {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	m := metrics.Default
	if o.Flags.Debug() {
		m = metrics.Void
	}

	return &Proxy{
		routing:             o.Routing,
		roundTripper:        tr,
		priorityRoutes:      o.PriorityRoutes,
		flags:               o.Flags,
		metrics:             m,
		quit:                quit,
		flushInterval:       o.FlushInterval,
		experimentalUpgrade: o.ExperimentalUpgrade}
}

// calls a function with recovering from panics and logging them
func tryCatch(p func(), onErr func(err interface{})) {
	defer func() {
		if err := recover(); err != nil {
			onErr(err)
		}
	}()

	p()
}

func newContext(
	w http.ResponseWriter,
	r *http.Request,
	preserveOriginal bool,
) *filterContext {

	c := &filterContext{
		responseWriter: w,
		request:        r,
		stateBag:       make(map[string]interface{}),
		outgoingHost:   r.Host,
	}

	if preserveOriginal {
		c.originalRequest = cloneRequestMetadata(r)
	}

	return c
}

func (c *filterContext) clone() *filterContext {
	var cc filterContext
	cc = *c
	return &cc
}

func cloneUrl(u *url.URL) *url.URL {
	uc := *u
	return &uc
}

func cloneRequestMetadata(r *http.Request) *http.Request {
	return &http.Request{
		Method:           r.Method,
		URL:              cloneUrl(r.URL),
		Proto:            r.Proto,
		ProtoMajor:       r.ProtoMajor,
		ProtoMinor:       r.ProtoMinor,
		Header:           cloneHeader(r.Header),
		Body:             &bodyBuffer{&bytes.Buffer{}},
		ContentLength:    r.ContentLength,
		TransferEncoding: r.TransferEncoding,
		Close:            r.Close,
		Host:             r.Host,
		RemoteAddr:       r.RemoteAddr,
		RequestURI:       r.RequestURI,
		TLS:              r.TLS}
}

func cloneResponseMetadata(r *http.Response) *http.Response {
	return &http.Response{
		Status:           r.Status,
		StatusCode:       r.StatusCode,
		Proto:            r.Proto,
		ProtoMajor:       r.ProtoMajor,
		ProtoMinor:       r.ProtoMinor,
		Header:           cloneHeader(r.Header),
		Body:             &bodyBuffer{&bytes.Buffer{}},
		ContentLength:    r.ContentLength,
		TransferEncoding: r.TransferEncoding,
		Close:            r.Close,
		Request:          r.Request,
		TLS:              r.TLS}
}

func (c *filterContext) ResponseWriter() http.ResponseWriter { return c.responseWriter }
func (c *filterContext) Request() *http.Request              { return c.request }
func (c *filterContext) Response() *http.Response            { return c.response }
func (c *filterContext) MarkServed()                         { c.deprecatedServed = true }
func (c *filterContext) Served() bool                        { return c.deprecatedServed || c.servedWithResponse }
func (c *filterContext) PathParam(key string) string         { return c.pathParams[key] }
func (c *filterContext) StateBag() map[string]interface{}    { return c.stateBag }
func (c *filterContext) BackendUrl() string                  { return c.backendURL }
func (c *filterContext) OriginalRequest() *http.Request      { return c.originalRequest }
func (c *filterContext) OriginalResponse() *http.Response    { return c.originalResponse }
func (c *filterContext) OutgoingHost() string                { return c.outgoingHost }
func (c *filterContext) SetOutgoingHost(h string)            { c.outgoingHost = h }

func (c *filterContext) incLoopCounter() {
	c.loopCounter++
}

func (c *filterContext) decLoopCounter() {
	c.loopCounter--
}

func mergeParams(to, from map[string]string) map[string]string {
	if to == nil {
		to = make(map[string]string)
	}

	for k, v := range from {
		to[k] = v
	}

	return to
}

func (c *filterContext) applyRoute(r *routing.Route, params map[string]string, preserveHost bool) {
	c.backendURL = r.Backend
	if !preserveHost {
		c.outgoingHost = r.Host
	}

	c.pathParams = mergeParams(c.pathParams, params)
}

func defaultBody() io.ReadCloser {
	return &bodyBuffer{&bytes.Buffer{}}
}

func defaultResponse(r *http.Request) *http.Response {
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Header:     make(http.Header),
		Body:       defaultBody(),
		Request:    r}
}

func (c *filterContext) Serve(r *http.Response) {
	r.Request = c.Request()

	if r.Header == nil {
		r.Header = make(http.Header)
	}

	if r.Body == nil {
		r.Body = defaultBody()
	}

	c.servedWithResponse = true
	c.response = r
}

func (c *filterContext) ensureDefaultResponse() {
	if c.response == nil {
		c.response = defaultResponse(c.request)
		return
	}

	if c.response.Header == nil {
		c.response.Header = make(http.Header)
	}

	if c.response.Body == nil {
		c.response.Body = defaultBody()
	}
}

func (c *filterContext) shuntedByFilters() bool {
	return c.deprecatedServed || c.servedWithResponse
}

func (c *filterContext) shouldServeResponse() bool {
	return c.loopCounter == 0 && !c.deprecatedServed
}

// applies all filters to a request
func (p *Proxy) applyFiltersToRequest(f []*routing.RouteFilter, ctx *filterContext) []*routing.RouteFilter {
	var start time.Time
	var filters = make([]*routing.RouteFilter, 0, len(f))
	for _, fi := range f {
		start = time.Now()
		tryCatch(func() { fi.Request(ctx) }, func(err interface{}) {
			log.Error("error while processing filters during request:", err)
		})

		p.metrics.MeasureFilterRequest(fi.Name, start)
		filters = append(filters, fi)
		if ctx.deprecatedServed || ctx.servedWithResponse {
			break
		}
	}
	return filters
}

// applies filters to a response in reverse order
func (p *Proxy) applyFiltersToResponse(filters []*routing.RouteFilter, ctx filters.FilterContext) {
	count := len(filters)
	var start time.Time
	for i, _ := range filters {
		fi := filters[count-1-i]
		start = time.Now()
		tryCatch(func() { fi.Response(ctx) }, func(err interface{}) {
			log.Error("error while processing filters during response:", err)
		})

		p.metrics.MeasureFilterResponse(fi.Name, start)
	}
}

// addBranding overwrites any existing `X-Powered-By` or `Server` header from headerMap
func addBranding(headerMap http.Header) {
	headerMap.Set("X-Powered-By", "Skipper")
	headerMap.Set("Server", "Skipper")
}

func (p *Proxy) lookupRoute(r *http.Request) (rt *routing.Route, params map[string]string) {
	for _, prt := range p.priorityRoutes {
		rt, params = prt.Match(r)
		if rt != nil {
			return rt, params
		}
	}

	return p.routing.Route(r)
}

// send a premature error response
func sendError(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
	addBranding(w.Header())
}

// TODO: verify where should the errors be hooked. Changing it should be a separate refactoring item.

// TODO: rename filterContext to context, store the route on the context

func (p *Proxy) makeUpgradeRequest(ctx *filterContext, route *routing.Route, req *http.Request) {
	// have to parse url again, because path is not be copied by mapRequest
	backendURL, err := url.Parse(route.Backend)
	if err != nil {
		log.Errorf("can not parse backend %s, caused by: %s", route.Backend, err)
		sendError(ctx.responseWriter, http.StatusBadGateway)
		return
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(backendURL)
	reverseProxy.FlushInterval = p.flushInterval
	upgradeProxy := upgradeProxy{
		backendAddr:     backendURL,
		reverseProxy:    reverseProxy,
		insecure:        p.flags.Insecure(),
		tlsClientConfig: p.roundTripper.TLSClientConfig,
	}

	upgradeProxy.serveHTTP(ctx.responseWriter, req)
	log.Debugf("Finished upgraded protocol %s session", getUpgradeRequest(ctx.request))

}

var errProxyCanceled = errors.New("proxy canceled")

func (p *Proxy) makeBackendRequest(ctx *filterContext, route *routing.Route) error {
	req, err := mapRequest(ctx.request, route, ctx.outgoingHost)
	if err != nil {
		log.Errorf("could not map backend request, caused by: %v", err)
		sendError(ctx.responseWriter, http.StatusInternalServerError)
		return errProxyCanceled
	}

	if p.experimentalUpgrade && isUpgradeRequest(req) {
		p.makeUpgradeRequest(ctx, route, req)
		// We are not owner of the connection anymore.
		return errProxyCanceled
	}

	response, err := p.roundTripper.RoundTrip(req)
	if err != nil {
		code := http.StatusInternalServerError
		if _, ok := err.(net.Error); ok {
			code = http.StatusServiceUnavailable
		}

		sendError(ctx.responseWriter, code)
		log.Error("error during backend roundtrip: ", err)
		return errProxyCanceled
	}

	ctx.response = response
	return nil
}

func (p *Proxy) do(ctx *filterContext) error {
	if ctx.loopCounter > p.maxLoops {
		ctx.ensureDefaultResponse()
		return nil
	}

	ctx.incLoopCounter()
	defer ctx.decLoopCounter()

	route, params := p.lookupRoute(ctx.request)
	if route == nil {
		ctx.ensureDefaultResponse()
		return nil
	}

	ctx.applyRoute(route, params, p.flags.PreserveHost())

	processedFilters := p.applyFiltersToRequest(route.Filters, ctx)

	if ctx.shuntedByFilters() {
		ctx.ensureDefaultResponse()
	} else if route.Shunt || route.BackendType == eskip.ShuntBackend {
		ctx.ensureDefaultResponse()
	} else if route.BackendType == eskip.LoopBackend {
		loopCTX := ctx.clone()
		if err := p.do(loopCTX); err != nil {
			return err
		}

		ctx.response = loopCTX.response
	} else {
		if err := p.makeBackendRequest(ctx, route); err != nil {
			return err
		}
	}

	if ctx.deprecatedServed {
		return nil
	}

	if p.flags.PreserveOriginal() {
		ctx.originalResponse = cloneResponseMetadata(ctx.response)
	}

	p.applyFiltersToResponse(processedFilters, ctx)
	return nil
}

func (p *Proxy) serveResponse(ctx *filterContext) {
	addBranding(ctx.response.Header)
	copyHeader(ctx.responseWriter.Header(), ctx.response.Header)
	ctx.responseWriter.WriteHeader(ctx.response.StatusCode)
	err := copyStream(ctx.responseWriter.(flusherWriter), ctx.response.Body)
	if err != nil {
		log.Error("error while copying the response stream", err)
	}
}

// http.Handler implementation
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(w, r, p.flags.PreserveOriginal())
	err := p.do(ctx)

	defer func() {
		if ctx.response != nil && ctx.response.Body != nil {
			ctx.response.Body.Close()
		}
	}()

	if err != nil {
		if err != errProxyCanceled {
			log.Error("error while proxying: ", err)
		}
	} else if ctx.shouldServeResponse() {
		p.serveResponse(ctx)
	}
}

// Close causes the proxy to stop closing idle
// connections and, currently, has no other effect.
// It's primary purpose is to support testing.
func (p *Proxy) Close() error {
	close(p.quit)
	return nil
}
