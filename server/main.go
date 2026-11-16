// Command webssh-gw serves the browser SSH client and acts as a dumb
// WebSocket<->TCP byte relay. It does NOT speak SSH: all SSH crypto happens
// in the browser (the wasm client), so neither this relay nor the corporate
// MITM proxy ever sees SSH plaintext.
//
// Access control is a gate token in front of the whole thing. Once a client
// holds a valid session cookie it may open a WebSocket to ANY host:port.
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"flag"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// buildTime is set via -ldflags "-X main.buildTime=..." (see Makefile and
// Dockerfile); a plain `go build` with no flags leaves it at "unknown".
var buildTime = "unknown"

var (
	configPath     = flag.String("config", "webssh-gw.conf", "path to a `key: value` config file; config keys match flag names (e.g. \"cookie-secret: ...\"), and any flag given on the command line overrides the matching config value")
	listen         = flag.String("listen", ":8443", "listen address")
	certFile       = flag.String("cert", "", "TLS certificate (leave empty if a TLS-terminating proxy/nginx sits in front)")
	keyFile        = flag.String("key", "", "TLS key")
	webDir         = flag.String("web", "./web", "static web directory")
	tokensCSV      = flag.String("tokens", "", "comma-separated gate tokens (use high-entropy values; visible to a MITM proxy)")
	secret         = flag.String("cookie-secret", "", "HMAC secret for the session cookie (required)")
	cookieTTL      = flag.Duration("cookie-ttl", 12*time.Hour, "session lifetime")
	dialTO         = flag.Duration("dial-timeout", 15*time.Second, "TCP dial timeout to the SSH target")
	secure         = flag.Bool("secure-cookie", true, "set the Secure flag on the session cookie (disable only for plain-HTTP testing)")
	basePathIn     = flag.String("base-path", "", "URL path prefix this gateway is mounted under behind the reverse proxy, e.g. /ssh to host it at example.com/ssh instead of its own subdomain (leave empty for root)")
	defaultUser    = flag.String("default-user", "", "default value pre-filled in the web UI's user field")
	defaultPort    = flag.String("default-port", "22", "default value pre-filled in the web UI's port field")
	staticCacheTTL = flag.Duration("static-cache-ttl", 5*time.Minute, "browser Cache-Control max-age for static assets (app.js, xterm.js, main.wasm, ...); index.html itself is never cached, since it's templated per request")
)

// basePath is *basePathIn normalized to either "" (root) or a leading-slash,
// no-trailing-slash prefix (e.g. "/ssh"). Set once in main before the mux is
// built; handlers read it directly, same as the other flag-backed settings.
var basePath string

func normalizeBasePath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// loadConfigFile reads simple "key: value" lines, skipping blank lines and
// '#' comments (full-line or trailing after a value). Values may be wrapped
// in quotes, which protects a value containing '#' from comment-stripping.
func loadConfigFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		val := strings.TrimSpace(line[i+1:])
		if !strings.HasPrefix(val, `"`) && !strings.HasPrefix(val, `'`) {
			if j := strings.Index(val, "#"); j >= 0 {
				val = strings.TrimSpace(val[:j])
			}
		}
		val = strings.Trim(val, `"'`)
		m[key] = val
	}
	return m, sc.Err()
}

// envKey maps a flag name to its environment variable, e.g. "cookie-secret"
// -> "WEBSSH_COOKIE_SECRET". The prefix avoids colliding with unrelated vars
// a container might already have set (a flag as generic as "key" or "web"
// would otherwise be an easy accidental collision).
func envKey(flagName string) string {
	return "WEBSSH_" + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// loadConfig layers settings from lowest to highest precedence: each flag's
// own default, the config file, environment variables (WEBSSH_<FLAG_NAME>),
// then any flag explicitly given on the command line, which always wins.
// Config/env keys are just the flag names, so this applies generically via
// each flag's own Value.Set (which already knows how to parse
// strings/durations/bools).
func loadConfig() {
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	// WEBSSH_CONFIG may redirect the config file path itself, unless -config
	// was given explicitly on the command line.
	configFromEnv := false
	if !explicit["config"] {
		if v, ok := os.LookupEnv(envKey("config")); ok {
			*configPath = v
			configFromEnv = true
		}
	}

	cfg, err := loadConfigFile(*configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Fatalf("reading config file %s: %v", *configPath, err)
		}
		if explicit["config"] || configFromEnv {
			log.Fatalf("config file %s not found", *configPath)
		}
		cfg = map[string]string{}
	}

	// Layer 1: config file.
	flag.VisitAll(func(f *flag.Flag) {
		if f.Name == "config" || explicit[f.Name] {
			return
		}
		if v, ok := cfg[f.Name]; ok {
			if err := f.Value.Set(v); err != nil {
				log.Fatalf("config: %s: %v", f.Name, err)
			}
		}
	})

	// Layer 2: environment variables, overriding the file but still losing
	// to an explicit command-line flag.
	flag.VisitAll(func(f *flag.Flag) {
		if f.Name == "config" || explicit[f.Name] {
			return
		}
		if v, ok := os.LookupEnv(envKey(f.Name)); ok {
			if err := f.Value.Set(v); err != nil {
				log.Fatalf("env %s: %v", envKey(f.Name), err)
			}
		}
	})
}

var tokenList []string

var upgrader = websocket.Upgrader{
	ReadBufferSize:  32 * 1024,
	WriteBufferSize: 32 * 1024,
	// The app is same-origin; the gate cookie is the real control. If you want
	// belt-and-suspenders, verify r.Header.Get("Origin") against your host here.
	CheckOrigin: func(r *http.Request) bool { return true },
}

const cookieName = "webssh_sess"

func sign(msg string) string {
	m := hmac.New(sha256.New, []byte(*secret))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

func makeCookieValue(exp int64) string {
	msg := strconv.FormatInt(exp, 10)
	return msg + "|" + sign(msg)
}

func validCookie(v string) bool {
	parts := strings.SplitN(v, "|", 2)
	if len(parts) != 2 {
		return false
	}
	if !hmac.Equal([]byte(parts[1]), []byte(sign(parts[0]))) {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix() < exp
}

func authed(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	return validCookie(c.Value)
}

func tokenOK(t string) bool {
	ok := false
	for _, x := range tokenList {
		if subtle.ConstantTimeCompare([]byte(x), []byte(t)) == 1 {
			ok = true
		}
	}
	return ok
}

const loginPage = `<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Gateway</title>
<style>body{font:15px system-ui;background:#111;color:#eee;display:grid;place-items:center;height:100vh;margin:0}
form{display:flex;gap:8px;flex-direction:column;width:280px}
input{padding:10px;border-radius:6px;border:1px solid #444;background:#1c1c1c;color:#eee}
button{padding:10px;border:0;border-radius:6px;background:#3b82f6;color:#fff;cursor:pointer}
.err{color:#f87171;min-height:1.2em}</style>
<form method=post action="%s">
<h3>Gateway access</h3>
<div class=err>%s</div>
<input type=password name=token placeholder="Access token" autofocus>
<button>Enter</button>
</form>`

// cookiePath is the Set-Cookie Path attribute: basePath itself (so the
// cookie is scoped to this mount point and its subpaths), or "/" at root.
func cookiePath() string {
	if basePath == "" {
		return "/"
	}
	return basePath
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, loginPage, basePath+"/login", "")
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !tokenOK(r.PostForm.Get("token")) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, loginPage, basePath+"/login", "Invalid token")
		return
	}
	exp := time.Now().Add(*cookieTTL).Unix()
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    makeCookieValue(exp),
		Path:     cookiePath(),
		HttpOnly: true,
		Secure:   *secure,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(exp, 0),
	})
	http.Redirect(w, r, basePath+"/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: cookiePath(), MaxAge: -1})
	http.Redirect(w, r, basePath+"/login", http.StatusSeeOther)
}

func validTarget(host, port string) (string, bool) {
	if host == "" || strings.ContainsAny(host, " \t\r\n\x00") {
		return "", false
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", false
	}
	return net.JoinHostPort(host, port), true
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	if !authed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	target, ok := validTarget(r.URL.Query().Get("host"), r.URL.Query().Get("port"))
	if !ok {
		http.Error(w, "bad target", http.StatusBadRequest)
		return
	}

	// Dial the SSH target BEFORE upgrading, so a dial failure is a clean HTTP error.
	tcp, err := net.DialTimeout("tcp", target, *dialTO)
	if err != nil {
		http.Error(w, "dial: "+err.Error(), http.StatusBadGateway)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		tcp.Close()
		return
	}
	log.Printf("relay open: %s -> %s", r.RemoteAddr, target)

	done := make(chan struct{}, 2)

	// ws -> tcp
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if _, err := tcp.Write(data); err != nil {
				return
			}
		}
	}()

	// tcp -> ws
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := tcp.Read(buf)
			if n > 0 {
				if werr := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
	tcp.Close()
	conn.Close()
	<-done
	log.Printf("relay close: %s -> %s", r.RemoteAddr, target)
}

// indexHandler intercepts the mounted root ("/" after StripPrefix) to inject
// the configured default-user/default-port into index.html; every other
// path (app.js, xterm.js, main.wasm, ...) falls through to the plain static
// file server untouched.
func indexHandler(fileServer http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			// Pure static library/wasm code, identical for every session —
			// safe, and worth letting the browser cache for a while so it
			// doesn't re-fetch a multi-MB wasm binary on every page load.
			w.Header().Set("Cache-Control", fmt.Sprintf("private, max-age=%d", int((*staticCacheTTL).Seconds())))
			fileServer.ServeHTTP(w, r)
			return
		}
		// index.html is templated per request (default-user/default-port)
		// and small, so there's no real cost to never caching it.
		w.Header().Set("Cache-Control", "no-store")
		b, err := os.ReadFile(filepath.Join(*webDir, "index.html"))
		if err != nil {
			http.Error(w, "index.html: "+err.Error(), http.StatusInternalServerError)
			return
		}
		page := strings.NewReplacer(
			"{{DEFAULT_USER}}", html.EscapeString(*defaultUser),
			"{{DEFAULT_PORT}}", html.EscapeString(*defaultPort),
		).Replace(string(b))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(page))
	})
}

func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			http.Redirect(w, r, basePath+"/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	flag.Parse()
	log.Printf("webssh-gw build %s", buildTime)
	loadConfig()
	if *secret == "" {
		log.Fatal("cookie-secret is required (set \"cookie-secret: ...\" in the config file, or pass -cookie-secret; e.g. output of: openssl rand -hex 32)")
	}
	for _, t := range strings.Split(*tokensCSV, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tokenList = append(tokenList, t)
		}
	}
	if len(tokenList) == 0 {
		log.Fatal("at least one gate token is required (set \"tokens: ...\" in the config file, or pass -tokens)")
	}
	basePath = normalizeBasePath(*basePathIn)

	mux := http.NewServeMux()
	mux.HandleFunc(basePath+"/login", loginHandler)
	mux.HandleFunc(basePath+"/logout", logoutHandler)
	mux.HandleFunc(basePath+"/ws", wsHandler)
	fileServer := http.FileServer(http.Dir(*webDir))
	mux.Handle(basePath+"/", requireAuth(http.StripPrefix(basePath, indexHandler(fileServer))))

	srv := &http.Server{
		Addr:         *listen,
		Handler:      mux,
		ReadTimeout:  0, // long-lived upgrades
		WriteTimeout: 0,
	}

	if *certFile != "" && *keyFile != "" {
		log.Printf("listening (TLS) on %s", *listen)
		log.Fatal(srv.ListenAndServeTLS(*certFile, *keyFile))
	}
	log.Printf("listening (plain HTTP — expect a TLS proxy in front) on %s", *listen)
	log.Fatal(srv.ListenAndServe())
}
