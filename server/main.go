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
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"sync"
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
	scrollback     = flag.Int("scrollback", 10000, "number of terminal lines xterm.js keeps in its scrollback buffer")
	resumeGrace    = flag.Duration("resume-grace", 2*time.Hour, "how long a dropped browser connection may reattach to its still-running SSH session before the relay gives up and closes it")
	resumeBufferMB = flag.Int64("resume-buffer-mb", 32, "per-session replay buffer size, in MB, for resuming a dropped connection; if a session's output exceeds this while disconnected, resuming becomes impossible and reconnecting requires a fresh login")
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

// WebSocket keepalive timing: ping every 30s, comfortably under most
// corporate proxies' idle-connection timeouts; allow 60s (two missed pings)
// before treating a non-responding browser as gone.
const (
	pingInterval = 30 * time.Second
	pongWait     = 60 * time.Second
	writeWait    = 10 * time.Second
)

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

// ---- resumable sessions ---------------------------------------------------
//
// SSH has no session-resumption of its own (unlike TLS): any lost or
// duplicated byte on the wire fails its per-packet MAC and kills the whole
// connection. So reattaching a fresh browser-side WebSocket to a still-open
// SSH session only works if it's byte-perfect — this is a small reliable-
// delivery layer under SSH, built specifically for that, not a best-effort
// "try to keep going" shim.
//
// Each session has exactly one long-lived goroutine (runDownload) covering
// its whole lifetime, continuously reading the SSH target's TCP connection
// (assumed stable; the caller decides the browser-side hop is the weak
// link) and keeping a bounded rolling buffer of the most recent bytes sent
// toward the browser, so a reattach can replay whatever tail the browser is
// missing. The upload direction (browser keystrokes toward the target)
// needs no server-side buffer: the session just tracks how many bytes it
// has confirmed receiving, and hands that count to a reattaching client,
// which is responsible for its own retransmit log.
//
// At most one WebSocket is attached to a session at a time; attachID is
// bumped on every (re)attach so a goroutine tied to a superseded
// attachment recognizes it's stale and stops touching shared state.

type session struct {
	key string
	tcp net.Conn

	mu              sync.Mutex
	sentToBrowser   int64 // cumulative bytes written toward the browser
	recvFromBrowser int64 // cumulative bytes received from the browser (== forwarded to tcp)
	buf             []byte
	bufStart        int64 // absolute offset of buf[0]
	ws              *websocket.Conn
	attachID        uint64
	graceTimer      *time.Timer
	finalized       bool
}

var (
	sessionsMu sync.Mutex
	sessions   = map[string]*session{}
)

func newSessionKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// attach validates replayFrom and bumps attachID, returning what the
// caller needs to send its own handshake frames. It deliberately does NOT
// yet publish conn as s.ws — see publishAttach.
func (s *session) attach(replayFrom int64) (replayTail []byte, recvFromBrowser int64, attachID uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finalized {
		return nil, 0, 0, errors.New("session already finalized")
	}
	if replayFrom < s.bufStart || replayFrom > s.sentToBrowser {
		return nil, 0, 0, fmt.Errorf("requested offset %d outside retained range [%d,%d]", replayFrom, s.bufStart, s.sentToBrowser)
	}
	if s.graceTimer != nil {
		s.graceTimer.Stop()
		s.graceTimer = nil
	}
	tail := append([]byte(nil), s.buf[replayFrom-s.bufStart:]...)
	s.attachID++
	return tail, s.recvFromBrowser, s.attachID, nil
}

// publishAttach makes conn visible to the session's permanent download
// goroutine as the current live connection to write to. This must only
// happen after the caller has finished writing its own handshake frames
// (session key, replay tail) to conn: gorilla/websocket requires ordinary
// WriteMessage calls on one connection to be serialized (unlike
// WriteControl, its one documented exception), so publishing conn any
// earlier would let the download goroutine's writes race with the
// handshake's — which in practice corrupts the WebSocket framing on the
// wire rather than panicking, making it a nasty one to debug blind.
func (s *session) publishAttach(conn *websocket.Conn, attachID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attachID == attachID { // not already superseded while we wrote the handshake
		s.ws = conn
	}
}

// detach clears s.ws (if attachID is still current — a detach from an
// already-superseded attachment is a no-op) and starts the grace timer.
func (s *session) detach(attachID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finalized || s.attachID != attachID {
		return
	}
	s.ws = nil
	s.graceTimer = time.AfterFunc(*resumeGrace, func() { s.graceExpired(attachID) })
	log.Printf("session %s orphaned, %s grace to resume", s.key[:8], *resumeGrace)
}

func (s *session) graceExpired(attachID uint64) {
	s.mu.Lock()
	stillOrphaned := !s.finalized && s.attachID == attachID && s.ws == nil
	s.mu.Unlock()
	if !stillOrphaned {
		return // resumed (or already finalized) before the timer fired
	}
	log.Printf("session %s grace period expired, giving up", s.key[:8])
	s.finalize()
}

// finalize is the hard, permanent teardown: closes the SSH target
// connection and removes the session from the registry. Used both when the
// target connection itself dies and when the grace period lapses with no
// resume.
func (s *session) finalize() {
	s.mu.Lock()
	if s.finalized {
		s.mu.Unlock()
		return
	}
	s.finalized = true
	if s.graceTimer != nil {
		s.graceTimer.Stop()
		s.graceTimer = nil
	}
	ws := s.ws
	s.ws = nil
	s.mu.Unlock()

	if ws != nil {
		ws.Close()
	}
	s.tcp.Close()
	sessionsMu.Lock()
	delete(sessions, s.key)
	sessionsMu.Unlock()
	log.Printf("session %s finalized", s.key[:8])
}

// runDownload is the session's one permanent goroutine: continuously reads
// the SSH target's output, buffers it (bounded, oldest bytes trimmed first),
// and forwards it to whatever WebSocket is currently attached, if any.
func (s *session) runDownload() {
	maxBuf := int(*resumeBufferMB * 1024 * 1024)
	buf := make([]byte, 32*1024)
	for {
		n, err := s.tcp.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)

			s.mu.Lock()
			s.sentToBrowser += int64(n)
			s.buf = append(s.buf, chunk...)
			if over := len(s.buf) - maxBuf; over > 0 {
				s.buf = s.buf[over:]
				s.bufStart += int64(over)
			}
			ws := s.ws
			attachID := s.attachID
			s.mu.Unlock()

			if ws != nil {
				if werr := ws.WriteMessage(websocket.BinaryMessage, chunk); werr != nil {
					s.detach(attachID)
				}
			}
		}
		if err != nil {
			s.finalize()
			return
		}
	}
}

// runUpload pumps one attachment's browser-side reads to the SSH target
// until that WebSocket dies, then detaches (starting the grace period) and
// returns; it does not affect the session's other, permanent goroutine.
func (s *session) runUpload(conn *websocket.Conn, attachID uint64) {
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			s.detach(attachID)
			conn.Close()
			return
		}
		conn.SetReadDeadline(time.Now().Add(pongWait))

		s.mu.Lock()
		if s.attachID != attachID {
			s.mu.Unlock()
			return // superseded by a newer attachment; stop touching tcp
		}
		s.recvFromBrowser += int64(len(data))
		s.mu.Unlock()

		if _, werr := s.tcp.Write(data); werr != nil {
			s.finalize()
			return
		}
	}
}

// runAttachment brings conn up to date (session key + how much of its
// upload the server has already confirmed + any download tail it's missing)
// and then relays until this attachment's WebSocket dies.
func runAttachment(s *session, conn *websocket.Conn, replayFrom int64) {
	tail, recvFromBrowser, attachID, err := s.attach(replayFrom)
	if err != nil {
		// Can't satisfy the requested replay point byte-for-byte — refuse
		// rather than risk a silent gap that just fails later with a
		// confusing corruption error. The client falls back to a fresh
		// connect.
		conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "resume unavailable: "+err.Error()),
			time.Now().Add(writeWait))
		conn.Close()
		return
	}

	initMsg, _ := json.Marshal(map[string]any{"session": s.key, "recvAck": recvFromBrowser})
	if err := conn.WriteMessage(websocket.TextMessage, initMsg); err != nil {
		conn.Close()
		return
	}
	if len(tail) > 0 {
		if err := conn.WriteMessage(websocket.BinaryMessage, tail); err != nil {
			conn.Close()
			return
		}
	}
	s.publishAttach(conn, attachID)

	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	stopPing := make(chan struct{})
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait)); err != nil {
					return
				}
			case <-stopPing:
				return
			}
		}
	}()

	s.runUpload(conn, attachID)
	close(stopPing)
}

func resumeHandler(w http.ResponseWriter, r *http.Request) {
	if !authed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	key := r.URL.Query().Get("key")
	recv, err := strconv.ParseInt(r.URL.Query().Get("recv"), 10, 64)
	if key == "" || err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Upgrade unconditionally, even for an unknown/expired key, and treat
	// that the same way as an out-of-range replay offset: a rejection
	// close sent *after* a successful upgrade. A client's WebSocket API
	// can't see the status code of a failed upgrade at all, so a pre-
	// upgrade HTTP error here would be indistinguishable from a transient
	// network blip — the client would retry forever instead of ever
	// reaching its give-up path.
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	sessionsMu.Lock()
	s := sessions[key]
	sessionsMu.Unlock()
	if s == nil {
		conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "resume unavailable: unknown or expired session"),
			time.Now().Add(writeWait))
		conn.Close()
		return
	}
	runAttachment(s, conn, recv)
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

	key, err := newSessionKey()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		tcp.Close()
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		tcp.Close()
		return
	}

	s := &session{key: key, tcp: tcp}
	sessionsMu.Lock()
	sessions[key] = s
	sessionsMu.Unlock()
	go s.runDownload()

	log.Printf("relay open: %s -> %s (session %s)", r.RemoteAddr, target, key[:8])
	runAttachment(s, conn, 0)
	log.Printf("relay detached: %s -> %s (session %s)", r.RemoteAddr, target, key[:8])
}

// indexHandler intercepts the mounted root ("/" after StripPrefix) to inject
// the configured default-user/default-port/scrollback into index.html; every
// other path (app.js, xterm.js, main.wasm, ...) falls through to the plain
// static file server untouched.
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
		// index.html is templated per request (default-user/default-port/
		// scrollback) and small, so there's no real cost to never caching it.
		w.Header().Set("Cache-Control", "no-store")
		b, err := os.ReadFile(filepath.Join(*webDir, "index.html"))
		if err != nil {
			http.Error(w, "index.html: "+err.Error(), http.StatusInternalServerError)
			return
		}
		page := strings.NewReplacer(
			"{{DEFAULT_USER}}", html.EscapeString(*defaultUser),
			"{{DEFAULT_PORT}}", html.EscapeString(*defaultPort),
			"{{SCROLLBACK}}", strconv.Itoa(*scrollback),
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
	mux.HandleFunc(basePath+"/resume", resumeHandler)
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
