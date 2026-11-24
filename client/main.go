//go:build js && wasm

// WASM SSH client. Runs entirely in the browser: performs the full SSH2
// handshake, key exchange, and symmetric crypto here, over a WebSocket that
// the relay bridges to raw TCP. The relay and any MITM proxy see only SSH
// ciphertext.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall/js"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---- WebSocket adapted to net.Conn --------------------------------------
//
// SSH has no session resumption of its own: any lost or duplicated byte
// fails its per-packet MAC and kills the whole connection. So when the
// underlying WebSocket drops (a proxy idle-killed it, the tab was frozen
// and the browser closed it, ...), this reconnects to the relay's /resume
// endpoint and keeps feeding ssh.Client the exact same ordered byte stream
// — from its perspective nothing happened, just a stall. ssh.Client only
// ever sees a hard error once resuming has been definitively refused (the
// relay's grace period lapsed, or its replay buffer no longer goes back
// far enough) — at that point there's nothing left to do but a fresh
// connect with real credentials, same as before this existed.
//
// Reconnecting needs its own small reliable-delivery bookkeeping,
// mirroring the relay's: recvFromServer is how many bytes we've taken in
// from the server, reported on resume so it knows what to replay; sentLog
// is everything we've written that the server hasn't yet confirmed
// receiving (reported via the recvAck control message on every (re)connect),
// kept so it can be retransmitted after a gap.

type wsConn struct {
	resumeURLFmt string // e.g. "wss://host/base/resume?key=%s&recv=%d"

	mu             sync.Mutex
	ws             js.Value
	fns            []js.Func
	sessionKey     string
	recvFromServer int64
	sentLog        []byte
	sentLogStart   int64 // absolute offset of sentLog[0]

	in        chan []byte
	rbuf      []byte
	closed    chan struct{}
	closeOnce sync.Once
}

// maxSentLog bounds the retransmit log. Upload volume (keystrokes) is tiny
// compared to download (program output), so this is a defensive cap, not
// a realistic ceiling — if it's ever hit, resuming can no longer be
// guaranteed gap-free, so give up cleanly rather than risk corruption.
const maxSentLog = 4 * 1024 * 1024

// resumeRejected means the relay explicitly refused to resume this
// session (as opposed to a transient failure worth retrying).
type resumeRejected struct{ reason string }

func (e *resumeRejected) Error() string { return "resume rejected: " + e.reason }

// liveTransportDied reports whether a close/error event is a genuine
// surprise worth reconnecting over: the connection it fired on had been
// committed as the live transport (committed closed), and nothing has
// already torn the whole wsConn down on purpose (closed not yet closed).
// Without that second check, our own deliberate shutdown — which closes
// closed and only then calls the browser's ws.close(), triggering this
// same event — would otherwise look identical to a real drop and launch a
// pointless reconnect attempt.
func liveTransportDied(committed, closed chan struct{}) bool {
	select {
	case <-committed:
	default:
		return false
	}
	select {
	case <-closed:
		return false
	default:
		return true
	}
}

func newWSConn(freshURL string) (*wsConn, error) {
	resumeURLFmt := strings.TrimSuffix(freshURL[:strings.IndexAny(freshURL, "?")], "/ws") + "/resume?key=%s&recv=%d"
	c := &wsConn{
		resumeURLFmt: resumeURLFmt,
		in:           make(chan []byte, 128),
		closed:       make(chan struct{}),
	}
	if err := c.connectOne(freshURL); err != nil {
		close(c.closed)
		return nil, err
	}
	return c, nil
}

// connectOne opens one WebSocket (fresh connect or a /resume attempt),
// waits for it to settle, and if it looks stable, commits it as the
// connection's current live transport — releasing whatever was there
// before. Returns a *resumeRejected if the relay explicitly refused
// (caller should give up), or a plain error for anything transient
// (caller may retry).
func (c *wsConn) connectOne(url string) error {
	ws := js.Global().Get("WebSocket").New(url)
	ws.Set("binaryType", "arraybuffer")

	opened := make(chan struct{}, 1)
	closedWithReason := make(chan string, 1)
	failed := make(chan struct{}, 1)
	committed := make(chan struct{})

	onMsg := js.FuncOf(func(_ js.Value, args []js.Value) any {
		data := args[0].Get("data")
		if data.Type() == js.TypeString {
			c.handleControl(data.String())
			return nil
		}
		u8 := js.Global().Get("Uint8Array").New(data)
		b := make([]byte, u8.Get("length").Int())
		js.CopyBytesToGo(b, u8)
		c.mu.Lock()
		c.recvFromServer += int64(len(b))
		c.mu.Unlock()
		select {
		case c.in <- b:
		case <-c.closed:
		}
		return nil
	})
	onOpen := js.FuncOf(func(_ js.Value, _ []js.Value) any {
		select {
		case opened <- struct{}{}:
		default:
		}
		return nil
	})
	onClose := js.FuncOf(func(_ js.Value, args []js.Value) any {
		reason := ""
		if len(args) > 0 {
			reason = args[0].Get("reason").String()
		}
		select {
		case closedWithReason <- reason:
		default:
		}
		if liveTransportDied(committed, c.closed) {
			go c.reconnectLoop()
		}
		return nil
	})
	onErr := js.FuncOf(func(_ js.Value, _ []js.Value) any {
		select {
		case failed <- struct{}{}:
		default:
		}
		if liveTransportDied(committed, c.closed) {
			go c.reconnectLoop()
		}
		return nil
	})
	fns := []js.Func{onMsg, onOpen, onClose, onErr}
	ws.Call("addEventListener", "message", onMsg)
	ws.Call("addEventListener", "open", onOpen)
	ws.Call("addEventListener", "close", onClose)
	ws.Call("addEventListener", "error", onErr)

	release := func() {
		for _, f := range fns {
			f.Release()
		}
	}

	select {
	case <-opened:
		// The relay sends a rejection close immediately after a successful
		// upgrade when a resume can't be satisfied; give it a brief, generous
		// window to arrive before trusting this connection as live.
		select {
		case reason := <-closedWithReason:
			release()
			return &resumeRejected{reason: reason}
		case <-time.After(300 * time.Millisecond):
		}
	case reason := <-closedWithReason:
		release()
		return &resumeRejected{reason: reason}
	case <-failed:
		release()
		return errors.New("websocket error")
	case <-time.After(20 * time.Second):
		ws.Call("close")
		release()
		return errors.New("websocket open timeout")
	}

	c.mu.Lock()
	oldFns := c.fns
	c.ws = ws
	c.fns = fns
	c.mu.Unlock()
	close(committed)
	for _, f := range oldFns {
		f.Release()
	}
	return nil
}

// handleControl parses the relay's initial per-connection text frame
// ({"session":"...","recvAck":N}) and trims the retransmit log up to
// whatever the relay confirms it has received.
func (c *wsConn) handleControl(raw string) {
	var msg struct {
		Session string `json:"session"`
		RecvAck int64  `json:"recvAck"`
	}
	if err := json.Unmarshal([]byte(raw), &msg); err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionKey = msg.Session
	if trim := msg.RecvAck - c.sentLogStart; trim > 0 {
		if trim > int64(len(c.sentLog)) {
			trim = int64(len(c.sentLog))
		}
		c.sentLog = c.sentLog[trim:]
		c.sentLogStart += trim
	}
}

// reconnectLoop runs after the live transport dies unexpectedly. It keeps
// trying /resume with capped backoff until it either succeeds (silently,
// ssh.Client never notices) or the relay explicitly refuses, at which
// point it gives up for good. There's deliberately no overall time limit
// beyond that: while backgrounded/frozen, this goroutine simply gets no
// CPU time at all and makes no attempts, and resumes exactly where it left
// off the moment the tab is active again.
func (c *wsConn) reconnectLoop() {
	if js.Global().Get("sshReconnecting").Type() == js.TypeFunction {
		js.Global().Get("sshReconnecting").Invoke()
	}
	backoff := 500 * time.Millisecond
	const maxBackoff = 15 * time.Second
	for {
		select {
		case <-c.closed:
			return
		default:
		}

		c.mu.Lock()
		key, recv := c.sessionKey, c.recvFromServer
		c.mu.Unlock()
		if key == "" {
			c.hardClose(errors.New("no session available to resume"))
			return
		}

		err := c.connectOne(fmt.Sprintf(c.resumeURLFmt, key, recv))
		if err == nil {
			c.flushSentLog()
			if js.Global().Get("sshReconnected").Type() == js.TypeFunction {
				js.Global().Get("sshReconnected").Invoke()
			}
			return
		}
		if rej, ok := err.(*resumeRejected); ok {
			c.hardClose(rej)
			return
		}

		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// wsSend sends p over ws, but only if it's actually open: calling send()
// on a WebSocket that's already CLOSING/CLOSED throws in JS, and
// syscall/js turns that into a Go panic, which would otherwise crash this
// goroutine if a reconnect swaps in a dead ws moments before a racing
// Write/flush gets to it. A skipped send here is harmless: the data stays
// in sentLog for the next successful reconnect to flush.
func wsSend(ws js.Value, p []byte) {
	const wsOpen = 1
	if len(p) == 0 || ws.Get("readyState").Int() != wsOpen {
		return
	}
	u8 := js.Global().Get("Uint8Array").New(len(p))
	js.CopyBytesToJS(u8, p)
	ws.Call("send", u8)
}

// flushSentLog resends whatever the relay's recvAck (processed by
// handleControl, already applied by the time connectOne returns) says it's
// still missing.
func (c *wsConn) flushSentLog() {
	c.mu.Lock()
	pending := append([]byte(nil), c.sentLog...)
	ws := c.ws
	c.mu.Unlock()
	wsSend(ws, pending)
}

func (c *wsConn) Read(p []byte) (int, error) {
	if len(c.rbuf) == 0 {
		select {
		case b := <-c.in:
			c.rbuf = b
		case <-c.closed:
			select {
			case b := <-c.in:
				c.rbuf = b
			default:
				return 0, io.EOF
			}
		}
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *wsConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	default:
	}

	c.mu.Lock()
	if len(c.sentLog)+len(p) > maxSentLog {
		c.mu.Unlock()
		c.hardClose(errors.New("retransmit log overflow"))
		return 0, io.ErrClosedPipe
	}
	c.sentLog = append(c.sentLog, p...)
	ws := c.ws
	c.mu.Unlock()

	wsSend(ws, p)
	return len(p), nil
}

// shutdown is the plain, no-callback teardown shared by an explicit Close()
// and a definitive give-up after a failed resume.
func (c *wsConn) shutdown() {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.mu.Lock()
		ws, fns := c.ws, c.fns
		c.mu.Unlock()
		if ws.Type() == js.TypeObject {
			ws.Call("close")
		}
		for _, f := range fns {
			f.Release()
		}
	})
}

// hardClose is reconnectLoop's and Write's "resuming is no longer
// possible" path: unlike a plain Close(), this is news to the UI (the
// session died for a reason beyond an ordinary user-initiated disconnect),
// so it gets its own callback distinct from doConnect's normal sshClosed.
func (c *wsConn) hardClose(err error) {
	c.shutdown()
	if js.Global().Get("sshGaveUp").Type() == js.TypeFunction {
		js.Global().Get("sshGaveUp").Invoke(err.Error())
	}
}

func (c *wsConn) Close() error { c.shutdown(); return nil }

type addr struct{}

func (addr) Network() string { return "ws" }
func (addr) String() string  { return "ws" }

func (c *wsConn) LocalAddr() net.Addr                { return addr{} }
func (c *wsConn) RemoteAddr() net.Addr               { return addr{} }
func (c *wsConn) SetDeadline(t time.Time) error      { return nil }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return nil }

// ---- SSH connect ---------------------------------------------------------

// bridgeFuncs holds the goSSHWrite/goSSHResize/goSSHClose closures for the
// current session, so a reconnect can release them before replacing them.
var bridgeFuncs []js.Func

func releaseBridgeFuncs() {
	for _, f := range bridgeFuncs {
		f.Release()
	}
	bridgeFuncs = nil
}

func doConnect(cfg js.Value) error {
	host := cfg.Get("host").String()
	port := cfg.Get("port").String()
	user := cfg.Get("user").String()
	wsBase := cfg.Get("wsBase").String()
	cols := cfg.Get("cols").Int()
	rows := cfg.Get("rows").Int()

	enc := js.Global().Get("encodeURIComponent")
	url := fmt.Sprintf("%s?host=%s&port=%s", wsBase, enc.Invoke(host).String(), enc.Invoke(port).String())

	wc, err := newWSConn(url)
	if err != nil {
		return err
	}

	var auths []ssh.AuthMethod
	switch cfg.Get("authType").String() {
	case "key":
		keyPEM := []byte(cfg.Get("key").String())
		var signer ssh.Signer
		if pass := cfg.Get("passphrase").String(); pass != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyPEM, []byte(pass))
		} else {
			signer, err = ssh.ParsePrivateKey(keyPEM)
		}
		if err != nil {
			wc.Close()
			return fmt.Errorf("private key: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	default:
		pw := cfg.Get("password").String()
		auths = append(auths,
			ssh.Password(pw),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				ans := make([]string, len(questions))
				for i := range questions {
					ans[i] = pw
				}
				return ans, nil
			}),
		)
	}

	conf := &ssh.ClientConfig{
		User: user,
		Auth: auths,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fpr := ssh.FingerprintSHA256(key)
			kind := key.Type()
			if js.Global().Get("hostKeyConfirm").Invoke(host, port, kind, fpr).Bool() {
				return nil
			}
			return errors.New("host key rejected by user")
		},
		Timeout: 20 * time.Second,
	}

	sc, chans, reqs, err := ssh.NewClientConn(wc, net.JoinHostPort(host, port), conf)
	if err != nil {
		wc.Close()
		return fmt.Errorf("ssh handshake/auth: %w", err)
	}
	client := ssh.NewClient(sc, chans, reqs)

	sess, err := client.NewSession()
	if err != nil {
		client.Close()
		return err
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		sess.Close()
		client.Close()
		return err
	}

	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	stderr, _ := sess.StderrPipe()
	if err := sess.Shell(); err != nil {
		sess.Close()
		client.Close()
		return err
	}

	releaseBridgeFuncs()
	writeFn := js.FuncOf(func(_ js.Value, a []js.Value) any {
		stdin.Write([]byte(a[0].String()))
		return nil
	})
	resizeFn := js.FuncOf(func(_ js.Value, a []js.Value) any {
		sess.WindowChange(a[1].Int(), a[0].Int()) // (rows, cols)
		return nil
	})
	closeFn := js.FuncOf(func(_ js.Value, _ []js.Value) any {
		sess.Close()
		client.Close()
		wc.Close()
		return nil
	})
	bridgeFuncs = []js.Func{writeFn, resizeFn, closeFn}
	js.Global().Set("goSSHWrite", writeFn)
	js.Global().Set("goSSHResize", resizeFn)
	js.Global().Set("goSSHClose", closeFn)

	pump := func(r io.Reader) {
		buf := make([]byte, 16*1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				u8 := js.Global().Get("Uint8Array").New(n)
				js.CopyBytesToJS(u8, buf[:n])
				js.Global().Get("termWrite").Invoke(u8)
			}
			if err != nil {
				return
			}
		}
	}
	go pump(stdout)
	go pump(stderr)

	go func() {
		sess.Wait()
		client.Close()
		wc.Close()
		js.Global().Get("sshClosed").Invoke()
	}()

	return nil
}

func sshConnect(_ js.Value, args []js.Value) any {
	cfg := args[0]
	handler := js.FuncOf(func(_ js.Value, p []js.Value) any {
		resolve, reject := p[0], p[1]
		go func() {
			if err := doConnect(cfg); err != nil {
				reject.Invoke(err.Error())
			} else {
				resolve.Invoke()
			}
		}()
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}

func main() {
	js.Global().Set("goSSHConnect", js.FuncOf(sshConnect))
	if r := js.Global().Get("goReady"); r.Type() == js.TypeFunction {
		r.Invoke()
	}
	select {}
}
