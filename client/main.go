//go:build js && wasm

// WASM SSH client. Runs entirely in the browser: performs the full SSH2
// handshake, key exchange, and symmetric crypto here, over a WebSocket that
// the relay bridges to raw TCP. The relay and any MITM proxy see only SSH
// ciphertext.
package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall/js"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---- WebSocket adapted to net.Conn --------------------------------------

type wsConn struct {
	ws        js.Value
	in        chan []byte
	rbuf      []byte
	closed    chan struct{}
	closeOnce sync.Once
	fns       []js.Func
}

func newWSConn(url string) (*wsConn, error) {
	ws := js.Global().Get("WebSocket").New(url)
	ws.Set("binaryType", "arraybuffer")
	c := &wsConn{ws: ws, in: make(chan []byte, 128), closed: make(chan struct{})}

	opened := make(chan error, 1)

	onMsg := js.FuncOf(func(_ js.Value, args []js.Value) any {
		u8 := js.Global().Get("Uint8Array").New(args[0].Get("data"))
		b := make([]byte, u8.Get("length").Int())
		js.CopyBytesToGo(b, u8)
		select {
		case c.in <- b:
		case <-c.closed:
		}
		return nil
	})
	onOpen := js.FuncOf(func(_ js.Value, _ []js.Value) any {
		select {
		case opened <- nil:
		default:
		}
		return nil
	})
	onClose := js.FuncOf(func(_ js.Value, _ []js.Value) any {
		c.close()
		return nil
	})
	onErr := js.FuncOf(func(_ js.Value, _ []js.Value) any {
		select {
		case opened <- errors.New("websocket error"):
		default:
		}
		return nil
	})
	c.fns = []js.Func{onMsg, onOpen, onClose, onErr}
	ws.Call("addEventListener", "message", onMsg)
	ws.Call("addEventListener", "open", onOpen)
	ws.Call("addEventListener", "close", onClose)
	ws.Call("addEventListener", "error", onErr)

	select {
	case err := <-opened:
		if err != nil {
			c.close()
			return nil, err
		}
	case <-time.After(20 * time.Second):
		c.close()
		return nil, errors.New("websocket open timeout")
	}
	return c, nil
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
	u8 := js.Global().Get("Uint8Array").New(len(p))
	js.CopyBytesToJS(u8, p)
	c.ws.Call("send", u8)
	return len(p), nil
}

func (c *wsConn) close() {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.ws.Call("close")
		// Release the JS-callable closures registered in newWSConn; a Func
		// must be released or it leaks in the Go/JS bridge's function table.
		for _, f := range c.fns {
			f.Release()
		}
	})
}

func (c *wsConn) Close() error { c.close(); return nil }

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
