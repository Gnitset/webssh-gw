# webssh-gw

A browser SSH client where **all SSH crypto runs in the browser** (Go compiled
to WebAssembly) and the web server is only a **dumb WebSocket↔TCP byte relay**.
A gate token sits in front; once you're past it you can connect to **any
host:port**, all tunneled over `wss://` on 443.

```
Browser ──wss://gw/ws?host=H&port=P──►  nginx :443  ──►  webssh-gw relay  ──TCP──►  H:P (sshd)
  │        (a MITM proxy in the path sees only SSH ciphertext)
  └─ SSH2 handshake + ciphers happen HERE, in wasm
```

Because the SSH layer is negotiated in the browser and terminated only on the
target sshd, neither the relay nor the MITM proxy ever sees SSH plaintext.

Useful when you're stuck behind a locked-down environment — browser-only, all
ports firewalled, all egress through a TLS-MITM proxy — and need to reach
your own SSH servers. The outer `wss://` on 443 is expected to be MITM'd;
that's fine, since it only ever carries SSH ciphertext.

## Layout

- `server/main.go` — relay + token gate (signed-cookie session) + static file server.
- `client/main.go` — `//go:build js && wasm`; the SSH client; adapts a WebSocket to `net.Conn`.
- `web/` — `index.html app.js style.css`; everything else in here (`main.wasm wasm_exec.js xterm.js xterm.css addon-fit.js`) is fetched/built, not committed (see Build below).
- `Dockerfile`, `Makefile`, `systemd/webssh-gw.service`.

## Build

Needs Go 1.22+ wherever you build it (server-side or cross-compiled, or via
the Dockerfile); the machine running the browser needs nothing installed.

```bash
cd webssh-gw
make
```

This runs `go mod tidy`, builds the server and the wasm client, copies
`wasm_exec.js`, and fetches the pinned xterm.js/addon-fit versions into
`web/` — a fresh clone needs nothing beyond this one command. The terminal
assets aren't vendored in the repo (same reasoning as not vendoring the Go
module dependencies): they're pinned by version in the `Makefile`
(`XTERM_VERSION`, `ADDON_FIT_VERSION`) and fetched once, cached in `web/`
until `make clean`. They're still served from your own origin at runtime —
that's a build-time fetch, not a browser-time one, so it doesn't reintroduce
any CDN dependency for whoever actually uses the deployed gateway.

### Or build the container image instead

```bash
docker build -t webssh-gw .
docker run -p 8443:8443 \
  -e WEBSSH_COOKIE_SECRET=$(openssl rand -hex 32) \
  -e WEBSSH_TOKENS=$(openssl rand -hex 24) \
  webssh-gw
```

The image builds the server binary and the wasm client from source and
fetches the terminal assets itself during the build — no separate `make` or
`curl` step needed on your end. It runs as a fixed non-root UID (65532); a
bind-mounted config file (see Run below) needs to be world-readable, or
owned by that UID, rather than `chmod 600`.

## Run

Settings are layered, lowest to highest precedence: each flag's **default**
→ the **config file** → **environment variables** → an explicit **command-line
flag**, which always wins. Day to day, the command line is normally just
`-config <file>`; use an env var or a `-flag` only for a one-off override.

The config file is `key: value` (default path `./webssh-gw.conf`, override
with `-config`):

```bash
cat > webssh-gw.conf <<EOF
listen: 127.0.0.1:8443
web: ./web
cookie-secret: $(openssl rand -hex 32)
tokens: $(openssl rand -hex 24)   # this is the gate credential
EOF
chmod 600 webssh-gw.conf
./webssh-gw -config ./webssh-gw.conf
```

Recognized keys (same name and meaning as the matching flag): `listen`,
`cert`, `key` (TLS private key path), `web`, `tokens`, `cookie-secret`,
`cookie-ttl`, `dial-timeout`, `secure-cookie`, `base-path`, `default-user`,
`default-port` (pre-fill the web UI's user/port fields — handy when most
connections go to the same account or a non-standard SSH port), and
`static-cache-ttl` (browser `Cache-Control` max-age for static assets like
`app.js`/`xterm.js`/`main.wasm`; defaults to 5 minutes — short enough that a
redeploy shows up quickly, long enough to avoid re-fetching a multi-MB wasm
binary on every page load; `index.html` itself is never cached, since it's
templated per request with the two defaults above). Blank lines are ignored,
as are `#` comments — either a whole line or trailing after a value
(wrap the value in quotes if it genuinely needs a literal `#`). It's a plain
custom parser, not a shell-sourced file — hence `.conf`, not `.env`.

Each key also has an environment variable of the same meaning:
`WEBSSH_<FLAG_NAME>`, e.g. `WEBSSH_LISTEN`, `WEBSSH_COOKIE_SECRET`,
`WEBSSH_BASE_PATH`. `WEBSSH_CONFIG` additionally redirects which config file
gets read in the first place (unless `-config` is given explicitly). This is
mainly for Docker/container use — e.g. `docker run -e WEBSSH_COOKIE_SECRET=...
-e WEBSSH_TOKENS=...` needs no mounted file at all, or `-e
WEBSSH_CONFIG=/run/secrets/webssh-gw.conf` to point at one without extra
flags.

Put nginx on 443 in front (TLS termination + the WebSocket upgrade):

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;
    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location / {                         # or "/ssh/" etc. — see below
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
```

The same block works whether this owns its own (sub)domain or shares one at
a subpath — only the `location` path changes, nothing else:

- **Own (sub)domain, e.g. `gw.example.com`:** use `location /` and leave
  `base-path` unset (the default). This is the common case.
- **A subpath of an existing domain, e.g. `example.com/ssh`:** use
  `location /ssh/` and set `base-path: /ssh` in the config file (or
  `-base-path /ssh`). The binary then serves everything under that prefix
  (`/ssh/login`, `/ssh/ws`, `/ssh/app.js`, ...), scopes the session cookie to
  it, and the wasm client derives the WebSocket URL from whatever path the
  page was actually loaded under — no client-side config needed. Visiting
  `https://example.com/ssh` (no trailing slash) 301s to `/ssh/` automatically
  (`net/http`'s normal subtree-routing behavior, nothing special-cased here).

Either way, one `location` block is enough for everything, including the
WebSocket upgrade: a `proxy_pass` target with no path component after
`host:port` preserves the original request URI as-is, matched prefix
included, so nginx never needs to rewrite anything.

For systemd, see `systemd/webssh-gw.service`.

## Security notes — read these

- **Gate token is visible to the MITM proxy.** The proxy decrypts the outer
  TLS, so it can see the login POST / cookie. Use a random, rotatable token and
  never reuse a sensitive password for it. Your *SSH* credentials are typed into
  the wasm client and ride inside the SSH tunnel — those the proxy cannot see.
- **Host keys: trust-on-first-use.** The browser stores accepted SHA256
  fingerprints in `localStorage` (like `known_hosts`) and warns on change.
  Verify the fingerprint out-of-band on first connect — this is what stops the
  relay or anyone in path from MITM'ing the *inner* SSH.
- **The relay dials anything once authed, by design.** The gate is the control.
  That also makes it a general TCP proxy for whoever holds a token — keep the
  token list short, rotate it, and front it with nginx access logging. If you
  want to blocklist cloud metadata / link-local, filter `169.254.0.0/16` and
  friends in `validTarget()` in `server/main.go`.
- Prefer private-key auth (the "private key" mode) over passwords; the key is
  parsed and used only in the browser and never sent to the relay.

## If the proxy blocks WebSockets

Some MITM proxies refuse the `Upgrade` or kill long-lived connections. First try
`wss` on 443 to your own domain (usually fine). If it's blocked, the fallback is
to carry the same byte stream over HTTP streaming (chunked POST up / SSE down) —
that needs a second transport in both the relay (`server/main.go`) and the wasm
`net.Conn` (`client/main.go`). Not yet implemented.
