# Builds the server binary and the wasm SSH client from source, then ships
# a minimal runtime image with just the binary + static web/ assets.
#
# Build:  docker build -t webssh-gw .
# Run:    docker run -p 8443:8443 -v $(pwd)/webssh-gw.conf:/app/webssh-gw.conf:ro webssh-gw
#
# The config file is not baked into the image — mount it at
# /app/webssh-gw.conf (the binary's default -config path, resolved against
# WORKDIR /app) or pass an explicit -config path as extra args to `docker run`.

FROM golang:1.23-bookworm AS build
ARG XTERM_VERSION=5.5.0
ARG ADDON_FIT_VERSION=0.10.0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY server ./server
COPY client ./client
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/webssh-gw ./server
RUN GOOS=js GOARCH=wasm go build -o /out/main.wasm ./client
# wasm_exec.js moved from misc/wasm/ to lib/wasm/ in a later Go release
# than this builder's; try both paths so this doesn't rot either way.
RUN sh -c 'f="$(go env GOROOT)/lib/wasm/wasm_exec.js"; [ -f "$f" ] || f="$(go env GOROOT)/misc/wasm/wasm_exec.js"; cp "$f" /out/wasm_exec.js'
# Third-party terminal assets, fetched fresh (not vendored in the repo) —
# same versions and URLs the Makefile's `vendor` target uses.
RUN curl -L -o /out/xterm.js "https://unpkg.com/@xterm/xterm@${XTERM_VERSION}/lib/xterm.js" \
 && curl -L -o /out/xterm.css "https://unpkg.com/@xterm/xterm@${XTERM_VERSION}/css/xterm.css" \
 && curl -L -o /out/addon-fit.js "https://unpkg.com/@xterm/addon-fit@${ADDON_FIT_VERSION}/lib/addon-fit.js"

FROM scratch
WORKDIR /app
COPY --from=build /out/webssh-gw ./webssh-gw
COPY --from=build /out/main.wasm /out/wasm_exec.js /out/xterm.js /out/xterm.css /out/addon-fit.js ./web/
COPY web/index.html web/app.js web/style.css ./web/

# Runs as a non-root UID. scratch has no /etc/passwd, but the kernel only
# needs the numeric UID/GID to enforce this — no entry required.
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/app/webssh-gw"]
