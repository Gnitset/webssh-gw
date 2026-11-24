package main

// RDP support. Unlike SSH and VNC, a browser cannot open a raw TCP/TLS
// socket to the RDP target itself, so the browser-side IronRDP wasm client
// (https://github.com/Devolutions/IronRDP) relies on a small handshake
// called RDCleanPath: the browser sends the gateway a DER-encoded request
// containing the target and the X.224 Connection Request bytes it built
// itself; the gateway dials the target, forwards that request, and performs
// the TLS handshake with the target on the browser's behalf (a browser-side
// TLS stack over an arbitrary TCP relay isn't something IronRDP attempts),
// handing back the server's TLS certificate chain and the X.224 Connection
// Confirm bytes in a DER-encoded response. From that point on it's exactly
// the same bidirectional byte relay used for SSH and VNC — reusing the same
// session/runDownload/runAttachment machinery below, including resumable
// sessions — except this one handshake step means the gateway necessarily
// sees RDP plaintext while it's relaying, unlike SSH/VNC where it never
// does. See README.md's security notes for what that means in practice.
//
// PDU format: github.com/Devolutions/IronRDP/blob/master/crates/ironrdp-rdcleanpath/src/lib.rs

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

const (
	rdCleanPathVersion = 3390 // ironrdp's BASE_VERSION(3389) + 1

	rdCleanPathGeneralErrorCode        = 1
	rdCleanPathTargetUnreachableCode   = 103
	rdCleanPathDNSResolutionFailedCode = 104
	rdCleanPathTLSHandshakeFailedCode  = 105
)

// ---- minimal DER (ASN.1) support ------------------------------------------
//
// RDCleanPathPdu is one flat SEQUENCE of EXPLICIT context-tagged optional
// fields (see ironrdp-rdcleanpath's doc comment). That's a small, fixed
// grammar, so this hand-rolls just enough DER rather than fighting Go's
// encoding/asn1 struct-tag quirks around EXPLICIT + optional + CHOICE-like
// shapes.

func derLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func derTLV(tag byte, content []byte) []byte {
	return append(append([]byte{tag}, derLength(len(content))...), content...)
}

func derInteger(v uint64) []byte {
	b := []byte{
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
	for len(b) > 1 && b[0] == 0 && b[1]&0x80 == 0 {
		b = b[1:]
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return derTLV(0x02, b)
}

func derOctetString(b []byte) []byte { return derTLV(0x04, b) }
func derUTF8String(s string) []byte  { return derTLV(0x0C, []byte(s)) }
func derSequence(fields ...[]byte) []byte {
	var content []byte
	for _, f := range fields {
		content = append(content, f...)
	}
	return derTLV(0x30, content)
}

// derExplicit wraps inner (itself a complete TLV) in a constructed
// context-specific tag, e.g. tagNum 0 -> [0] EXPLICIT.
func derExplicit(tagNum int, inner []byte) []byte {
	return derTLV(0xA0|byte(tagNum), inner)
}

// derReader walks a flat sequence of top-level TLVs, used both for the
// outer SEQUENCE body and for context-tagged fields that themselves wrap a
// single TLV (EXPLICIT tagging).
type derReader struct {
	b   []byte
	pos int
}

// readTLV reads one tag+length+value starting at pos, returning the tag, the
// value bytes, and advancing pos past it. DER length can be short (1 byte,
// <0x80) or long form (0x80|n, followed by n big-endian length bytes).
func (r *derReader) readTLV() (tag byte, value []byte, ok bool) {
	if r.pos >= len(r.b) {
		return 0, nil, false
	}
	tag = r.b[r.pos]
	p := r.pos + 1
	if p >= len(r.b) {
		return 0, nil, false
	}
	lb := r.b[p]
	p++
	var length int
	if lb < 0x80 {
		length = int(lb)
	} else {
		n := int(lb &^ 0x80)
		if n == 0 || p+n > len(r.b) {
			return 0, nil, false
		}
		for i := 0; i < n; i++ {
			length = length<<8 | int(r.b[p+i])
		}
		p += n
	}
	if p+length > len(r.b) {
		return 0, nil, false
	}
	value = r.b[p : p+length]
	r.pos = p + length
	return tag, value, true
}

// rdCleanPathRequest is the subset of RDCleanPathPdu fields the gateway
// reads from a client ("Request") message. preconnection_blob and
// server_auth aren't needed for a plain direct-to-host connection and are
// left unparsed.
type rdCleanPathRequest struct {
	destination string
	x224Pdu     []byte
}

// decodeRDCleanPathRequest parses a client request: SEQUENCE of EXPLICIT
// context-tagged fields in ascending tag order (0=version, 2=destination,
// 3=proxy_auth, 5=preconnection_blob, 6=x224_connection_pdu). Fields are
// read in order and skipped if their tag doesn't match the next one
// expected, matching how DER/BER optional-field SEQUENCEs are structured.
func decodeRDCleanPathRequest(der []byte) (*rdCleanPathRequest, error) {
	outer := &derReader{b: der}
	tag, body, ok := outer.readTLV()
	if !ok || tag != 0x30 {
		return nil, errors.New("not a DER SEQUENCE")
	}
	r := &derReader{b: body}

	next := func(wantTag int) ([]byte, bool) {
		save := r.pos
		tag, value, ok := r.readTLV()
		if !ok || tag != 0xA0|byte(wantTag) {
			r.pos = save
			return nil, false
		}
		inner := &derReader{b: value}
		_, innerValue, ok := inner.readTLV()
		if !ok {
			r.pos = save
			return nil, false
		}
		return innerValue, true
	}

	if _, ok := next(0); !ok {
		return nil, errors.New("missing version field")
	}
	req := &rdCleanPathRequest{}
	if v, ok := next(1); ok { // error — not expected on a request, but tolerate/skip
		_ = v
	}
	if v, ok := next(2); ok {
		req.destination = string(v)
	} else {
		return nil, errors.New("missing destination field")
	}
	next(3) // proxy_auth — ignored; access is already gated by the cookie on the WS upgrade
	next(4) // server_auth — unused by any peer today
	next(5) // preconnection_blob — not supported yet
	if v, ok := next(6); ok {
		req.x224Pdu = v
	} else {
		return nil, errors.New("missing x224_connection_pdu field")
	}
	return req, nil
}

// encodeRDCleanPathResponse encodes a "Response" message. The real
// decoder's classification logic (ironrdp-rdcleanpath's TryFrom impl)
// recognizes this shape specifically by server_addr being present — not by
// x224_connection_pdu or server_cert_chain, despite what their doc
// comments ("sent from proxy to client only") might suggest — and
// unconditionally requires server_cert_chain to be Some(...), even when
// empty (standard RDP security, no TLS). Both fields are therefore always
// included here, never omitted even when there's nothing meaningful to put
// in them.
func encodeRDCleanPathResponse(x224ConnectionResponse []byte, certChain [][]byte, serverAddr string) []byte {
	certs := make([]byte, 0)
	for _, c := range certChain {
		certs = append(certs, derOctetString(c)...)
	}
	return derSequence(
		derExplicit(0, derInteger(rdCleanPathVersion)),
		derExplicit(6, derOctetString(x224ConnectionResponse)),
		derExplicit(7, derTLV(0x30, certs)),
		encodeRDCleanPathUTF8(9, serverAddr),
	)
}

func encodeRDCleanPathGeneralErr(errorCode uint16) []byte {
	errFields := derSequence(derExplicit(0, derInteger(uint64(errorCode))))
	return derSequence(
		derExplicit(0, derInteger(rdCleanPathVersion)),
		derExplicit(1, errFields),
	)
}

func encodeRDCleanPathUTF8(tagNum int, s string) []byte {
	return derExplicit(tagNum, derUTF8String(s))
}

// ---- TPKT / X.224 -----------------------------------------------------
//
// Only as much as the gateway needs: read one TPKT-framed X.224 Connection
// Confirm PDU from the target and pull out the negotiated security
// protocol, so it knows whether to wrap the connection in TLS before
// handing it back to the browser. See MS-RDPBCGR 2.2.1.2 / ITU-T X.224.

const (
	protocolSSL      = 0x00000001
	protocolHybrid   = 0x00000002 // CredSSP/NLA
	protocolHybridEx = 0x00000008
)

// readX224ConnectionConfirm reads one TPKT-framed PDU from conn and returns
// its raw bytes (TPKT header included — that's what IronRDP's web client
// expects back verbatim as x224_connection_pdu) plus the negotiated
// security protocol bitmask (0 if the server's response carries no
// RDP_NEG_RSP/RDP_NEG_FAILURE at all, meaning legacy standard RDP security).
func readX224ConnectionConfirm(conn net.Conn) (raw []byte, selectedProtocol uint32, negotiationFailed bool, err error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, 0, false, fmt.Errorf("reading TPKT header: %w", err)
	}
	if hdr[0] != 3 {
		return nil, 0, false, fmt.Errorf("unexpected TPKT version %d", hdr[0])
	}
	packetLength := int(binary.BigEndian.Uint16(hdr[2:4]))
	if packetLength < 11 || packetLength > 65535 {
		return nil, 0, false, fmt.Errorf("implausible TPKT length %d", packetLength)
	}
	rest := make([]byte, packetLength-4)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return nil, 0, false, fmt.Errorf("reading X.224 body: %w", err)
	}
	raw = append(hdr, rest...)

	// rest[0]=LI, rest[1]=code (expect 0xD0 Connection Confirm), [2:4]=dst-ref,
	// [4:6]=src-ref, [6]=class/options; variable part (if any) follows.
	if len(rest) < 7 {
		return raw, 0, false, fmt.Errorf("X.224 header too short (%d bytes)", len(rest))
	}
	if rest[1] != 0xD0 {
		return raw, 0, false, fmt.Errorf("unexpected X.224 TPDU code 0x%02x (want Connection Confirm)", rest[1])
	}
	li := int(rest[0])
	variable := rest[7:]
	if li-6 > 0 && li-6 <= len(variable) {
		variable = variable[:li-6]
	} else {
		variable = nil
	}
	if len(variable) >= 8 {
		switch variable[0] {
		case 0x02: // RDP_NEG_RSP
			selectedProtocol = binary.LittleEndian.Uint32(variable[4:8])
		case 0x03: // RDP_NEG_FAILURE
			negotiationFailed = true
		}
	}
	return raw, selectedProtocol, negotiationFailed, nil
}

// ---- handler ------------------------------------------------------------

func rdpHandler(w http.ResponseWriter, r *http.Request) {
	if !authed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	fail := func(code uint16, format string, args ...any) {
		log.Printf("rdp relay error (%s): "+format, append([]any{r.RemoteAddr}, args...)...)
		conn.WriteMessage(websocket.BinaryMessage, encodeRDCleanPathGeneralErr(code))
		conn.Close()
	}

	reqBytes, err := readRDCleanPathMessage(conn)
	if err != nil {
		fail(rdCleanPathGeneralErrorCode, "reading request: %v", err)
		return
	}
	req, err := decodeRDCleanPathRequest(reqBytes)
	if err != nil {
		fail(rdCleanPathGeneralErrorCode, "decoding request: %v", err)
		return
	}

	host, port, err := net.SplitHostPort(req.destination)
	if err != nil {
		host, port = req.destination, "3389"
	}
	target, ok := validTarget(host, port)
	if !ok {
		fail(rdCleanPathGeneralErrorCode, "bad target %q", req.destination)
		return
	}

	tcp, err := net.DialTimeout("tcp", target, *dialTO)
	if err != nil {
		code := uint16(rdCleanPathTargetUnreachableCode)
		if _, ok := err.(*net.DNSError); ok {
			code = rdCleanPathDNSResolutionFailedCode
		}
		fail(code, "dial %s: %v", target, err)
		return
	}

	if _, err := tcp.Write(req.x224Pdu); err != nil {
		tcp.Close()
		fail(rdCleanPathGeneralErrorCode, "forwarding X.224 request to %s: %v", target, err)
		return
	}

	x224Response, selectedProtocol, negotiationFailed, err := readX224ConnectionConfirm(tcp)
	if err != nil {
		tcp.Close()
		fail(rdCleanPathGeneralErrorCode, "reading X.224 response from %s: %v", target, err)
		return
	}
	serverAddr := tcp.RemoteAddr().String()
	if negotiationFailed {
		tcp.Close()
		conn.WriteMessage(websocket.BinaryMessage, encodeRDCleanPathResponse(x224Response, nil, serverAddr))
		conn.Close()
		return
	}

	var backend net.Conn = tcp
	var certChain [][]byte
	if selectedProtocol&(protocolSSL|protocolHybrid|protocolHybridEx) != 0 {
		// MaxVersion caps at TLS 1.2: against a real Windows RDP listener,
		// letting Go negotiate TLS 1.3 (its default preference) made the
		// server's SChannel-based RDP TLS stack complete the handshake
		// successfully and then immediately send a fatal "internal_error"
		// alert on the very next read — capping to 1.2 (what RDP's TLS
		// layer has used in practice for its whole existence) made the
		// same target work cleanly. Confirmed by testing against a real
		// host, not a guess.
		//
		// ServerName is left unset when host is a literal IP (the common
		// case for a direct "connect by address" RDP target): Go only
		// sends the SNI extension when ServerName is non-empty, and
		// offering an IP address as SNI isn't meaningful (SNI exists to
		// pick a hostname-based vhost). Skipped entirely since cert
		// verification is already off here; the browser does its own
		// trust decision on the forwarded cert chain instead.
		tlsConfig := &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}
		if net.ParseIP(host) == nil {
			tlsConfig.ServerName = host
		}
		tlsConn := tls.Client(tcp, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			tcp.Close()
			fail(rdCleanPathTLSHandshakeFailedCode, "TLS handshake with %s: %v", target, err)
			return
		}
		peerCerts := tlsConn.ConnectionState().PeerCertificates
		for _, c := range peerCerts {
			certChain = append(certChain, c.Raw)
		}
		backend = tlsConn
	}

	if err := conn.WriteMessage(websocket.BinaryMessage, encodeRDCleanPathResponse(x224Response, certChain, serverAddr)); err != nil {
		backend.Close()
		conn.Close()
		return
	}

	key, err := newSessionKey()
	if err != nil {
		backend.Close()
		conn.Close()
		return
	}
	s := &session{key: key, tcp: backend}
	sessionsMu.Lock()
	sessions[key] = s
	sessionsMu.Unlock()
	go s.runDownload()

	log.Printf("rdp relay open: %s -> %s (session %s)", r.RemoteAddr, target, key[:8])
	runAttachment(s, conn, 0, false)
	log.Printf("rdp relay detached: %s -> %s (session %s)", r.RemoteAddr, target, key[:8])
}

// readRDCleanPathMessage reads WebSocket binary messages, concatenating
// them until a complete DER SEQUENCE is available, in case the browser's
// write got split across more than one WS message (IronRDP's web client
// treats the connection as a plain byte stream and detects PDU boundaries
// by peeking the DER length, same as this does).
func readRDCleanPathMessage(conn *websocket.Conn) ([]byte, error) {
	var buf []byte
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return nil, err
		}
		if mt != websocket.BinaryMessage {
			continue
		}
		buf = append(buf, data...)
		if len(buf) < 2 {
			continue
		}
		if buf[0] != 0x30 {
			return nil, errors.New("not a DER SEQUENCE")
		}
		r := &derReader{b: buf}
		if _, _, ok := r.readTLV(); ok {
			conn.SetReadDeadline(time.Time{})
			return buf, nil
		}
		// Incomplete — keep reading more messages.
	}
}
