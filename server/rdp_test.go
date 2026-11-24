package main

import (
	"bytes"
	"testing"
)

func TestDERIntegerEncoding(t *testing.T) {
	cases := []struct {
		v    uint64
		want []byte
	}{
		{0, []byte{0x02, 0x01, 0x00}},
		{127, []byte{0x02, 0x01, 0x7f}},
		{128, []byte{0x02, 0x02, 0x00, 0x80}}, // needs leading zero: high bit set
		{255, []byte{0x02, 0x02, 0x00, 0xff}},
		{3390, []byte{0x02, 0x02, 0x0d, 0x3e}}, // RDCleanPath VERSION_1
	}
	for _, c := range cases {
		got := derInteger(c.v)
		if !bytes.Equal(got, c.want) {
			t.Errorf("derInteger(%d) = % x, want % x", c.v, got, c.want)
		}
	}
}

func TestDERLengthEncoding(t *testing.T) {
	cases := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x00}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x80}},
		{255, []byte{0x81, 0xff}},
		{256, []byte{0x82, 0x01, 0x00}},
	}
	for _, c := range cases {
		got := derLength(c.n)
		if !bytes.Equal(got, c.want) {
			t.Errorf("derLength(%d) = % x, want % x", c.n, got, c.want)
		}
	}
}

// buildRequestDER mirrors ironrdp-rdcleanpath's field order/tags exactly
// (version[0], destination[2], proxy_auth[3], x224_connection_pdu[6]) to
// simulate what the real client sends, independent of decodeRDCleanPathRequest
// itself.
func buildRequestDER(destination, proxyAuth string, x224 []byte) []byte {
	return derSequence(
		derExplicit(0, derInteger(rdCleanPathVersion)),
		encodeRDCleanPathUTF8(2, destination),
		encodeRDCleanPathUTF8(3, proxyAuth),
		derExplicit(6, derOctetString(x224)),
	)
}

func TestDecodeRDCleanPathRequest(t *testing.T) {
	x224 := []byte{0x11, 0x22, 0x33, 0x44, 0x55}
	raw := buildRequestDER("myhost:3389", "sometoken", x224)

	req, err := decodeRDCleanPathRequest(raw)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if req.destination != "myhost:3389" {
		t.Errorf("destination = %q, want %q", req.destination, "myhost:3389")
	}
	if !bytes.Equal(req.x224Pdu, x224) {
		t.Errorf("x224Pdu = % x, want % x", req.x224Pdu, x224)
	}
}

func TestDecodeRDCleanPathRequest_MissingX224(t *testing.T) {
	raw := derSequence(
		derExplicit(0, derInteger(rdCleanPathVersion)),
		encodeRDCleanPathUTF8(2, "myhost:3389"),
	)
	if _, err := decodeRDCleanPathRequest(raw); err == nil {
		t.Fatal("expected error for missing x224_connection_pdu field, got nil")
	}
}

func TestEncodeRDCleanPathResponse_ParsesAsValidDER(t *testing.T) {
	x224 := []byte{0xAA, 0xBB, 0xCC}
	cert := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	der := encodeRDCleanPathResponse(x224, [][]byte{cert}, "10.0.0.1:3389")

	outer := &derReader{b: der}
	tag, body, ok := outer.readTLV()
	if !ok || tag != 0x30 {
		t.Fatalf("outer TLV not a SEQUENCE: tag=0x%02x ok=%v", tag, ok)
	}

	inner := &derReader{b: body}
	tag, v, ok := inner.readTLV()
	if !ok || tag != 0xA0 { // [0] version
		t.Fatalf("field 0 (version) missing or wrong tag: 0x%02x", tag)
	}
	versionInner := &derReader{b: v}
	if vtag, vval, ok := versionInner.readTLV(); !ok || vtag != 0x02 || !bytes.Equal(vval, []byte{0x0d, 0x3e}) {
		t.Errorf("version field decoded wrong: tag=0x%02x val=% x", vtag, vval)
	}

	tag, v, ok = inner.readTLV()
	if !ok || tag != 0xA6 { // [6] x224_connection_pdu
		t.Fatalf("field 6 (x224) missing or wrong tag: 0x%02x", tag)
	}
	x224Inner := &derReader{b: v}
	if xtag, xval, ok := x224Inner.readTLV(); !ok || xtag != 0x04 || !bytes.Equal(xval, x224) {
		t.Errorf("x224 field decoded wrong: tag=0x%02x val=% x, want % x", xtag, xval, x224)
	}

	tag, v, ok = inner.readTLV()
	if !ok || tag != 0xA7 { // [7] server_cert_chain
		t.Fatalf("field 7 (cert chain) missing or wrong tag: 0x%02x", tag)
	}
	chainInner := &derReader{b: v}
	ctag, certsBody, ok := chainInner.readTLV()
	if !ok || ctag != 0x30 {
		t.Fatalf("cert chain not a SEQUENCE: 0x%02x", ctag)
	}
	certsReader := &derReader{b: certsBody}
	ctag, cval, ok := certsReader.readTLV()
	if !ok || ctag != 0x04 || !bytes.Equal(cval, cert) {
		t.Errorf("cert entry decoded wrong: tag=0x%02x val=% x, want % x", ctag, cval, cert)
	}

	// [9] server_addr — the real decoder (ironrdp-rdcleanpath's TryFrom impl)
	// uses THIS field's presence, not x224/cert_chain, to recognize a
	// "Response" message at all; omitting it makes a real client reject an
	// otherwise-correct response as "missing error field".
	tag, v, ok = inner.readTLV()
	if !ok || tag != 0xA9 { // [9] server_addr
		t.Fatalf("field 9 (server_addr) missing or wrong tag: 0x%02x", tag)
	}
	addrInner := &derReader{b: v}
	if atag, aval, ok := addrInner.readTLV(); !ok || atag != 0x0C || string(aval) != "10.0.0.1:3389" {
		t.Errorf("server_addr decoded wrong: tag=0x%02x val=%q", atag, aval)
	}
}

// Standard (legacy, non-TLS) RDP security has no certificate to report, but
// the real decoder still requires server_cert_chain to be present (as an
// empty SEQUENCE), not omitted — see the comment on encodeRDCleanPathResponse.
func TestEncodeRDCleanPathResponse_EmptyCertChainStillPresent(t *testing.T) {
	der := encodeRDCleanPathResponse([]byte{0x01}, nil, "10.0.0.1:3389")

	outer := &derReader{b: der}
	_, body, _ := outer.readTLV()
	inner := &derReader{b: body}
	inner.readTLV() // version
	inner.readTLV() // x224
	tag, v, ok := inner.readTLV()
	if !ok || tag != 0xA7 {
		t.Fatalf("field 7 (cert chain) missing even though it must always be present: 0x%02x", tag)
	}
	chainInner := &derReader{b: v}
	ctag, certsBody, ok := chainInner.readTLV()
	if !ok || ctag != 0x30 || len(certsBody) != 0 {
		t.Errorf("empty cert chain not encoded as an empty SEQUENCE: tag=0x%02x body=% x", ctag, certsBody)
	}
}

func TestEncodeRDCleanPathGeneralErr(t *testing.T) {
	der := encodeRDCleanPathGeneralErr(rdCleanPathTargetUnreachableCode)

	outer := &derReader{b: der}
	_, body, ok := outer.readTLV()
	if !ok {
		t.Fatal("not a valid outer TLV")
	}
	inner := &derReader{b: body}
	inner.readTLV() // skip version field
	tag, errField, ok := inner.readTLV()
	if !ok || tag != 0xA1 { // [1] error
		t.Fatalf("field 1 (error) missing or wrong tag: 0x%02x", tag)
	}
	errInner := &derReader{b: errField}
	etag, errSeqBody, ok := errInner.readTLV()
	if !ok || etag != 0x30 {
		t.Fatalf("error field not a SEQUENCE: 0x%02x", etag)
	}
	errSeq := &derReader{b: errSeqBody}
	ctag, codeField, ok := errSeq.readTLV()
	if !ok || ctag != 0xA0 {
		t.Fatalf("error_code field missing or wrong tag: 0x%02x", ctag)
	}
	codeInner := &derReader{b: codeField}
	_, codeVal, ok := codeInner.readTLV()
	if !ok || !bytes.Equal(codeVal, []byte{0x67}) { // 103 = 0x67, fits in one byte (no leading zero needed)
		t.Errorf("error_code = % x, want % x", codeVal, []byte{0x67})
	}
}
