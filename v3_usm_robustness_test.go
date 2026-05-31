// Copyright 2026 runZero, Inc. All rights reserved.
//
// Regression tests: the SNMPv3 USM crypto code sliced
// attacker-controlled fields (msgPrivacyParameters, msgAuthenticationParameters)
// without validating their length, panicking on short/truncated inputs from a
// hostile agent. After the fix these must return an error instead of panicking.

package gosnmp

import "testing"

// TestShortPrivacyParametersNoPanic feeds the DES decrypt path a
// msgPrivacyParameters value shorter than the required 8-byte salt. Before the
// fix this indexed sp.PrivacyParameters[i] for i in 0..7 out of bounds.
func TestShortPrivacyParametersNoPanic(t *testing.T) {
	sp := &UsmSecurityParameters{
		Logger:            NewLogger(nil),
		PrivacyProtocol:   DES,
		PrivacyKey:        make([]byte, 16),         // preiv = PrivacyKey[8:], len 8
		PrivacyParameters: []byte{0x01, 0x02, 0x03}, // SHORT: only 3 bytes
	}
	// A minimal encrypted ScopedPDU OctetString: tag + length + 8 ciphertext
	// bytes (a multiple of the DES block size).
	packet := append([]byte{byte(OctetString), 0x08}, make([]byte, 8)...)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("decryptPacket panicked on short privacy parameters: %v", r)
		}
	}()

	if _, err := sp.decryptPacket(packet, 0); err == nil {
		t.Fatalf("expected an error for <8-byte msgPrivacyParameters, got nil")
	}
}

// TestNonBlockMultipleCiphertext confirms the existing block-size guard
// still rejects ciphertext that is not a multiple of the DES block size.
func TestNonBlockMultipleCiphertext(t *testing.T) {
	sp := &UsmSecurityParameters{
		Logger:            NewLogger(nil),
		PrivacyProtocol:   DES,
		PrivacyKey:        make([]byte, 16),
		PrivacyParameters: make([]byte, 8),
	}
	// 5 ciphertext bytes -> not a multiple of 8.
	packet := append([]byte{byte(OctetString), 0x05}, make([]byte, 5)...)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("decryptPacket panicked on non-block-multiple ciphertext: %v", r)
		}
	}()
	if _, err := sp.decryptPacket(packet, 0); err == nil {
		t.Fatalf("expected an error for non-block-multiple ciphertext, got nil")
	}
}

// TestShortAuthParametersNoPanic builds a USM SEQUENCE whose
// msgAuthenticationParameters OctetString is short (4 bytes) and sits at the end
// of the buffer, so cursor+len(macVarbinds[SHA512]) would exceed len(packet).
// Before the fix the placeholder-blanking copy() sliced out of bounds.
func TestShortAuthParametersNoPanic(t *testing.T) {
	field := func(b ...byte) []byte { return append([]byte{byte(OctetString), byte(len(b))}, b...) }
	intf := func(v byte) []byte { return []byte{byte(Integer), 1, v} }
	body := []byte{}
	body = append(body, field('e', 'n', 'g')...) // msgAuthoritativeEngineID
	body = append(body, intf(1)...)              // EngineBoots
	body = append(body, intf(1)...)              // EngineTime
	body = append(body, field('u', 's', 'r')...) // msgUserName
	body = append(body, field(0, 0, 0, 0)...)    // msgAuthenticationParameters: SHORT (4 bytes), at end
	packet := append([]byte{byte(Sequence), byte(len(body))}, body...)

	sp := &UsmSecurityParameters{
		Logger:                 NewLogger(nil),
		AuthenticationProtocol: SHA512, // configured digest field length = 50
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unmarshal panicked on short authentication parameters: %v", r)
		}
	}()

	if _, err := sp.unmarshal(AuthNoPriv, packet, 0); err == nil {
		t.Fatalf("expected an error for truncated msgAuthenticationParameters, got nil")
	}
}
