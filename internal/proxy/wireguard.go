package proxy

// WireGuard message types (first byte, followed by three reserved zero bytes).
const (
	wgHandshakeInitiation = 1
	wgHandshakeResponse   = 2
	wgCookieReply         = 3
	wgTransportData       = 4
)

// IsWireGuard reports whether b looks like a well-formed WireGuard message.
//
// The check is structural only (type, reserved bytes, exact/aligned length);
// it cannot authenticate traffic but it rejects random scans and non-WireGuard
// protocols cheaply. Sizes come from the WireGuard whitepaper §5.4:
//
//	initiation 148 bytes, response 92, cookie reply 64,
//	transport data = 16-byte header + ciphertext padded to 16 + 16-byte tag.
func IsWireGuard(b []byte) bool {
	if len(b) < 4 || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return false
	}
	switch b[0] {
	case wgHandshakeInitiation:
		return len(b) == 148
	case wgHandshakeResponse:
		return len(b) == 92
	case wgCookieReply:
		return len(b) == 64
	case wgTransportData:
		return len(b) >= 32 && len(b)%16 == 0
	}
	return false
}
