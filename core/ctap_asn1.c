#include "ctap_asn1.h"
#include "utils.h"
#include <string.h> // memcmp()

/**
 * Converts an ES256 raw signature (64 bytes: r|s)
 * to an ASN.1 DER Ecdsa-Sig-Value, as defined in [RFC3279] section 2.2.3.
 *
 * WebAuthn 6.5.5. Signature Formats for Packed Attestation, FIDO U2F Attestation, and Assertion Signatures
 * https://w3c.github.io/webauthn/#sctn-signature-attestation-types
 * For COSEAlgorithmIdentifier -7 (ES256), and other ECDSA-based algorithms,
 * the sig value MUST be encoded as an ASN.1 DER Ecdsa-Sig-Value, as defined in [RFC3279] section 2.2.3.
 *
 * The ASN.1 structure is:
 * Ecdsa-Sig-Value ::= SEQUENCE {
 *   r INTEGER,
 *   s INTEGER
 * }
 *
 * @param signature input raw signature (r|s), must be 64 bytes
 * @param asn1_der_signature output buffer for the ASN.1 DER encoded signature,
 *                           must be at least 72 bytes to handle the worst case
 *                           (when padding is needed in both r and s)
 */
void ctap_convert_to_asn1_der_ecdsa_sig_value(
	const uint8_t *signature,
	uint8_t *asn1_der_signature,
	size_t *asn1_der_signature_size
) {

	// extract r and s values (each 32 bytes)
	const uint8_t *r = signature;
	const uint8_t *s = signature + 32;

	// calculate lengths and padding needed for r and s
	// padding is needed if the high bit of the first byte is set
	uint8_t r_pad = (r[0] & 0x80) ? 1 : 0;
	uint8_t s_pad = (s[0] & 0x80) ? 1 : 0;

	// skip leading zeros in r
	uint8_t r_leading_zeros = 0;
	while (r_leading_zeros < 32 && r[r_leading_zeros] == 0) {
		r_leading_zeros++;
	}
	// but keep one zero byte if the next byte has its high bit set
	if ((r_leading_zeros > 0 && r_leading_zeros < 32 && (r[r_leading_zeros] & 0x80)) || r_leading_zeros == 32) {
		r_leading_zeros--;
	}

	// skip leading zeros in s
	uint8_t s_leading_zeros = 0;
	while (s_leading_zeros < 32 && s[s_leading_zeros] == 0) {
		s_leading_zeros++;
	}
	// but keep one zero byte if the next byte has its high bit set
	if ((s_leading_zeros > 0 && s_leading_zeros < 32 && (s[s_leading_zeros] & 0x80)) || s_leading_zeros == 32) {
		s_leading_zeros--;
	}

	uint8_t r_len = 32 - r_leading_zeros + r_pad;
	uint8_t s_len = 32 - s_leading_zeros + s_pad;

	uint8_t seq_len = 2 + r_len + 2 + s_len;
	assert(seq_len < 128);

	uint8_t *p = asn1_der_signature;

	// write SEQUENCE tag
	*p++ = 0x30; // SEQUENCE tag
	*p++ = seq_len;

	// write INTEGER tag and length for r
	*p++ = 0x02; // INTEGER tag
	*p++ = r_len;
	// write r value (with padding if needed)
	if (r_pad) {
		*p++ = 0x00;  // Add padding byte
	}
	memcpy(p, r + r_leading_zeros, 32 - r_leading_zeros);
	p += 32 - r_leading_zeros;

	// write INTEGER tag and length for s
	*p++ = 0x02;  // INTEGER tag
	*p++ = s_len;
	// write s value (with padding if needed)
	if (s_pad) {
		*p++ = 0x00;  // Add padding byte
	}
	memcpy(p, s + s_leading_zeros, 32 - s_leading_zeros);
	p += 32 - s_leading_zeros;

	*asn1_der_signature_size = 2 + seq_len;
	assert((size_t) (p - asn1_der_signature) == *asn1_der_signature_size);

}
