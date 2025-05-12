#ifndef LIONKEY_COSE_H
#define LIONKEY_COSE_H

#include <stdint.h>

// CBOR Object Signing and Encryption (COSE)
// RFC 9052: CBOR Object Signing and Encryption (COSE): Structures and Process
//   https://datatracker.ietf.org/doc/html/rfc9052
// RFC 9053: CBOR Object Signing and Encryption (COSE): Initial Algorithms
//   https://datatracker.ietf.org/doc/html/rfc9053

// RFC 8949: Concise Binary Object Representation (CBOR)
//   https://cbor.io/
//   https://datatracker.ietf.org/doc/html/rfc8949

// https://datatracker.ietf.org/doc/html/rfc9052#name-key-objects
// The following values are to be used with the ctap_set_present() and the ctap_param_is_present() macros.
// The values are arbitrary for our implementation (a mapping of the string keys to numbers)
// and do not come from the spec.
#define COSE_Key_field_kty       1
#define COSE_Key_field_alg       2
#define COSE_Key_field_crv       3
#define COSE_Key_field_pubkey_x  4
#define COSE_Key_field_pubkey_y  5
typedef struct COSE_Key {
	uint32_t present; // holds parsing info (which fields are present)
	int kty;
	int alg;
	int crv;
	struct COSE_Key_pubkey {
		uint8_t x[32];
		uint8_t y[32];
	} pubkey;
} COSE_Key;
#ifndef __cplusplus
static_assert(
	sizeof(struct COSE_Key_pubkey) == 64,
	"sizeof(struct COSE_Key_pubkey) == 64"
);
#else
static_assert(
	sizeof(COSE_Key::COSE_Key_pubkey) == 64,
	"sizeof(COSE_Key::COSE_Key_pubkey) == 64"
);
#endif

// https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
// https://datatracker.ietf.org/doc/html/rfc9052#name-cose-key-common-parameters

#define COSE_Key_label_kty      1 // Identification of the key type (COSE_Key_kty_*)
#define COSE_Key_label_alg      3 // Key usage restriction to this algorithm

// kty (key type) values:
// https://datatracker.ietf.org/doc/html/rfc9053#name-key-object-parameters
// https://www.iana.org/assignments/cose/cose.xhtml#key-type

#define COSE_Key_kty_OKP 1 // OKP = Octet Key Pair [kty(1), crv]
#define COSE_Key_kty_EC2 2 // Elliptic Curve Keys w/ x- and y-coordinate pair [kty(2), crv]

// https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
// https://datatracker.ietf.org/doc/html/rfc9053#name-double-coordinate-curves

#define COSE_Key_kty_OKP_EC2_label_crv      (-1) // EC (Elliptic Curve) identifier
#define COSE_Key_kty_OKP_EC2_label_x        (-2) // Public Key x-coordinate
#define COSE_Key_kty_OKP_EC2_label_y        (-3) // Public Key y-coordinate
#define COSE_Key_kty_OKP_EC2_label_d        (-4) // Private key

// COSE Elliptic Curves
// https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
// https://datatracker.ietf.org/doc/html/rfc9053#section-7.1

// NIST P-256 also known as secp256r1
#define COSE_Key_kty_EC2_crv_P256       1
// Ed25519 for use w/ EdDSA only
#define COSE_Key_kty_OKP_crv_Ed25519    6

// alg values:
// https://www.iana.org/assignments/cose/cose.xhtml#algorithms

// Elliptic Curve Digital Signature Algorithm (ECDSA)
// ECDSA with SHA-256
// https://datatracker.ietf.org/doc/html/rfc9053#name-ecdsa
#define COSE_ALG_ES256             (-7)
// Edwards-Curve Digital Signature Algorithm (EdDSA)
// https://datatracker.ietf.org/doc/html/rfc9053#name-edwards-curve-digital-signa
#define COSE_ALG_EdDSA             (-8)

#define COSE_ALG_ECDH_ES_HKDF_256  (-25)

#endif // LIONKEY_COSE_H
