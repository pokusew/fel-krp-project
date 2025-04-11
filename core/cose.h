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
typedef struct COSE_Key {
	struct {
		uint8_t x[32];
		uint8_t y[32];
	} pubkey;
	int kty;
	int crv;
} COSE_Key;

// Identification of the key type
#define COSE_KEY_LABEL_KTY      1
// Key usage restriction to this algorithm
#define COSE_KEY_LABEL_ALG      3
// CRV = curve, values from Table 22
#define COSE_KEY_LABEL_CRV      (-1)
#define COSE_KEY_LABEL_X        (-2)
#define COSE_KEY_LABEL_Y        (-3)

// https://datatracker.ietf.org/doc/html/rfc9053#name-key-object-parameters
// OKP = Octet Key Pair
#define COSE_KEY_KTY_OKP        1
// Elliptic Curve Keys w/ x- and y-coordinate pair
#define COSE_KEY_KTY_EC2        2

// NIST P-256 also known as secp256r1
#define COSE_KEY_CRV_P256       1
// Ed25519 for use w/ EdDSA only
#define COSE_KEY_CRV_ED25519    6

// Elliptic Curve Digital Signature Algorithm (ECDSA)
// ECDSA with SHA-256
// https://datatracker.ietf.org/doc/html/rfc9053#name-ecdsa
#define COSE_ALG_ES256             (-7)
// Edwards-Curve Digital Signature Algorithm (EdDSA)
// https://datatracker.ietf.org/doc/html/rfc9053#name-edwards-curve-digital-signa
#define COSE_ALG_EDDSA             (-8)

#define COSE_ALG_ECDH_ES_HKDF_256  (-25)

#endif // LIONKEY_COSE_H
