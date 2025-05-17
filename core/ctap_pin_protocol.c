#include "ctap_pin_protocol.h"
#include "ctap_string.h"
#include "utils.h"

#include <uECC.h>
#include <hkdf.h>
#include <aes.h>

// verify that TinyAES is compiled with AES-256-CBC support
static_assert(TINYAES_ENABLE_AES256 == 1, "unexpected TINYAES_ENABLE_AES256 value for AES-256-CBC");
static_assert(TINYAES_ENABLE_CBC == 1, "unexpected TINYAES_ENABLE_CBC value for AES-256-CBC");
static_assert(TINYAES_AES_KEYLEN == 32, "unexpected TINYAES_AES_KEYLEN value for AES-256-CBC");

int ctap_pin_protocol_initialize(
	ctap_pin_protocol_t *const protocol
) {
	if (protocol->regenerate(protocol) != 0) {
		return 1;
	}
	if (protocol->reset_pin_uv_auth_token(protocol) != 0) {
		return 1;
	}
	return 0;
}

int ctap_pin_protocol_regenerate(
	ctap_pin_protocol_t *const protocol
) {
	// Generate a fresh, random P-256 private key, x, and compute the associated public point.

	static_assert(
		sizeof(protocol->key_agreement_private_key) == 32,
		"unexpected sizeof(protocol->key_agreement_private_key)"
	);
	if (ctap_generate_rng(
		protocol->key_agreement_private_key,
		sizeof(protocol->key_agreement_private_key)
	) != 1) {
		// here we use 0 = success, 1 = error
		// (but ctap_generate_rng() uses 1 = error, 0 = success, to be compatible with uECC)
		return 1;
	}
	debug_log("key_agreement_private_key = ");
	dump_hex(protocol->key_agreement_private_key, sizeof(protocol->key_agreement_private_key));

	if (uECC_compute_public_key(
		protocol->key_agreement_private_key,
		protocol->key_agreement_public_key,
		uECC_secp256r1()
	) != 1) {
		error_log("uECC_compute_public_key failed" nl);
		// here we use 0 = success, 1 = error (but uECC_*() functions use 1 = error, 0 = success)
		return 1;
	}

	return 0;
}

int ctap_pin_protocol_reset_pin_uv_auth_token(
	ctap_pin_protocol_t *const protocol
) {
	if (ctap_generate_rng(
		protocol->pin_uv_auth_token,
		sizeof(protocol->pin_uv_auth_token)
	) != 1) {
		// here we use 0 = success, 1 = error
		// (but ctap_generate_rng() uses 1 = error, 0 = success, to be compatible with uECC)
		return 1;
	}
	debug_log("v%" PRIsz " pinUvAuthToken = ", protocol->version);
	dump_hex(protocol->pin_uv_auth_token, sizeof(protocol->pin_uv_auth_token));
	return 0;
}

uint8_t ctap_pin_protocol_get_public_key(
	ctap_pin_protocol_t *const protocol,
	CborEncoder *const encoder
) {

	const uint8_t *x = protocol->key_agreement_public_key;
	const uint8_t *y = protocol->key_agreement_public_key + 32;

	CborError err;
	CborEncoder map;

	cbor_encoding_check(cbor_encoder_create_map(encoder, &map, 5));

	cbor_encoding_check(cbor_encode_int(&map, COSE_Key_label_kty));
	cbor_encoding_check(cbor_encode_int(&map, COSE_Key_kty_EC2));

	cbor_encoding_check(cbor_encode_int(&map, COSE_Key_label_alg));
	cbor_encoding_check(cbor_encode_int(&map, COSE_ALG_ECDH_ES_HKDF_256));

	cbor_encoding_check(cbor_encode_int(&map, COSE_Key_kty_OKP_EC2_label_crv));
	cbor_encoding_check(cbor_encode_int(&map, COSE_Key_kty_EC2_crv_P256));

	cbor_encoding_check(cbor_encode_int(&map, COSE_Key_kty_OKP_EC2_label_x));
	cbor_encoding_check(cbor_encode_byte_string(&map, x, 32));

	cbor_encoding_check(cbor_encode_int(&map, COSE_Key_kty_OKP_EC2_label_y));
	cbor_encoding_check(cbor_encode_byte_string(&map, y, 32));

	cbor_encoding_check(cbor_encoder_close_container(encoder, &map));

	return CTAP2_OK;

}

int ctap_pin_protocol_decapsulate(
	const ctap_pin_protocol_t *const protocol,
	const COSE_Key *const peer_public_key,
	uint8_t *const shared_secret
) {
	// 6.5.6. PIN/UV Auth Protocol One
	// 6.5.7. PIN/UV Auth Protocol Two
	//
	// decapsulate(peerCoseKey) -> sharedSecret | error
	//   1. Return ecdh(peerCoseKey).
	//
	// ecdh(peerCoseKey) -> sharedSecret | error
	//   1. Parse peerCoseKey as specified for getPublicKey, below, and produce a P-256 point, Y.
	//      If unsuccessful, or if the resulting point is not on the curve, return error.
	//   2. Calculate xY, the shared point. (I.e. the scalar-multiplication of the peer’s point, Y,
	//      with the local private key agreement key.)
	//   3. Let Z be the 32-byte, big-endian encoding of the x-coordinate of the shared point.
	//   4. Return kdf(Z).

	uint8_t ecdh_shared_point_z[32];
	if (uECC_shared_secret(
		(uint8_t *) &peer_public_key->pubkey,
		protocol->key_agreement_private_key,
		ecdh_shared_point_z,
		uECC_secp256r1()
	) != 1) {
		error_log("uECC_shared_secret failed" nl);
		// we use 0 = success, 1 = error (uECC use 1 = error, 0 = success)
		return 1;
	}

	debug_log(yellow("peer_cose_key->pubkey") nl "  ");
	dump_hex((uint8_t *) &peer_public_key->pubkey, sizeof(peer_public_key->pubkey));
	debug_log(yellow("key_agreement_private_key") nl "  ");
	dump_hex(protocol->key_agreement_private_key, sizeof(protocol->key_agreement_private_key));
	debug_log(yellow("ecdh_shared_point_z ") nl "  ");
	dump_hex(ecdh_shared_point_z, sizeof(ecdh_shared_point_z));

	if (protocol->kdf(protocol, ecdh_shared_point_z, shared_secret) != 0) {
		error_log("protocol->kdf() failed" nl);
		return 1;
	}

	debug_log(yellow("shared secret ") nl "  ");
	dump_hex(shared_secret, protocol->shared_secret_length);

	return 0;
}

int ctap_pin_protocol_v1_kdf(
	const ctap_pin_protocol_t *protocol,
	const uint8_t *ecdh_shared_point_z,
	uint8_t *shared_secret
) {
	sha256_ctx_t sha256_ctx;
	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, ecdh_shared_point_z, 32);
	sha256_final(&sha256_ctx, shared_secret);
	return 0;
}

int ctap_pin_protocol_v2_kdf(
	const ctap_pin_protocol_t *protocol,
	const uint8_t *ecdh_shared_point_z,
	uint8_t *shared_secret
) {
	uint8_t all_zero_salt[32];
	memset(all_zero_salt, 0, sizeof(all_zero_salt));
	const ctap_string_t info_hmac_key = ctap_str("CTAP2 HMAC key");
	hkdf_sha256(
		all_zero_salt, sizeof(all_zero_salt),
		ecdh_shared_point_z, 32,
		info_hmac_key.data, info_hmac_key.size,
		32,
		shared_secret
	);
	const ctap_string_t info_aes_key = ctap_str("CTAP2 AES key");
	hkdf_sha256(
		all_zero_salt, sizeof(all_zero_salt),
		ecdh_shared_point_z, 32,
		info_aes_key.data, info_aes_key.size,
		32,
		&shared_secret[32]
	);
	return 0;
}

int ctap_pin_protocol_v1_encrypt(
	const uint8_t *const shared_secret,
	const uint8_t *const plaintext, const size_t plaintext_length,
	uint8_t *const ciphertext
) {
	if (plaintext_length % TINYAES_AES_BLOCKLEN != 0) {
		return 1;
	}

	// v1 uses an all-zero IV
	uint8_t all_zero_iv[TINYAES_AES_BLOCKLEN];
	memset(all_zero_iv, 0, TINYAES_AES_BLOCKLEN);
	// v1 uses the whole 32-byte shared_secret as the AES key
	const uint8_t *const key = shared_secret;

	struct AES_ctx aes_ctx;
	AES_init_ctx_iv(&aes_ctx, key, all_zero_iv);
	memcpy(ciphertext, plaintext, plaintext_length);
	AES_CBC_encrypt_buffer(&aes_ctx, ciphertext, plaintext_length);

	return 0;
}

int ctap_pin_protocol_v2_encrypt(
	const uint8_t *const shared_secret,
	const uint8_t *const plaintext, const size_t plaintext_length,
	uint8_t *const ciphertext
) {
	if (plaintext_length % TINYAES_AES_BLOCKLEN != 0) {
		return 1;
	}

	// v2 uses a random IV (which it prepends to the returned ciphertext,
	// see ctap_pin_protocol_t.encryption_extra_length)
	uint8_t random_iv[TINYAES_AES_BLOCKLEN];
	if (ctap_generate_rng(random_iv, sizeof(random_iv)) != 1) {
		// here we use 0 = success, 1 = error
		// (but ctap_generate_rng() uses 1 = error, 0 = success, to be compatible with uECC)
		return 1;
	}
	// v2 uses the last 32 bytes of the 64-byte shared_secret as the AES key
	const uint8_t *const key = &shared_secret[32];

	struct AES_ctx aes_ctx;
	AES_init_ctx_iv(&aes_ctx, key, random_iv);
	memcpy(ciphertext, random_iv, sizeof(random_iv));
	memcpy(&ciphertext[sizeof(random_iv)], plaintext, plaintext_length);
	AES_CBC_encrypt_buffer(&aes_ctx, &ciphertext[sizeof(random_iv)], plaintext_length);

	return 0;
}

int ctap_pin_protocol_v1_decrypt(
	const uint8_t *const shared_secret,
	const uint8_t *const ciphertext, const size_t ciphertext_length,
	uint8_t *const plaintext
) {
	if (ciphertext_length % TINYAES_AES_BLOCKLEN != 0) {
		return 1;
	}

	// v1 uses an all-zero IV
	uint8_t all_zero_iv[TINYAES_AES_BLOCKLEN];
	memset(all_zero_iv, 0, TINYAES_AES_BLOCKLEN);
	// v1 uses the whole 32-byte shared_secret as the AES key
	const uint8_t *const key = shared_secret;

	struct AES_ctx aes_ctx;
	AES_init_ctx_iv(&aes_ctx, key, all_zero_iv);
	memcpy(plaintext, ciphertext, ciphertext_length);
	AES_CBC_decrypt_buffer(&aes_ctx, plaintext, ciphertext_length);

	return 0;
}

int ctap_pin_protocol_v2_decrypt(
	const uint8_t *const shared_secret,
	const uint8_t *const ciphertext, const size_t ciphertext_length,
	uint8_t *const plaintext
) {
	// in v2 ciphertext_length = IV length + the actual ciphertext length
	// since the IV length is TINYAES_AES_BLOCKLEN, we can just
	// add the min length check and keep the modulo check unchanged
	if (ciphertext_length < TINYAES_AES_BLOCKLEN || ciphertext_length % TINYAES_AES_BLOCKLEN != 0) {
		return 1;
	}
	// v2 uses a random IV (which is prepended to the actual ciphertext,
	// see ctap_pin_protocol_t.encryption_extra_length)
	const uint8_t *const iv = ciphertext; // first TINYAES_AES_BLOCKLEN bytes
	const uint8_t *const actual_ciphertext = &ciphertext[TINYAES_AES_BLOCKLEN];
	const size_t actual_ciphertext_length = ciphertext_length - TINYAES_AES_BLOCKLEN;
	// v2 uses the last 32 bytes of the 64-byte shared_secret as the AES key
	const uint8_t *const key = &shared_secret[32];

	struct AES_ctx aes_ctx;
	AES_init_ctx_iv(&aes_ctx, key, iv);
	memcpy(plaintext, actual_ciphertext, actual_ciphertext_length);
	AES_CBC_decrypt_buffer(&aes_ctx, plaintext, actual_ciphertext_length);

	return 0;
}

size_t ctap_pin_protocol_verify_get_context_size(const ctap_pin_protocol_t *const protocol) {
	return sizeof(hmac_sha256_ctx_t);
}

void ctap_pin_protocol_v1_verify_init_with_shared_secret(
	const ctap_pin_protocol_t *const protocol,
	void *const hmac_sha256_ctx,
	const uint8_t *const shared_secret
) {
	// 6.5.6. PIN/UV Auth Protocol One
	// verify(key, message, signature) -> success | error
	//   1. If the key parameter value is the current pinUvAuthToken and it is not in use, then return error.
	//      (not applicable to this function, see ctap_pin_protocol_verify_init_with_pin_uv_auth_token())
	//   2. Compute HMAC-SHA-256 with the given key and message.
	//      Return success if signature is 16 bytes and is equal to the first 16 bytes of the result,
	//      otherwise return error (implemented in ctap_pin_protocol_v1_verify_final()).
	hmac_sha256_init(hmac_sha256_ctx, shared_secret, protocol->shared_secret_length);
}

void ctap_pin_protocol_v2_verify_init_with_shared_secret(
	const ctap_pin_protocol_t *const protocol,
	void *const hmac_sha256_ctx,
	const uint8_t *const shared_secret
) {
	// 6.5.7. PIN/UV Auth Protocol Two
	// verify(key, message, signature) -> success | error
	//   1. If the key parameter value is the current pinUvAuthToken and it is not in use, then return error.
	//      (not applicable to this function, see ctap_pin_protocol_verify_init_with_pin_uv_auth_token())
	//   2. Select the HMAC-key portion of the shared secret.
	//   3. Compute HMAC-SHA-256 with the given key and message.
	//      Return success if signature is equal to the result,
	//      otherwise return error (implemented in ctap_pin_protocol_v2_verify_final()).
	assert(protocol->shared_secret_length == 64);
	const uint8_t *const hmac_key = shared_secret;
	const size_t hmac_key_length = 32;
	hmac_sha256_init(hmac_sha256_ctx, hmac_key, hmac_key_length);
}

int ctap_pin_protocol_verify_init_with_pin_uv_auth_token(
	const ctap_pin_protocol_t *const protocol,
	void *const hmac_sha256_ctx,
	ctap_pin_uv_auth_token_state *const pin_uv_auth_token_state
) {
	// 6.5.6. PIN/UV Auth Protocol One
	// 6.5.7. PIN/UV Auth Protocol Two
	// verify(key, message, signature) -> success | error
	//   1. If the key parameter value is the current pinUvAuthToken and it is not in use, then return error.
	if (!pin_uv_auth_token_state->in_use) {
		return 1;
	}
	pin_uv_auth_token_state->usage_timer.last_use = ctap_get_current_time();
	hmac_sha256_init(hmac_sha256_ctx, protocol->pin_uv_auth_token, sizeof(protocol->pin_uv_auth_token));
	return 0;
}


void ctap_pin_protocol_verify_update(
	const ctap_pin_protocol_t *const protocol,
	void *const hmac_sha256_ctx,
	const uint8_t *const message_data, const size_t message_data_length
) {
	hmac_sha256_update(hmac_sha256_ctx, message_data, message_data_length);
}


int ctap_pin_protocol_v1_verify_final(
	const ctap_pin_protocol_t *const protocol,
	void *const hmac_sha256_ctx,
	const uint8_t *const signature, const size_t signature_length
) {
	// 6.5.6. PIN/UV Auth Protocol One
	// verify(key, message, signature) -> success | error
	//   2. Compute HMAC-SHA-256 with the given key and message.
	//      Return success if signature is 16 bytes and is equal to the first 16 bytes of the result,
	//      otherwise return error.
	static_assert(LIONKEY_SHA256_OUTPUT_SIZE == 32, "LIONKEY_SHA256_OUTPUT_SIZE == 32");
	uint8_t hmac[LIONKEY_SHA256_OUTPUT_SIZE];
	hmac_sha256_final(hmac_sha256_ctx, hmac);
	if (signature_length != 16 || memcmp(hmac, signature, 16) != 0) {
		return 1;
	}
	return 0;
}

int ctap_pin_protocol_v2_verify_final(
	const ctap_pin_protocol_t *const protocol,
	void *const hmac_sha256_ctx,
	const uint8_t *const signature, const size_t signature_length
) {
	// 6.5.6. PIN/UV Auth Protocol One
	// verify(key, message, signature) -> success | error
	//   2. Compute HMAC-SHA-256 with the given key and message.
	//      Return success if signature is equal to the result,
	//      otherwise return error.
	static_assert(LIONKEY_SHA256_OUTPUT_SIZE == 32, "LIONKEY_SHA256_OUTPUT_SIZE == 32");
	uint8_t hmac[LIONKEY_SHA256_OUTPUT_SIZE];
	hmac_sha256_final(hmac_sha256_ctx, hmac);
	if (signature_length != sizeof(hmac) || memcmp(hmac, signature, sizeof(hmac)) != 0) {
		return 1;
	}
	return 0;
}
