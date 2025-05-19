#include "ctap_pin_protocol.h"
#include "ctap_string.h"
#include "utils.h"
#include "compiler.h"

#include <hmac.h>
#include <hkdf.h>

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

	const ctap_crypto_t *const crypto = protocol->crypto;

	static_assert(
		sizeof(protocol->key_agreement_private_key) == 32,
		"unexpected sizeof(protocol->key_agreement_private_key)"
	);
	if (crypto->rng_generate_data(
		crypto,
		protocol->key_agreement_private_key,
		sizeof(protocol->key_agreement_private_key)
	) != CTAP_CRYPTO_OK) {
		error_log("rng_generate_data() failed" nl);
		return 1;
	}
	debug_log("v%" PRIsz " key_agreement_private_key = ", protocol->version);
	dump_hex(protocol->key_agreement_private_key, sizeof(protocol->key_agreement_private_key));

	if (crypto->ecc_secp256r1_compute_public_key(
		crypto,
		protocol->key_agreement_private_key,
		protocol->key_agreement_public_key
	) != CTAP_CRYPTO_OK) {
		error_log("ecc_secp256r1_compute_public_key() failed" nl);
		return 1;
	}

	return 0;
}

int ctap_pin_protocol_reset_pin_uv_auth_token(
	ctap_pin_protocol_t *const protocol
) {
	const ctap_crypto_t *const crypto = protocol->crypto;
	if (crypto->rng_generate_data(
		crypto,
		protocol->pin_uv_auth_token,
		sizeof(protocol->pin_uv_auth_token)
	) != CTAP_CRYPTO_OK) {
		error_log("rng_generate_data() failed" nl);
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

	const ctap_crypto_t *const crypto = protocol->crypto;
	uint8_t ecdh_shared_point_z[32];
	if (crypto->ecc_secp256r1_shared_secret(
		crypto,
		(uint8_t *) &peer_public_key->pubkey,
		protocol->key_agreement_private_key,
		ecdh_shared_point_z
	) != CTAP_CRYPTO_OK) {
		error_log("ecc_secp256r1_shared_secret() failed" nl);
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
	const ctap_crypto_t *const crypto = protocol->crypto;
	if (crypto->sha256_compute_digest(crypto, ecdh_shared_point_z, 32, shared_secret) != CTAP_CRYPTO_OK) {
		error_log(red("sha256_compute_digest() failed") nl);
		return 1;
	}
	return 0;
}

int ctap_pin_protocol_v2_kdf(
	const ctap_pin_protocol_t *protocol,
	const uint8_t *ecdh_shared_point_z,
	uint8_t *shared_secret
) {
	const ctap_crypto_t *const crypto = protocol->crypto;

	const hash_alg_t *const sha256 = crypto->sha256;
	uint8_t sha256_ctx[sha256->ctx_size];
	crypto->sha256_bind_ctx(crypto, sha256_ctx);

	uint8_t all_zero_salt[32];
	memset(all_zero_salt, 0, sizeof(all_zero_salt));

	const ctap_string_t info_hmac_key = ctap_str("CTAP2 HMAC key");
	hkdf(
		sha256,
		sha256_ctx,
		all_zero_salt, sizeof(all_zero_salt),
		ecdh_shared_point_z, 32,
		info_hmac_key.data, info_hmac_key.size,
		32,
		shared_secret
	);
	const ctap_string_t info_aes_key = ctap_str("CTAP2 AES key");
	hkdf(
		sha256,
		sha256_ctx,
		all_zero_salt, sizeof(all_zero_salt),
		ecdh_shared_point_z, 32,
		info_aes_key.data, info_aes_key.size,
		32,
		&shared_secret[32]
	);
	return 0;
}

int ctap_pin_protocol_v1_encrypt(
	const ctap_pin_protocol_t *protocol,
	const uint8_t *const shared_secret,
	const uint8_t *const plaintext, const size_t plaintext_length,
	uint8_t *const ciphertext
) {
	if (plaintext_length % CTAP_CRYPTO_AES_BLOCK_SIZE != 0) {
		return 1;
	}

	// v1 uses an all-zero IV
	uint8_t all_zero_iv[CTAP_CRYPTO_AES_BLOCK_SIZE];
	memset(all_zero_iv, 0, CTAP_CRYPTO_AES_BLOCK_SIZE);
	// v1 uses the whole 32-byte shared_secret as the AES key
	const uint8_t *const key = shared_secret;
	memcpy(ciphertext, plaintext, plaintext_length);

	const ctap_crypto_t *const crypto = protocol->crypto;
	if (crypto->aes_256_cbc_encrypt(
		crypto, all_zero_iv, key, ciphertext, plaintext_length
	) != CTAP_CRYPTO_OK) {
		return 1;
	}

	return 0;
}

int ctap_pin_protocol_v2_encrypt(
	const ctap_pin_protocol_t *protocol,
	const uint8_t *const shared_secret,
	const uint8_t *const plaintext, const size_t plaintext_length,
	uint8_t *const ciphertext
) {
	if (plaintext_length % CTAP_CRYPTO_AES_BLOCK_SIZE != 0) {
		return 1;
	}

	const ctap_crypto_t *const crypto = protocol->crypto;

	// v2 uses a random IV (which it prepends to the returned ciphertext,
	// see ctap_pin_protocol_t.encryption_extra_length)
	uint8_t random_iv[CTAP_CRYPTO_AES_BLOCK_SIZE];
	if (crypto->rng_generate_data(crypto, random_iv, sizeof(random_iv)) != CTAP_CRYPTO_OK) {
		error_log("rng_generate_data() failed" nl);
		return 1;
	}
	// v2 uses the last 32 bytes of the 64-byte shared_secret as the AES key
	const uint8_t *const key = &shared_secret[32];
	memcpy(ciphertext, random_iv, sizeof(random_iv));
	memcpy(&ciphertext[sizeof(random_iv)], plaintext, plaintext_length);

	if (crypto->aes_256_cbc_encrypt(
		crypto, random_iv, key, &ciphertext[sizeof(random_iv)], plaintext_length
	) != CTAP_CRYPTO_OK) {
		return 1;
	}

	return 0;
}

int ctap_pin_protocol_v1_decrypt(
	const ctap_pin_protocol_t *protocol,
	const uint8_t *const shared_secret,
	const uint8_t *const ciphertext, const size_t ciphertext_length,
	uint8_t *const plaintext
) {
	if (ciphertext_length % CTAP_CRYPTO_AES_BLOCK_SIZE != 0) {
		return 1;
	}

	// v1 uses an all-zero IV
	uint8_t all_zero_iv[CTAP_CRYPTO_AES_BLOCK_SIZE];
	memset(all_zero_iv, 0, CTAP_CRYPTO_AES_BLOCK_SIZE);
	// v1 uses the whole 32-byte shared_secret as the AES key
	const uint8_t *const key = shared_secret;
	memcpy(plaintext, ciphertext, ciphertext_length);

	const ctap_crypto_t *const crypto = protocol->crypto;
	if (crypto->aes_256_cbc_decrypt(crypto, all_zero_iv, key, plaintext, ciphertext_length) != CTAP_CRYPTO_OK) {
		return 1;
	}

	return 0;
}

int ctap_pin_protocol_v2_decrypt(
	const ctap_pin_protocol_t *protocol,
	const uint8_t *const shared_secret,
	const uint8_t *const ciphertext, const size_t ciphertext_length,
	uint8_t *const plaintext
) {
	// in v2 ciphertext_length = IV length + the actual ciphertext length
	// since the IV length is TINYAES_AES_BLOCKLEN, we can just
	// add the min length check and keep the modulo check unchanged
	if (ciphertext_length < CTAP_CRYPTO_AES_BLOCK_SIZE || ciphertext_length % CTAP_CRYPTO_AES_BLOCK_SIZE != 0) {
		return 1;
	}
	// v2 uses a random IV (which is prepended to the actual ciphertext,
	// see ctap_pin_protocol_t.encryption_extra_length)
	const uint8_t *const iv = ciphertext; // first TINYAES_AES_BLOCKLEN bytes
	const uint8_t *const actual_ciphertext = &ciphertext[CTAP_CRYPTO_AES_BLOCK_SIZE];
	const size_t actual_ciphertext_length = ciphertext_length - CTAP_CRYPTO_AES_BLOCK_SIZE;
	// v2 uses the last 32 bytes of the 64-byte shared_secret as the AES key
	const uint8_t *const key = &shared_secret[32];
	memcpy(plaintext, actual_ciphertext, actual_ciphertext_length);

	const ctap_crypto_t *const crypto = protocol->crypto;
	if (crypto->aes_256_cbc_decrypt(crypto, iv, key, plaintext, actual_ciphertext_length) != CTAP_CRYPTO_OK) {
		return 1;
	}

	return 0;
}

size_t ctap_pin_protocol_verify_get_context_size(const ctap_pin_protocol_t *const protocol) {
	const hash_alg_t *const sha256 = protocol->crypto->sha256;
	return hmac_get_context_size(sha256) + sha256->ctx_size;
}

static inline uint8_t *hmac_ctx_from_verify_ctx(void *const verify_ctx) {
	return &((uint8_t *) verify_ctx)[0];
}

static void ctap_pin_protocol_verify_init(
	const ctap_pin_protocol_t *const protocol,
	void *const verify_ctx,
	const uint8_t *const hmac_key,
	const size_t hmac_key_length
) {
	const ctap_crypto_t *const crypto = protocol->crypto;

	uint8_t *const hmac_ctx = hmac_ctx_from_verify_ctx(verify_ctx);

	const hash_alg_t *const sha256 = crypto->sha256;
	uint8_t *const sha256_ctx = &((uint8_t *) verify_ctx)[hmac_get_context_size(sha256)];
	crypto->sha256_bind_ctx(crypto, sha256_ctx);

	hmac_init(hmac_ctx, sha256, sha256_ctx, hmac_key, hmac_key_length);
}

void ctap_pin_protocol_v1_verify_init_with_shared_secret(
	const ctap_pin_protocol_t *const protocol,
	void *const verify_ctx,
	const uint8_t *const shared_secret
) {
	// 6.5.6. PIN/UV Auth Protocol One
	// verify(key, message, signature) -> success | error
	//   1. If the key parameter value is the current pinUvAuthToken and it is not in use, then return error.
	//      (not applicable to this function, see ctap_pin_protocol_verify_init_with_pin_uv_auth_token())
	//   2. Compute HMAC-SHA-256 with the given key and message.
	//      Return success if signature is 16 bytes and is equal to the first 16 bytes of the result,
	//      otherwise return error (implemented in ctap_pin_protocol_v1_verify_final()).
	const uint8_t *const hmac_key = shared_secret;
	const size_t hmac_key_length = protocol->shared_secret_length;
	ctap_pin_protocol_verify_init(protocol, verify_ctx, hmac_key, hmac_key_length);
}

void ctap_pin_protocol_v2_verify_init_with_shared_secret(
	const ctap_pin_protocol_t *const protocol,
	void *const verify_ctx,
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
	ctap_pin_protocol_verify_init(protocol, verify_ctx, hmac_key, hmac_key_length);
}

int ctap_pin_protocol_verify_init_with_pin_uv_auth_token(
	const ctap_pin_protocol_t *const protocol,
	void *const verify_ctx,
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

	const uint8_t *const hmac_key = protocol->pin_uv_auth_token;
	const size_t hmac_key_length = sizeof(protocol->pin_uv_auth_token);

	ctap_pin_protocol_verify_init(protocol, verify_ctx, hmac_key, hmac_key_length);

	return 0;
}


void ctap_pin_protocol_verify_update(
	const ctap_pin_protocol_t *const protocol,
	void *const verify_ctx,
	const uint8_t *const message_data, const size_t message_data_length
) {
	lion_unused(protocol); // unused for now, might be needed if we switch to HW-based HMAC
	hmac_update(hmac_ctx_from_verify_ctx(verify_ctx), message_data, message_data_length);
}


int ctap_pin_protocol_v1_verify_final(
	const ctap_pin_protocol_t *const protocol,
	void *const verify_ctx,
	const uint8_t *const signature, const size_t signature_length
) {
	// 6.5.6. PIN/UV Auth Protocol One
	// verify(key, message, signature) -> success | error
	//   2. Compute HMAC-SHA-256 with the given key and message.
	//      Return success if signature is 16 bytes and is equal to the first 16 bytes of the result,
	//      otherwise return error.
	assert(protocol->crypto->sha256->output_size == 32);
	uint8_t hmac[protocol->crypto->sha256->output_size];
	hmac_final(hmac_ctx_from_verify_ctx(verify_ctx), hmac);
	if (signature_length != 16 || memcmp(hmac, signature, 16) != 0) {
		return 1;
	}
	return 0;
}

int ctap_pin_protocol_v2_verify_final(
	const ctap_pin_protocol_t *const protocol,
	void *const verify_ctx,
	const uint8_t *const signature, const size_t signature_length
) {
	// 6.5.6. PIN/UV Auth Protocol One
	// verify(key, message, signature) -> success | error
	//   2. Compute HMAC-SHA-256 with the given key and message.
	//      Return success if signature is equal to the result,
	//      otherwise return error.
	assert(protocol->crypto->sha256->output_size == 32);
	uint8_t hmac[protocol->crypto->sha256->output_size];
	hmac_final(hmac_ctx_from_verify_ctx(verify_ctx), hmac);
	if (signature_length != sizeof(hmac) || memcmp(hmac, signature, sizeof(hmac)) != 0) {
		return 1;
	}
	return 0;
}
