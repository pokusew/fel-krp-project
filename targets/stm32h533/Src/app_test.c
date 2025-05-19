#include "app.h"
#include "app_test.h"
#include "main.h"

#include <uECC.h>

void app_test_rng_tinymt(void) {
	info_log(cyan("app_test_rng_tinymt") nl);
	uint8_t random_test_buffer[1024];
	const uint32_t t1 = HAL_GetTick();
	const ctap_crypto_status_t status = app_sw_crypto.rng_generate_data(
		&app_sw_crypto,
		random_test_buffer, sizeof(random_test_buffer)
	);
	const uint32_t t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("generated" nl);
	} else {
		error_log("error while generating" nl);
	}
	dump_hex(random_test_buffer, sizeof(random_test_buffer));
	info_log("done in %" PRIu32 " ms" nl, t2 - t1);
}

void app_test_rng_hw(void) {
	info_log(cyan("app_test_rng_hw") nl);
	uint8_t random_test_buffer[1024];
	const uint32_t t1 = HAL_GetTick();
	const ctap_crypto_status_t status = app_hw_crypto.rng_generate_data(
		&app_hw_crypto,
		random_test_buffer, sizeof(random_test_buffer)
	);
	const uint32_t t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("generated" nl);
	} else {
		error_log("error while generating" nl);
	}
	dump_hex(random_test_buffer, sizeof(random_test_buffer));
	info_log("done in %" PRIu32 " ms" nl, t2 - t1);
}

void app_test_ecc_sign(void) {

	info_log(cyan("app_test_ecc_sign") nl);

	ctap_crypto_status_t status;
	int result;
	uint32_t t1;
	uint32_t t2;

	status = app_sw_crypto.rng_init(&app_sw_crypto, 0);
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("rng_init failed") nl);
		return;
	}

	uint8_t private_key[32];
	status = app_sw_crypto.rng_generate_data(
		&app_sw_crypto,
		private_key,
		sizeof(private_key)
	);
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("rng_generate_data(private_key) failed") nl);
		return;
	}
	debug_log("private_key" nl);
	dump_hex(private_key, sizeof(private_key));

	uint8_t message_hash[32];
	status = app_sw_crypto.rng_generate_data(
		&app_sw_crypto,
		message_hash,
		sizeof(message_hash)
	);
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("rng_generate_data(message_hash) failed") nl);
		return;
	}
	debug_log("message_hash" nl);
	dump_hex(message_hash, sizeof(message_hash));

	uint8_t public_key[64];
	status = app_hw_crypto.ecc_secp256r1_compute_public_key(
		&app_hw_crypto,
		private_key,
		public_key
	);
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("ecc_secp256r1_compute_public_key failed") nl);
		return;
	}
	debug_log("public_key" nl);
	dump_hex(public_key, sizeof(public_key));

	const uint8_t fixed_k[32] = {
		1, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0
	};

	// const uint8_t fixed_k[32] = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";

	uint8_t sw_signature[64]; // r (32 bytes) || s (32 bytes)
	uint8_t hw_signature[64]; // r (32 bytes) || s (32 bytes)

	t1 = HAL_GetTick();
	status = app_sw_crypto.ecc_secp256r1_sign(
		&app_sw_crypto,
		private_key,
		message_hash,
		sizeof(message_hash),
		sw_signature,
		fixed_k
	);
	t2 = HAL_GetTick();
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("sw ecc_secp256r1_sign failed") nl);
	}
	debug_log("sw signature" nl);
	dump_hex(sw_signature, sizeof(sw_signature));
	info_log("sw took %" PRIu32 " ms" nl, t2 - t1);

	t1 = HAL_GetTick();
	status = app_hw_crypto.ecc_secp256r1_sign(
		&app_hw_crypto,
		private_key,
		message_hash,
		sizeof(message_hash),
		hw_signature,
		fixed_k
	);
	t2 = HAL_GetTick();
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("hw ecc_secp256r1_sign failed") nl);
	}
	debug_log("hw signature" nl);
	dump_hex(hw_signature, sizeof(hw_signature));
	info_log("hw took %" PRIu32 " ms" nl, t2 - t1);

	if (memcmp(sw_signature, hw_signature, 64) != 0) {
		error_log(red("sw and hw signature differs") nl);
	}

	t1 = HAL_GetTick();
	result = uECC_verify(
		public_key,
		message_hash,
		sizeof(message_hash),
		sw_signature,
		uECC_secp256r1()
	);
	t2 = HAL_GetTick();
	if (result != 1) {
		error_log(red("uECC_verify failed to verify sw-generated signature") nl);
	}
	info_log("uECC_verify took %" PRIu32 " ms" nl, t2 - t1);


	t1 = HAL_GetTick();
	result = uECC_verify(
		public_key,
		message_hash,
		sizeof(message_hash),
		hw_signature,
		uECC_secp256r1()
	);
	t2 = HAL_GetTick();
	if (result != 1) {
		error_log(red("uECC_verify failed to verify hw-generated signature") nl);
	}
	info_log("uECC_verify took %" PRIu32 " ms" nl, t2 - t1);

}

void app_test_ecc_compute_public_key(void) {

	info_log(cyan("app_test_ecc_compute_public_key") nl);

	ctap_crypto_status_t status;
	uint32_t t1;
	uint32_t t2;

	status = app_sw_crypto.rng_init(&app_sw_crypto, 0);
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("rng_init failed") nl);
		return;
	}

	uint8_t private_key[32];
	status = app_sw_crypto.rng_generate_data(
		&app_sw_crypto,
		private_key,
		sizeof(private_key)
	);
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("rng_generate_data(private_key) failed") nl);
		return;
	}
	debug_log("private_key" nl);
	dump_hex(private_key, sizeof(private_key));

	uint8_t sw_public_key[64];
	uint8_t hw_public_key[64];

	t1 = HAL_GetTick();
	status = app_sw_crypto.ecc_secp256r1_compute_public_key(
		&app_sw_crypto,
		private_key,
		sw_public_key
	);
	t2 = HAL_GetTick();
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("sw ecc_secp256r1_compute_public_key failed") nl);
	}
	debug_log("sw_public_key" nl);
	dump_hex(sw_public_key, sizeof(sw_public_key));
	info_log("sw took %" PRIu32 " ms" nl, t2 - t1);

	t1 = HAL_GetTick();
	status = app_hw_crypto.ecc_secp256r1_compute_public_key(
		&app_hw_crypto,
		private_key,
		hw_public_key
	);
	t2 = HAL_GetTick();
	if (status != CTAP_CRYPTO_OK) {
		error_log(red("hw ecc_secp256r1_compute_public_key failed") nl);
		return;
	}
	debug_log("hw_public_key" nl);
	dump_hex(hw_public_key, sizeof(hw_public_key));
	info_log("hw took %" PRIu32 " ms" nl, t2 - t1);

	if (memcmp(sw_public_key, hw_public_key, 64) != 0) {
		error_log(red("sw and hw signature differs") nl);
	}

}

void app_test_aes(void) {

	info_log(cyan("app_test_rng_hw") nl);

	app_sw_crypto.rng_init(&app_sw_crypto, 0);

	uint8_t random_iv[CTAP_CRYPTO_AES_BLOCK_SIZE];
	app_sw_crypto.rng_generate_data(&app_sw_crypto, random_iv, sizeof(random_iv));
	debug_log("iv: ");
	dump_hex(random_iv, sizeof(random_iv));

	uint8_t random_key[CTAP_CRYPTO_AES_256_KEY_SIZE];
	app_sw_crypto.rng_generate_data(&app_sw_crypto, random_key, sizeof(random_key));
	debug_log("key: ");
	dump_hex(random_key, sizeof(random_key));

	const size_t test_size = CTAP_CRYPTO_AES_BLOCK_SIZE * 3;
	uint8_t random_plaintext[test_size];
	app_sw_crypto.rng_generate_data(&app_sw_crypto, random_plaintext, test_size);
	debug_log("plaintext: ");
	dump_hex(random_plaintext, test_size);

	uint8_t data_sw[test_size];
	memcpy(data_sw, random_plaintext, test_size);

	uint8_t data_hw[test_size];
	memcpy(data_hw, random_plaintext, test_size);

	uint32_t t1;
	uint32_t t2;
	ctap_crypto_status_t status;

	t1 = HAL_GetTick();
	status = app_sw_crypto.aes_256_cbc_encrypt(
		&app_sw_crypto,
		random_iv, random_key, data_sw, test_size
	);
	t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("sw encrypt ok" nl);
	} else {
		error_log(red("error while sw encrypt") nl);
	}
	info_log("sw done in %" PRIu32 " ms" nl, t2 - t1);
	dump_hex(data_sw, test_size);

	t1 = HAL_GetTick();
	status = app_hw_crypto.aes_256_cbc_encrypt(
		&app_hw_crypto,
		random_iv, random_key, data_hw, test_size
	);
	t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("hw encrypt ok" nl);
	} else {
		error_log(red("error while hw encrypt") nl);
	}
	info_log("hw done in %" PRIu32 " ms" nl, t2 - t1);
	dump_hex(data_hw, test_size);

	if (memcmp(data_sw, data_hw, test_size) != 0) {
		error_log(red("ciphertexts mismatch") nl);
	} else {
		debug_log(green("ciphertexts equal") nl);
	}

	t1 = HAL_GetTick();
	status = app_sw_crypto.aes_256_cbc_decrypt(
		&app_sw_crypto,
		random_iv, random_key, data_sw, test_size
	);
	t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("sw decrypt ok" nl);
	} else {
		error_log(red("error while sw decrypt") nl);
	}
	info_log("sw done in %" PRIu32 " ms" nl, t2 - t1);
	dump_hex(data_sw, test_size);

	t1 = HAL_GetTick();
	status = app_hw_crypto.aes_256_cbc_decrypt(
		&app_hw_crypto,
		random_iv, random_key, data_hw, test_size
	);
	t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("hw decrypt ok" nl);
	} else {
		error_log(red("error while hw decrypt") nl);
	}
	info_log("hw done in %" PRIu32 " ms" nl, t2 - t1);
	dump_hex(data_hw, test_size);

	if (memcmp(data_sw, data_hw, test_size) != 0) {
		error_log(red("plaintexts mismatch") nl);
	} else {
		debug_log(green("plaintexts equal") nl);
	}

}

void app_test_hash_zero(void) {

	info_log(cyan("app_test_hash_zero") nl);

	app_sw_crypto.rng_init(&app_sw_crypto, 0);

	uint8_t data[1]; // zero-length variable-length arrays are not allowed

	assert(app_sw_crypto.sha256->output_size == app_hw_crypto.sha256->output_size);
	uint8_t hash_sw[app_sw_crypto.sha256->output_size];
	uint8_t hash_hw[app_hw_crypto.sha256->output_size];

	uint32_t t1;
	uint32_t t2;
	ctap_crypto_status_t status;

	t1 = HAL_GetTick();
	status = app_sw_crypto.sha256_compute_digest(
		&app_sw_crypto,
		data, 0,
		hash_sw
	);
	t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("sw sha256_compute_digest ok" nl);
	} else {
		error_log(red("error while sw sha256_compute_digest") nl);
	}
	info_log("sw done in %" PRIu32 " ms" nl, t2 - t1);
	dump_hex(hash_sw, sizeof(hash_sw));

	t1 = HAL_GetTick();
	status = app_hw_crypto.sha256_compute_digest(
		&app_hw_crypto,
		data, 0,
		hash_hw
	);
	t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("hw sha256_compute_digest ok" nl);
	} else {
		error_log(red("error while hw sha256_compute_digest") nl);
	}
	info_log("hw done in %" PRIu32 " ms" nl, t2 - t1);
	dump_hex(hash_hw, sizeof(hash_hw));

	if (memcmp(hash_sw, hash_hw, sizeof(hash_sw)) != 0) {
		error_log(red("hashes mismatch") nl);
	} else {
		debug_log(green("hashes equal") nl);
	}

}

void app_test_hash_big(void) {

	info_log(cyan("app_test_hash_big") nl);

	app_sw_crypto.rng_init(&app_sw_crypto, 0);

	uint8_t data[333];
	app_sw_crypto.rng_generate_data(&app_sw_crypto, data, sizeof(data));
	debug_log("data: ");
	dump_hex(data, sizeof(data));


	assert(app_sw_crypto.sha256->output_size == app_hw_crypto.sha256->output_size);
	uint8_t hash_sw[app_sw_crypto.sha256->output_size];
	uint8_t hash_hw[app_hw_crypto.sha256->output_size];

	uint32_t t1;
	uint32_t t2;
	ctap_crypto_status_t status;

	t1 = HAL_GetTick();
	status = app_sw_crypto.sha256_compute_digest(
		&app_sw_crypto,
		data, sizeof(data),
		hash_sw
	);
	t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("sw sha256_compute_digest ok" nl);
	} else {
		error_log(red("error while sw sha256_compute_digest") nl);
	}
	info_log("sw done in %" PRIu32 " ms" nl, t2 - t1);
	dump_hex(hash_sw, sizeof(hash_sw));

	t1 = HAL_GetTick();
	status = app_hw_crypto.sha256_compute_digest(
		&app_hw_crypto,
		data, sizeof(data),
		hash_hw
	);
	t2 = HAL_GetTick();
	if (status == CTAP_CRYPTO_OK) {
		info_log("hw sha256_compute_digest ok" nl);
	} else {
		error_log(red("error while hw sha256_compute_digest") nl);
	}
	info_log("hw done in %" PRIu32 " ms" nl, t2 - t1);
	dump_hex(hash_hw, sizeof(hash_hw));

	if (memcmp(hash_sw, hash_hw, sizeof(hash_sw)) != 0) {
		error_log(red("hashes mismatch") nl);
	} else {
		debug_log(green("hashes equal") nl);
	}

}

void app_test_hash_big_two_parts(void) {

	info_log(cyan("app_test_hash_big") nl);

	app_sw_crypto.rng_init(&app_sw_crypto, 0);

	uint8_t data1[49];
	app_sw_crypto.rng_generate_data(&app_sw_crypto, data1, sizeof(data1));
	debug_log("data1: ");
	dump_hex(data1, sizeof(data1));
	uint8_t data2[87];
	app_sw_crypto.rng_generate_data(&app_sw_crypto, data2, sizeof(data2));
	debug_log("data2: ");
	dump_hex(data2, sizeof(data2));


	assert(app_sw_crypto.sha256->output_size == app_hw_crypto.sha256->output_size);
	uint8_t hash_sw[app_sw_crypto.sha256->output_size];
	uint8_t hash_hw[app_hw_crypto.sha256->output_size];

	uint32_t t1;
	uint32_t t2;
	ctap_crypto_status_t status;

	t1 = HAL_GetTick();
	const hash_alg_t *const sw_sha256 = app_sw_crypto.sha256;
	uint8_t sw_sha256_ctx[sw_sha256->ctx_size];
	app_sw_crypto.sha256_bind_ctx(&app_sw_crypto, sw_sha256_ctx);
	sw_sha256->init(sw_sha256_ctx);
	sw_sha256->update(sw_sha256_ctx, data1, sizeof(data1));
	sw_sha256->update(sw_sha256_ctx, data2, sizeof(data2));
	sw_sha256->final(sw_sha256_ctx, hash_sw);
	t2 = HAL_GetTick();
	// if (status == CTAP_CRYPTO_OK) {
	// 	info_log("sw sha256_compute_digest ok" nl);
	// } else {
	// 	error_log(red("error while sw sha256_compute_digest") nl);
	// }
	info_log("sw done in %" PRIu32 " ms, sizeof(sw_sha256_ctx) = %" PRIsz nl, t2 - t1, sizeof(sw_sha256_ctx));
	dump_hex(hash_sw, sizeof(hash_sw));

	t1 = HAL_GetTick();
	const hash_alg_t *const hw_sha256 = app_hw_crypto.sha256;
	uint8_t hw_sha256_ctx[hw_sha256->ctx_size];
	app_hw_crypto.sha256_bind_ctx(&app_hw_crypto, hw_sha256_ctx);
	hw_sha256->init(hw_sha256_ctx);
	hw_sha256->update(hw_sha256_ctx, data1, sizeof(data1));
	hw_sha256->update(hw_sha256_ctx, data2, sizeof(data2));
	hw_sha256->final(hw_sha256_ctx, hash_hw);
	t2 = HAL_GetTick();
	// if (status == CTAP_CRYPTO_OK) {
	// 	info_log("hw sha256_compute_digest ok" nl);
	// } else {
	// 	error_log(red("error while hw sha256_compute_digest") nl);
	// }
	info_log("hw done in %" PRIu32 " ms, sizeof(hw_sha256_ctx) = %" PRIsz nl, t2 - t1, sizeof(hw_sha256_ctx));
	dump_hex(hash_hw, sizeof(hash_hw));

	if (memcmp(hash_sw, hash_hw, sizeof(hash_sw)) != 0) {
		error_log(red("hashes mismatch") nl);
	} else {
		debug_log(green("hashes equal") nl);
	}

}
