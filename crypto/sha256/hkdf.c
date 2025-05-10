#include <string.h>
#include <assert.h>
#include "hkdf.h"

void hkdf_sha256_extract(
	hmac_sha256_ctx_t *const hmac_sha256_ctx,
	const uint8_t *const salt, const size_t salt_length,
	const uint8_t *const ikm, const size_t ikm_length,
	uint8_t *const prk
) {

	assert(prk != NULL);

	//  HKDF-Extract(salt, IKM) -> PRK
	// https://datatracker.ietf.org/doc/html/rfc5869#section-2.2

	hmac_sha256_init(hmac_sha256_ctx, salt, salt_length);
	hmac_sha256_update(hmac_sha256_ctx, ikm, ikm_length);
	hmac_sha256_final(hmac_sha256_ctx, prk);

}

void hkdf_sha256_expand(
	hmac_sha256_ctx_t *const hmac_sha256_ctx,
	const uint8_t *const prk,
	const uint8_t *const info, const size_t info_length,
	const size_t okm_length,
	uint8_t *const okm
) {

	if (okm_length == 0) {
		return;
	}

	//  HKDF-Expand(PRK, info, L) -> OKM
	// https://datatracker.ietf.org/doc/html/rfc5869#section-2.3

	assert(okm_length <= (255 * LIONKEY_SHA256_OUTPUT_SIZE));
	assert(okm != NULL);

	// HashLen = LIONKEY_SHA256_OUTPUT_SIZE
	// N = ceil(L/HashLen)
	// T(0) = empty string (zero length)
	// T(i) = HMAC-Hash(PRK, T(i - 1) | info | i)
	// T = T(1) | T(2) | T(3) | ... | T(N)
	// OKM = first `okm_length` bytes of T

	size_t t_i_length = 0;
	uint8_t *okm_pos = &okm[0];
	uint8_t *okm_prev_pos = okm_pos;
	const uint8_t *const okm_end = okm + okm_length;
	uint8_t i = 1;
	while ((okm_pos + LIONKEY_SHA256_OUTPUT_SIZE) <= okm_end) {
		hmac_sha256_init(hmac_sha256_ctx, prk, LIONKEY_SHA256_OUTPUT_SIZE);
		hmac_sha256_update(hmac_sha256_ctx, okm_prev_pos, t_i_length);
		hmac_sha256_update(hmac_sha256_ctx, info, info_length);
		hmac_sha256_update(hmac_sha256_ctx, &i, 1);
		// write T(i) directly to the OKM
		hmac_sha256_final(hmac_sha256_ctx, okm_pos);
		t_i_length = LIONKEY_SHA256_OUTPUT_SIZE; // t_i_length == 0 only in the first iteration
		okm_prev_pos = okm_pos;
		okm_pos += LIONKEY_SHA256_OUTPUT_SIZE;
		i++;
	}
	if (okm_pos < okm_end) {
		hmac_sha256_init(hmac_sha256_ctx, prk, LIONKEY_SHA256_OUTPUT_SIZE);
		hmac_sha256_update(hmac_sha256_ctx, okm_prev_pos, t_i_length);
		hmac_sha256_update(hmac_sha256_ctx, info, info_length);
		hmac_sha256_update(hmac_sha256_ctx, &i, 1);
		// write T(N) directly to a temporary buffer
		uint8_t t_n[LIONKEY_SHA256_OUTPUT_SIZE];
		hmac_sha256_final(hmac_sha256_ctx, t_n);
		// copy the relevant bytes to the OKP
		const size_t remaining_bytes = okm_end - okm_pos;
		assert(remaining_bytes < LIONKEY_SHA256_OUTPUT_SIZE);
		memcpy(okm_pos, t_n, remaining_bytes);
		// no need to update t_i_length, okm_prev_pos, okm_pos, i as we are at the end of the iteration
	}

}

void hkdf_sha256(
	const uint8_t *const salt, const size_t salt_length,
	const uint8_t *const ikm, const size_t ikm_length,
	const uint8_t *const info, const size_t info_length,
	const size_t okm_length,
	uint8_t *const okm
) {

	assert(okm_length <= (255 * LIONKEY_SHA256_OUTPUT_SIZE));

	hmac_sha256_ctx_t hmac_sha256_ctx;

	uint8_t prk[LIONKEY_SHA256_OUTPUT_SIZE];

	hkdf_sha256_extract(
		&hmac_sha256_ctx,
		salt, salt_length,
		ikm, ikm_length,
		prk
	);
	hkdf_sha256_expand(
		&hmac_sha256_ctx,
		prk,
		info, info_length,
		okm_length,
		okm
	);

}
