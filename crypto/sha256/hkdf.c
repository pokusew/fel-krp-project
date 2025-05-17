#include <string.h>
#include <assert.h>
#include "hkdf.h"

void hkdf_extract(
	const hash_alg_t *const hash_alg,
	void *const hmac_ctx,
	const uint8_t *const salt, const size_t salt_length,
	const uint8_t *const ikm, const size_t ikm_length,
	uint8_t *const prk
) {

	assert(prk != NULL);

	// HKDF-Extract(salt, IKM) -> PRK
	//   PRK = HMAC-Hash(salt, IKM)
	// https://datatracker.ietf.org/doc/html/rfc5869#section-2.2

	hmac_init(hmac_ctx, hash_alg, salt, salt_length);
	hmac_update(hmac_ctx, ikm, ikm_length);
	hmac_final(hmac_ctx, prk);

}

void hkdf_expand(
	const hash_alg_t *const hash_alg,
	void *const hmac_ctx,
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

	const size_t hash_output_size = hash_alg->output_size;

	assert(okm_length <= (255 * hash_output_size));
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
	while ((okm_pos + hash_output_size) <= okm_end) {
		hmac_init(hmac_ctx, hash_alg, prk, hash_output_size);
		hmac_update(hmac_ctx, okm_prev_pos, t_i_length);
		hmac_update(hmac_ctx, info, info_length);
		hmac_update(hmac_ctx, &i, 1);
		// write T(i) directly to the OKM
		hmac_final(hmac_ctx, okm_pos);
		t_i_length = hash_output_size; // t_i_length == 0 only in the first iteration
		okm_prev_pos = okm_pos;
		okm_pos += hash_output_size;
		i++;
	}
	if (okm_pos < okm_end) {
		hmac_init(hmac_ctx, hash_alg, prk, hash_output_size);
		hmac_update(hmac_ctx, okm_prev_pos, t_i_length);
		hmac_update(hmac_ctx, info, info_length);
		hmac_update(hmac_ctx, &i, 1);
		// write T(N) directly to a temporary buffer
		uint8_t t_n[hash_output_size];
		hmac_final(hmac_ctx, t_n);
		// copy the relevant bytes to the OKP
		const size_t remaining_bytes = okm_end - okm_pos;
		assert(remaining_bytes < hash_output_size);
		memcpy(okm_pos, t_n, remaining_bytes);
		// no need to update t_i_length, okm_prev_pos, okm_pos, i as we are at the end of the iteration
	}

}

void hkdf(
	const hash_alg_t *const hash_alg,
	const uint8_t *const salt, const size_t salt_length,
	const uint8_t *const ikm, const size_t ikm_length,
	const uint8_t *const info, const size_t info_length,
	const size_t okm_length,
	uint8_t *const okm
) {

	assert(okm_length <= (255 * hash_alg->output_size));

	uint8_t hmac_ctx[hmac_get_context_size(hash_alg)];

	uint8_t prk[hash_alg->output_size];

	hkdf_extract(
		hash_alg,
		hmac_ctx,
		salt, salt_length,
		ikm, ikm_length,
		prk
	);
	hkdf_expand(
		hash_alg,
		hmac_ctx,
		prk,
		info, info_length,
		okm_length,
		okm
	);

}
