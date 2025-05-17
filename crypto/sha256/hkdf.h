#ifndef LIONKEY_HKDF_H
#define LIONKEY_HKDF_H

#include <stdint.h>
#include <stddef.h>
#include "hmac.h"

/**
 * Derives an key (output keying material, OKM) from an input keying material (IKM)
 * using the HKDF (HMAC-based Extract-and-Expand Key Derivation Function, as described
 * in RFC 5869) and the given hashing algorithm (hash_alg)
 *
 * See RFC 5869, https://datatracker.ietf.org/doc/html/rfc5869, or https://en.wikipedia.org/wiki/HKDF.
 *
 * @param [in] hash_alg the hashing algorithm to use
 * @param [in] salt
 * @param [in] salt_length
 * @param [in] ikm input keying material
 * @param [in] ikm_length
 * @param [in] info optional context and application specific information
               (can be a zero-length string)
 * @param [in] info_length
 * @param [in] okm_length the desired length of the okm in bytes, must be <= 255 * LIONKEY_SHA256_OUTPUT_SIZE,
 *                        i.e., must be <= 255 * 32 = 8160, note: the limit is defined by the spec (RFC 5869)
 *                        and stems from the internal HKDF design
 * @param [out] okm output keying material, a buffer of at least `okm_length` bytes
 */
void hkdf(
	const hash_alg_t *hash_alg,
	const uint8_t *salt, size_t salt_length,
	const uint8_t *ikm, size_t ikm_length,
	const uint8_t *info, size_t info_length,
	size_t okm_length,
	uint8_t *okm
);

void hkdf_extract(
	const hash_alg_t *hash_alg,
	void *hmac_ctx,
	const uint8_t *salt, size_t salt_length,
	const uint8_t *ikm, size_t ikm_length,
	uint8_t *prk
);

void hkdf_expand(
	const hash_alg_t *hash_alg,
	void *hmac_ctx,
	const uint8_t *prk,
	const uint8_t *info, size_t info_length,
	size_t okm_length,
	uint8_t *okm
);

#endif // LIONKEY_HKDF_H
