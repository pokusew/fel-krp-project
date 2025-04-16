#include "ctap.h"
#include <uECC.h>

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

static inline bool is_option_present(const CTAP_makeCredential *mc, const uint8_t option) {
	return (mc->options_present & option) == option;
}

static inline bool get_option_value(const CTAP_makeCredential *mc, const uint8_t option) {
	return (mc->options_values & option) == option;
}

static inline bool get_option_value_or_false(const CTAP_makeCredential *mc, const uint8_t option) {
	return is_option_present(mc, option) ? get_option_value(mc, option) : false;
}

static inline uint8_t verify(
	ctap_state_t *state,
	const CTAP_makeCredential *mc,
	ctap_pin_protocol_t *pin_protocol
) {
	hmac_sha256_ctx_t verify_ctx;
	if (pin_protocol->verify_init_with_pin_uv_auth_token(
		pin_protocol,
		&verify_ctx,
		&state->pin_uv_auth_token_state
	) != 0) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	pin_protocol->verify_update(
		pin_protocol,
		&verify_ctx,
		/* message */ mc->clientDataHash, sizeof(mc->clientDataHash)
	);
	if (pin_protocol->verify_final(
		pin_protocol,
		&verify_ctx,
		/* signature */ mc->pinUvAuthParam, mc->pinUvAuthParam_size
	) != 0) {
		return CTAP2_ERR_PIN_AUTH_INVALID;
	}
	return CTAP2_OK;
}

typedef struct ctap_credentials_map_key {
	bool used;
	CTAP_rpId rpId;
	CTAP_userHandle userHandle;
} ctap_credentials_map_key;

typedef struct ctap_credentials_map_value {
	bool discoverable;
	// credProtect extension
	uint8_t credProtect;
	// the actual private key
	uint8_t private_key[32];
	// hmac-secret extension
	uint8_t CredRandomWithUV[32];
	uint8_t CredRandomWithoutUV[32];
} ctap_credentials_map_value;

#define CTAP_MEMORY_MAX_NUM_CREDENTIALS 10

static ctap_credentials_map_key credentials_map_keys[CTAP_MEMORY_MAX_NUM_CREDENTIALS];
static ctap_credentials_map_value credentials_map_values[CTAP_MEMORY_MAX_NUM_CREDENTIALS];

static int find_credential_index(const CTAP_rpId *rp_id, const CTAP_userHandle *user_handle) {

	for (int i = 0; i < CTAP_MEMORY_MAX_NUM_CREDENTIALS; ++i) {
		ctap_credentials_map_key *key = &credentials_map_keys[i];
		if (!key->used) {
			continue;
		}
		if (!ctap_rp_id_matches(&key->rpId, rp_id)) {
			continue;
		}
		if (!ctap_user_handle_matches(&key->userHandle, user_handle)) {
			continue;
		}
		return i;
	}

	return -1;

}

static uint8_t store_credential(
	const CTAP_rpId *rp_id,
	const CTAP_userHandle *user_handle,
	const ctap_credentials_map_value *credential
) {

	int slot;

	// If a credential for the same rpId and userHandle already exists on the authenticator,
	// then overwrite that credential.
	slot = find_credential_index(
		rp_id,
		user_handle
	);

	// Otherwise, find a free map slot and update the key.
	if (slot == -1) {
		for (int i = 0; i < CTAP_MEMORY_MAX_NUM_CREDENTIALS; ++i) {
			ctap_credentials_map_key *key = &credentials_map_keys[i];
			if (!key->used) {
				slot = i;
				key->used = false;
				key->rpId = *rp_id;
				key->userHandle = *user_handle;
				break;
			}
		}
	}

	// No free space left.
	if (slot == -1) {
		return CTAP2_ERR_KEY_STORE_FULL;
	}

	ctap_credentials_map_value *value = &credentials_map_values[slot];
	value->discoverable = credential->discoverable;
	value->credProtect = credential->credProtect;
	memcpy(value->private_key, credential->private_key, sizeof(value->private_key));
	memcpy(value->CredRandomWithUV, credential->CredRandomWithUV, sizeof(value->CredRandomWithUV));
	memcpy(value->CredRandomWithoutUV, credential->CredRandomWithoutUV, sizeof(value->CredRandomWithoutUV));

	return CTAP2_OK;

}

uint8_t ctap_make_credential(ctap_state_t *state, const uint8_t *request, size_t length) {

	uint8_t ret;
	CborError err;

	CborParser parser;
	CborValue it;
	ctap_parse_check(ctap_init_cbor_parser(request, length, &parser, &it));

	CTAP_makeCredential mc;
	ctap_parse_check(ctap_parse_make_credential(&it, &mc));

	const bool pinUvAuthParam_present = ctap_param_is_present(&mc, CTAP_makeCredential_pinUvAuthParam);
	ctap_pin_protocol_t *pin_protocol = NULL;

	// 6.1.2. authenticatorMakeCredential Algorithm
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-makeCred-authnr-alg
	// see also WebAuthn 6.3.2. The authenticatorMakeCredential Operation
	// https://w3c.github.io/webauthn/#sctn-op-make-cred

	// 1. If authenticator supports either pinUvAuthToken or clientPin features
	//    and the platform sends a zero length pinUvAuthParam:
	//    Note:
	//      This is done for backwards compatibility with CTAP2.0 platforms in the case
	//      where multiple authenticators are attached to the platform and the platform
	//      wants to enforce pinUvAuthToken feature semantics, but the user has to select
	//      which authenticator to get the pinUvAuthToken from.
	//      CTAP2.1 platforms SHOULD use 6.9 authenticatorSelection (0x0B).
	if (pinUvAuthParam_present && mc.pinUvAuthParam_size == 0) {
		// 1. Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
		ctap_user_presence_result_t up_result = ctap_wait_for_user_presence();
		switch (up_result) {
			case CTAP_UP_RESULT_CANCEL:
				// handling of 11.2.9.1.5. CTAPHID_CANCEL (0x11)
				return CTAP2_ERR_KEEPALIVE_CANCEL;
			case CTAP_UP_RESULT_TIMEOUT:
			case CTAP_UP_RESULT_DENY:
				// 2. If the user declines permission, or the operation times out,
				//    then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
				return CTAP2_ERR_OPERATION_DENIED;
			case CTAP_UP_RESULT_ALLOW:
				// 3. If evidence of user interaction is provided in this step then return either CTAP2_ERR_PIN_NOT_SET
				//    if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN has been set.
				return !state->persistent.is_pin_set ? CTAP2_ERR_PIN_NOT_SET : CTAP2_ERR_PIN_INVALID;
		}
	}

	// 2. If the pinUvAuthParam parameter is present:
	if (pinUvAuthParam_present) {
		// 2. If the pinUvAuthProtocol parameter is absent,
		//    return CTAP2_ERR_MISSING_PARAMETER error.
		if (!ctap_param_is_present(&mc, CTAP_makeCredential_pinUvAuthProtocol)) {
			return CTAP2_ERR_MISSING_PARAMETER;
		}
		// 1. If the pinUvAuthProtocol parameter's value is not supported,
		//    return CTAP1_ERR_INVALID_PARAMETER error.
		ctap_parse_check(ctap_get_pin_protocol(state, mc.pinUvAuthProtocol, &pin_protocol));
	}

	// 3. Validate pubKeyCredParams and choose the first supported algorithm.
	ctap_parse_check(ctap_parse_make_credential_pub_key_cred_params(&mc));
	debug_log("chosen algorithm = %" PRId32 nl, mc.pubKeyCredParams_chosen.alg);

	// 4. Create a new authenticatorMakeCredential response structure
	//    and initialize both its "uv" bit and "up" bit as false.
	CTAP_authenticator_data auth_data;
	memset(&auth_data, 0, sizeof(auth_data));
	// alls flags are initialized to 0 (false)

	const bool rk = get_option_value_or_false(&mc, CTAP_makeCredential_option_rk);
	debug_log("option rk=%d" nl, rk);
	// 5. If the options parameter is present, process all option keys and values present in the parameter.
	//    Treat any option keys that are not understood as absent.
	if (ctap_param_is_present(&mc, CTAP_makeCredential_options)) {
		// user verification:
		//   Note:
		//     Use of this "uv" option key is deprecated in CTAP2.1.
		//     Instead, platforms SHOULD create a pinUvAuthParam by obtaining pinUvAuthToken
		//     via getPinUvAuthTokenUsingUvWithPermissions or getPinUvAuthTokenUsingPinWithPermissions,
		//     as appropriate.
		//   Note:
		//     pinUvAuthParam and the "uv" option are processed as mutually exclusive
		//     with pinUvAuthParam taking precedence.
		const bool uv = pinUvAuthParam_present ? false : get_option_value_or_false(&mc, CTAP_makeCredential_option_uv);
		if (uv) {
			// 3. If the "uv" option is true then:
			//    1. If the authenticator does not support a built-in user verification method
			//       (as is the case with the current version of LionKey),
			//       end the operation by returning CTAP2_ERR_INVALID_OPTION.
			//       Note: One would expect the CTAP2_ERR_UNSUPPORTED_OPTION error code,
			//             but the spec really says CTAP2_ERR_INVALID_OPTION.
			return CTAP2_ERR_INVALID_OPTION;
		}
		// user presence (defaults to true):
		//   Instructs the authenticator to require user consent to complete the operation.
		//   Platforms MAY send the "up" option key to CTAP2.1 authenticators,
		//   and its value MUST be true if present.
		//   The value false will cause a CTAP2_ERR_INVALID_OPTION response regardless of authenticator version.
		if ((
			is_option_present(&mc, CTAP_makeCredential_option_up)
			&& get_option_value(&mc, CTAP_makeCredential_option_up) == false
		)) {
			return CTAP2_ERR_INVALID_OPTION;
		}
	}

	// 6. (not applicable to LionKey) If the alwaysUv option ID is present and true then ...

	// 7. If the makeCredUvNotRqd option ID is present and set to true in the authenticatorGetInfo response:
	//    Note:
	//      This step returns an error if the platform tries to create a discoverable credential
	//      without performing some form of user verification.
	if (state->persistent.is_pin_set && !pinUvAuthParam_present && rk) {
		return CTAP2_ERR_PUAT_REQUIRED;
	}

	// 8. (not applicable to LionKey) Else: (the makeCredUvNotRqd option ID in authenticatorGetInfo's response
	//    is present with the value false or is absent): ...

	// 9. If the enterpriseAttestation parameter is present:
	if (ctap_param_is_present(&mc, CTAP_makeCredential_enterpriseAttestation)) {
		// 1. If the authenticator is not enterprise attestation capable,
		//    or the authenticator is enterprise attestation capable but enterprise attestation is disabled,
		//    then end the operation by returning CTAP1_ERR_INVALID_PARAMETER.
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	// 10. Allow the authenticator to create a non-discoverable credential
	//     without requiring some form of user verification under the below specific criteria.
	const bool allow_no_verification = !rk && !pinUvAuthParam_present;
	debug_log("allow_no_verification=%d" nl, allow_no_verification);
	// 11. If the authenticator is protected by some form of user verification , then:
	if (!allow_no_verification && state->persistent.is_pin_set) {
		// 1. If pinUvAuthParam parameter is present (implying the "uv" option is false (see Step 5)):
		if (pinUvAuthParam_present) {
			// This should be ensured by Step 2.
			assert(pin_protocol != NULL);
			// 1. Call verify(pinUvAuthToken, clientDataHash, pinUvAuthParam).
			//    1. If the verification returns error,
			//       then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID error.
			ctap_parse_check(verify(state, &mc, pin_protocol));
			// 2. Verify that the pinUvAuthToken has the mc permission,
			//    if not, then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
			if (ctap_pin_uv_auth_token_has_permissions(
				&state->pin_uv_auth_token_state,
				CTAP_clientPIN_pinUvAuthToken_permission_mc
			)) {
				return CTAP2_ERR_PIN_AUTH_INVALID;
			}
			// 3. If the pinUvAuthToken has a permissions RP ID associated:
			//    1. If the permissions RP ID does not match the rp.id in this request,
			//       then end the operation by returning CTAP2_ERR_PIN_AUTH_INVALID.
			if ((
				state->pin_uv_auth_token_state.rpId_set
				&& ctap_rp_id_matches(&state->pin_uv_auth_token_state.rpId, &mc.rpId)
			)) {
				return CTAP2_ERR_PIN_AUTH_INVALID;
			}
			// TODO: Implement userVerifiedFlagValue handling in steps 4, 5, 6.
			// 7. If the pinUvAuthToken does not have a permissions RP ID associated:
			//    1. Associate the request's rp.id parameter value with the pinUvAuthToken as its permissions RP ID.
			if (!state->pin_uv_auth_token_state.rpId_set) {
				state->pin_uv_auth_token_state.rpId = mc.rpId;
				state->pin_uv_auth_token_state.rpId_set = true;
			}
		}
		// 2. If the "uv" option is present and set to true (implying the pinUvAuthParam parameter is not present,
		//    and that the authenticator supports an enabled built-in user verification method, see Step 5):
		//    (not applicable to LionKey)
	}

	// TODO: 12. If the excludeList parameter is present and contains a credential ID
	//           created by this authenticator, that is bound to the specified rp.id: ...

	// 13. (not applicable to LionKey) If evidence of user interaction was provided as part of Step 11
	//     (i.e., by invoking performBuiltInUv()): ...

	// 14. If the "up" option is set to true:
	//     Note: Step 3 ensures that the "up" option is effectively always true.
	// 14.1. and 14.2. together (since we do not perform step 13, the "up" bit in the response
	// can never be true at this point and thus the 14.2.1. check is unnecessary).
	const bool user_present = pinUvAuthParam_present && ctap_pin_uv_auth_token_get_user_present_flag_value(
		&state->pin_uv_auth_token_state
	);
	if (!user_present) {
		// 1. Request evidence of user interaction in an authenticator-specific way (e.g., flash the LED light).
		//    If the authenticator has a display, show the items contained within the user and rp parameter
		//    structures to the user, and request permission to create a credential.
		ctap_user_presence_result_t up_result = ctap_wait_for_user_presence();
		switch (up_result) {
			case CTAP_UP_RESULT_CANCEL:
				// handling of 11.2.9.1.5. CTAPHID_CANCEL (0x11)
				return CTAP2_ERR_KEEPALIVE_CANCEL;
			case CTAP_UP_RESULT_TIMEOUT:
			case CTAP_UP_RESULT_DENY:
				// 2. If the user declines permission, or the operation times out,
				//    then end the operation by returning CTAP2_ERR_OPERATION_DENIED.
				return CTAP2_ERR_OPERATION_DENIED;
			case CTAP_UP_RESULT_ALLOW:
				// continue
				break;
		}
	}
	// 14.3. Set the "up" bit to true in the response.
	auth_data.flags |= CTAP_authenticator_data_flags_up;
	// 14.4. Call clearUserPresentFlag(), clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw().
	//       Note: This consumes both the "user present state", sometimes referred to as the "cached UP",
	//       and the "user verified state", sometimes referred to as "cached UV".
	//       These functions are no-ops if there is not an in-use pinUvAuthToken.
	ctap_pin_uv_auth_token_clear_user_present_flag(&state->pin_uv_auth_token_state);
	ctap_pin_uv_auth_token_clear_user_verified_flag(&state->pin_uv_auth_token_state);
	ctap_pin_uv_auth_token_clear_permissions_except_lbw(&state->pin_uv_auth_token_state);

	// extensions processing

	ctap_credentials_map_value credential;
	credential.discoverable = rk;

	// 12.1. Credential Protection (credProtect)
	// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-credProtect-extension
	//   credProtect value is persisted with the credential.
	//   If no credProtect extension was included in the request the authenticator
	//   SHOULD use the default value of 1 for compatibility with CTAP2.0 platforms.
	//   The authenticator MUST NOT return an unsolicited credProtect extension output.
	credential.credProtect = CTAP_extension_credProtect_1_userVerificationOptional;

	// 12.5. HMAC Secret Extension (hmac-secret)
	//   authenticatorMakeCredential additional behaviors
	//     The authenticator generates two random 32-byte values (called CredRandomWithUV and CredRandomWithoutUV)
	//     and associates them with the credential.
	//     Note:
	//       Authenticator SHOULD generate CredRandomWithUV/CredRandomWithoutUV and associate
	//       them with the credential, even if hmac-secret extension is NOT present
	//       in authenticatorMakeCredential request.
	ctap_generate_rng(credential.CredRandomWithUV, sizeof(credential.CredRandomWithUV));
	ctap_generate_rng(credential.CredRandomWithoutUV, sizeof(credential.CredRandomWithoutUV));

	// 15. If the extensions parameter is present:
	if (ctap_param_is_present(&mc, CTAP_makeCredential_extensions)) {
		// 1. Process any extensions that this authenticator supports,
		//    ignoring any that it does not support.
		// 2. Authenticator extension outputs generated by the authenticator
		//    extension processing are returned in the authenticator data.
		//    The set of keys in the authenticator extension outputs map MUST
		//    be equal to, or a subset of, the keys of the authenticator extension inputs map.
		// Note: Some extensions may produce different output depending on the state of
		// the "uv" bit and/or "up" bit in the response.
		if ((mc.extensions_present & CTAP_extension_credProtect) != 0u) {
			// Only set, if the given credProtect value is valid and non-default.
			// Note:
			//   The spec does not explicitly say what to do with invalid credProtect values.
			//   We decided to ignore any invalid values here since the actual used value will be returned
			//   in the response and the client/RP can decide, what to do.
			if ((
				mc.credProtect == CTAP_extension_credProtect_2_userVerificationOptionalWithCredentialIDList
				|| mc.credProtect == CTAP_extension_credProtect_3_userVerificationRequired
			)) {
				credential.credProtect = mc.credProtect;
			}
		}
	}

	// 16. Generate a new credential key pair for the algorithm chosen in step 3.
	// 17. If the "rk" option is set to true:
	//     1. The authenticator MUST create a discoverable credential.
	//     2. If a credential for the same rp.id and account ID already exists on the authenticator:
	//        1. If the existing credential contains a largeBlobKey, an authenticator MAY erase any
	//           associated large-blob data. Platforms MUST NOT assume that authenticators will do this.
	//           Platforms can later garbage collect any orphaned large-blobs.
	//        2. Overwrite that credential.
	//     3. Store the user parameter along with the newly-created key pair.
	//     4. If authenticator does not have enough internal storage to persist the new credential,
	//        return CTAP2_ERR_KEY_STORE_FULL.
	// 18. Otherwise, if the "rk" option is false: the authenticator MUST create a non-discoverable credential.
	//     Note: This step is a change from CTAP2.0 where if the "rk" option is false the authenticator
	//           could optionally create a discoverable credential.

	ctap_generate_rng(credential.private_key, sizeof(credential.private_key));
	uint8_t public_key[64];
	if (uECC_compute_public_key(
		credential.private_key,
		public_key,
		uECC_secp256r1()
	) != 1) {
		error_log("uECC_compute_public_key failed" nl);
		return CTAP1_ERR_OTHER;
	}
	ctap_parse_check(store_credential(&mc.rpId, &mc.user.id, &credential));

	// 19. Generate an attestation statement for the newly-created credential using clientDataHash,
	//     taking into account the value of the enterpriseAttestation parameter, if present,
	//     as described above in Step 9.

	// TODO: Generate the attestation statement.

	return CTAP1_ERR_OTHER;

}

// https://w3c.github.io/webauthn/#credential-id
// Credential ID
//
// A probabilistically-unique byte sequence identifying a public key credential source
// and its authentication assertions. At most 1023 bytes long.
//
// Credential IDs are generated by authenticators in two forms:
//
//   1. At least 16 bytes that include at least 100 (~ 13 bytes) bits of entropy, or
//
//   2. The public key credential source, without its Credential ID or mutable items,
//      encrypted so only its managing authenticator can decrypt it.
//      This form allows the authenticator to be nearly stateless,
//      by having the Relying Party store any necessary state.
//
//   Note: [FIDO-UAF-AUTHNR-CMDS] includes guidance on encryption techniques under "Security Guidelines".
//     https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-uaf-authnr-cmds-v1.1-id-20170202.html#security-guidelines:~:text=regarding%20random%20numbers-,KeyHandle,-It%20is%20highly
//       It is highly recommended to use authenticated encryption while wrapping key handles with Wrap.sym.
//       Algorithms such as AES-GCM and AES-CCM are most suitable for this operation.
//     https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-uaf-authnr-cmds-v1.1-id-20170202.html#security-guidelines:~:text=the%20authenticator%20together.-,Wrap.sym,-If%20the%20authenticator
//        Refer to [SP800-57] and [SP800-38F] publications for more information
//        about choosing the right wrapping algorithm and implementing it correctly.
//
//   Relying Parties do not need to distinguish these two Credential ID forms.
//

// Each authenticator stores a credentials map, a map from (rpId, userHandle) to public key credential source.
