#include "ctap.h"

#define CTAP_MEMORY_MAX_NUM_CREDENTIALS 50
static size_t num_stored_credentials = 0;
static size_t num_stored_discoverable_credentials = 0;
static ctap_credentials_map_key credentials_map_keys[CTAP_MEMORY_MAX_NUM_CREDENTIALS];
static ctap_credentials_map_value credentials_map_values[CTAP_MEMORY_MAX_NUM_CREDENTIALS];

size_t ctap_get_num_stored_credentials(void) {
	return num_stored_credentials;
}

size_t ctap_get_num_stored_discoverable_credentials(void) {
	return num_stored_discoverable_credentials;
}

size_t ctap_get_num_max_possible_remaining_discoverable_credentials(void) {
	// currently we store all credentials (even the non-discoverable credentials)
	return CTAP_MEMORY_MAX_NUM_CREDENTIALS - num_stored_credentials;
}

ctap_credentials_map_key *ctap_get_credential_key_by_idx(const int idx) {
	assert(0 <= idx && idx < CTAP_MEMORY_MAX_NUM_CREDENTIALS);
	return &credentials_map_keys[idx];
}

ctap_credentials_map_value *ctap_get_credential_value_by_idx(const int idx) {
	assert(0 <= idx && idx < CTAP_MEMORY_MAX_NUM_CREDENTIALS);
	return &credentials_map_values[idx];
}

bool ctap_credential_matches_rp_id_hash(
	const ctap_credentials_map_key *key,
	const uint8_t *rp_id_hash
) {
	return memcmp(key->rpId.hash, rp_id_hash, CTAP_SHA256_HASH_SIZE) == 0;
}

bool ctap_credential_matches_rp(
	const ctap_credentials_map_key *key,
	const CTAP_rpId *rp_id
) {
	const bool rp_id_matches = (key->truncated & CTAP_truncated_rpId) == 0u
		// if the rpId was NOT truncated, then we can compare the exact rpId values
		? ctap_string_matches(&key->rpId.id, &rp_id->id)
		// otherwise, our only option is to compare the hashes
		: ctap_credential_matches_rp_id_hash(key, rp_id->hash);
	if (!rp_id_matches) {
		return false;
	}
	// debugging assert: rp_id_matches => the hashes are equal
	assert(ctap_credential_matches_rp_id_hash(key, rp_id->hash));
	return true;
}

int ctap_find_credential_index(
	const CTAP_rpId *rp_id,
	const CTAP_userHandle *user_handle
) {

	for (int i = 0; i < CTAP_MEMORY_MAX_NUM_CREDENTIALS; ++i) {

		ctap_credentials_map_key *key = &credentials_map_keys[i];

		if (!key->used) {
			continue;
		}
		if (!ctap_credential_matches_rp(key, rp_id)) {
			continue;
		}
		if (!ctap_string_matches(&key->user.id, user_handle)) {
			continue;
		}

		return i;

	}

	return -1;

}

int ctap_lookup_credential_by_desc(const CTAP_credDesc *cred_desc) {

	if (cred_desc->type != CTAP_pubKeyCredType_public_key || cred_desc->id.size != 128) {
		return -1;
	}

	for (int i = 0; i < CTAP_MEMORY_MAX_NUM_CREDENTIALS; ++i) {
		ctap_credentials_map_key *key = &credentials_map_keys[i];
		if (!key->used) {
			continue;
		}
		ctap_credentials_map_value *value = &credentials_map_values[i];
		static_assert(sizeof(value->id) == 128, "sizeof(value->id) == 128");
		if (memcmp(cred_desc->id.data, value->id, 128) == 0) {
			return i;
		}
	}

	return -1;

}

uint8_t ctap_store_credential(
	const CTAP_rpId *rp_id,
	const CTAP_userEntity *user,
	const ctap_credentials_map_value *credential
) {

	int slot;

	// If a credential for the same rpId and userHandle already exists on the authenticator,
	// then overwrite that credential.
	slot = ctap_find_credential_index(
		rp_id,
		&user->id
	);

	// Otherwise, find a free map slot and update the key.
	if (slot == -1) {
		for (int i = 0; i < CTAP_MEMORY_MAX_NUM_CREDENTIALS; ++i) {
			ctap_credentials_map_key *key = &credentials_map_keys[i];
			if (!key->used) {
				slot = i;
				key->used = true;

				static_assert(
					sizeof(key->rpId.hash) == sizeof(rp_id->hash),
					"sizeof(key->rpId.hash) == sizeof(rp_id->hash)"
				);
				memcpy(key->rpId.hash, rp_id->hash, sizeof(key->rpId_hash));
				if (ctap_store_arbitrary_length_string(
					&rp_id->id,
					&key->rpId.id,
					key->rpId_buffer,
					sizeof(key->rpId_buffer),
					ctap_maybe_truncate_rp_id
				)) {
					key->truncated |= CTAP_truncated_rpId;
				}

				key->user.present = user->present;

				// The WebAuthn spec defines a maximum size of 64 bytes for the userHandle (user.id).
				static_assert(
					sizeof(key->userId_buffer) == CTAP_USER_ENTITY_ID_MAX_SIZE,
					"sizeof(key->userId_buffer) == CTAP_USER_ENTITY_ID_MAX_SIZE"
				);
				// Note: This should already be ensured by the checks in parse_user_entity().
				if ((
					key->user.id.size > sizeof(key->userId_buffer)
					|| !ctap_param_is_present(user, CTAP_userEntity_id)
				)) {
					return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
				}
				if (ctap_store_arbitrary_length_string(
					&user->id,
					&key->user.id,
					key->userId_buffer,
					sizeof(key->userId_buffer),
					ctap_maybe_truncate_string
				)) {
					// This should never be reached thanks to the
					// `key->user.id.size > sizeof(key->userId_buffer)` check above.
					assert(false);
				}

				if (ctap_param_is_present(user, CTAP_userEntity_name)) {
					if (ctap_store_arbitrary_length_string(
						&user->name,
						&key->user.name,
						key->userName_buffer,
						sizeof(key->userName_buffer),
						ctap_maybe_truncate_string
					)) {
						key->truncated |= CTAP_truncated_userName;
					}
				}
				if (ctap_param_is_present(user, CTAP_userEntity_displayName)) {
					if (ctap_store_arbitrary_length_string(
						&user->displayName,
						&key->user.displayName,
						key->userDisplayName_buffer,
						sizeof(key->userDisplayName_buffer),
						ctap_maybe_truncate_string
					)) {
						key->truncated |= CTAP_truncated_userDisplayName;
					}
				}

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
	value->signCount = credential->signCount;
	memcpy(value->id, credential->id, sizeof(value->id));
	value->credProtect = credential->credProtect;
	memcpy(value->private_key, credential->private_key, sizeof(value->private_key));
	memcpy(value->CredRandomWithUV, credential->CredRandomWithUV, sizeof(value->CredRandomWithUV));
	memcpy(value->CredRandomWithoutUV, credential->CredRandomWithoutUV, sizeof(value->CredRandomWithoutUV));

	num_stored_credentials++;
	if (credential->discoverable) {
		num_stored_discoverable_credentials++;
	}

	return CTAP2_OK;

}

uint8_t ctap_delete_credential(const int idx) {

	assert(0 <= idx && idx < CTAP_MEMORY_MAX_NUM_CREDENTIALS);

	ctap_credentials_map_key *key = &credentials_map_keys[idx];
	ctap_credentials_map_value *value = &credentials_map_values[idx];

	assert(key->used);

	num_stored_credentials--;
	if (value->discoverable) {
		num_stored_discoverable_credentials--;
	}

	memset(key, 0, sizeof(ctap_credentials_map_key)); // ensures key->used == false
	memset(value, 0, sizeof(ctap_credentials_map_value));

	return CTAP2_OK;

}

void ctap_reset_credentials_store(void) {
	num_stored_credentials = 0;
	num_stored_discoverable_credentials = 0;
	memset(credentials_map_keys, 0, sizeof(credentials_map_keys));
	memset(credentials_map_values, 0, sizeof(credentials_map_values));
}

bool ctap_should_add_credential_to_list(
	const ctap_credentials_map_value *cred_value,
	const bool is_from_allow_list,
	const bool response_has_uv
) {
	// 6.2.2. authenticatorGetAssertion Algorithm, 7. Locate all credentials ...
	//   https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#op-getassn-step-locate-credentials
	// 7.4. ... if credential protection for a credential
	//      is marked as userVerificationRequired, and the "uv" bit is false in the response,
	//      remove that credential from the applicable credentials list.
	if ((
		cred_value->credProtect == CTAP_extension_credProtect_3_userVerificationRequired
		&& !response_has_uv
	)) {
		// do not add this credential to the list
		return false;
	}
	// 7.5. ... if credential protection for a credential
	//      is marked as userVerificationOptionalWithCredentialIDList and there is no allowList passed by
	//      the client and the "uv" bit is false in the response, remove that credential
	//      from the applicable credentials list.
	if ((
		cred_value->credProtect == CTAP_extension_credProtect_2_userVerificationOptionalWithCredentialIDList
		&& !is_from_allow_list
		&& !response_has_uv
	)) {
		// do not add this credential to the list
		return false;
	}
	return true;
}

uint8_t ctap_find_discoverable_credentials_by_rp_id(
	const CTAP_rpId *rp_id,
	const uint8_t *rp_id_hash,
	const bool response_has_uv,
	ctap_credential *credentials,
	size_t *const num_credentials,
	const size_t max_num_credentials
) {

	debug_log("ctap_find_discoverable_credentials_by_rp_id" nl);

	assert(rp_id != NULL || rp_id_hash != NULL);

	size_t credentials_num = 0;

	for (int i = 0; i < CTAP_MEMORY_MAX_NUM_CREDENTIALS; ++i) {

		ctap_credentials_map_key *key = &credentials_map_keys[i];

		if (!key->used) {
			continue;
		}

		if (rp_id != NULL) {
			if (!ctap_credential_matches_rp(key, rp_id)) {
				continue;
			}
		} else if (rp_id_hash != NULL) {
			if (!ctap_credential_matches_rp_id_hash(key, rp_id_hash)) {
				continue;
			}
		} else {
			assert(false);
			continue;
		}

		ctap_credentials_map_value *value = &credentials_map_values[i];

		if (!value->discoverable) {
			debug_log("find_credentials_by_rp_id: skipping non-discoverable credential" nl);
			continue;
		}

		if (!ctap_should_add_credential_to_list(value, false, response_has_uv)) {
			debug_log("find_credentials_by_rp_id: skipping credential due to its credProtect" nl);
			continue;
		}

		if (credentials_num == max_num_credentials) {
			error_log(
				red("find_credentials_by_rp_id: credentials_max_size (%" PRIsz ") reached") nl,
				max_num_credentials
			);
			return CTAP1_ERR_INVALID_LENGTH;
		}
		ctap_credential *credential = &credentials[credentials_num++];
		credential->key = key;
		credential->value = value;

	}

	*num_credentials = credentials_num;

	return CTAP2_OK;

}

static bool is_rp_id_in_the_list(
	const CTAP_rpId *rp_id,
	CTAP_rpId **rp_ids,
	const size_t num_rp_ids
) {

	for (size_t i = 0; i < num_rp_ids; ++i) {
		if (memcmp(rp_ids[i]->hash, rp_id->hash, CTAP_SHA256_HASH_SIZE) == 0) {
			return true;
		}
	}

	return false;

}

uint8_t ctap_enumerate_rp_ids_of_discoverable_credentials(
	CTAP_rpId **rp_ids,
	size_t *const num_rp_ids,
	const size_t max_num_rp_ids
) {

	debug_log("enumerate_rp_ids_of_discoverable_credentials" nl);

	size_t current_num_rp_ids = 0;

	for (int i = 0; i < CTAP_MEMORY_MAX_NUM_CREDENTIALS; ++i) {

		ctap_credentials_map_key *key = &credentials_map_keys[i];

		if (!key->used) {
			continue;
		}

		ctap_credentials_map_value *value = &credentials_map_values[i];

		if (!value->discoverable) {
			debug_log("enumerate_rp_ids_of_discoverable_credentials: skipping non-discoverable credential" nl);
			continue;
		}

		if (is_rp_id_in_the_list(&key->rpId, rp_ids, current_num_rp_ids)) {
			debug_log("enumerate_rp_ids_of_discoverable_credentials: skipping adding duplicate RP ID" nl);
			continue;
		}

		if (current_num_rp_ids == max_num_rp_ids) {
			error_log(
				red("enumerate_rp_ids_of_discoverable_credentials: max_num_rp_ids (%" PRIsz ") reached") nl,
				max_num_rp_ids
			);
			return CTAP2_ERR_REQUEST_TOO_LARGE;
		}
		rp_ids[current_num_rp_ids++] = &key->rpId;
	}

	*num_rp_ids = current_num_rp_ids;

	return CTAP2_OK;

}
