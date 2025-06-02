#include "ctap_credentials_store.h"
#include "compiler.h"

size_t ctap_count_num_stored_credentials(const ctap_storage_t *const storage, bool only_discoverable) {

	ctap_storage_item_t item = {
		.key = CTAP_STORAGE_KEY_CREDENTIAL,
	};

	size_t num_stored_discoverable_credentials = 0u;

	while (storage->find_item(storage, &item) == CTAP_STORAGE_OK) {

		if (item.size < sizeof(ctap_credential_source_t)) {
			error_log("skipping invalid credential item" nl);
			continue;
		}

		const ctap_credential_handle_t credential = {
			.source = (const ctap_credential_source_t *) item.data,
			.item_handle = item.handle,
		};

		if (!only_discoverable || ctap_credential_is_discoverable(&credential)) {
			num_stored_discoverable_credentials++;
		}

	}

	return num_stored_discoverable_credentials;

}

size_t ctap_count_num_stored_discoverable_credentials(const ctap_storage_t *storage) {
	// currently we store all credentials (even the non-discoverable credentials)
	return ctap_count_num_stored_credentials(storage, true);
}

size_t ctap_get_num_max_possible_remaining_discoverable_credentials(const ctap_storage_t *const storage) {
	const size_t source_max_total_size =
		sizeof(ctap_credential_source_t)
		+ CTAP_RP_ID_MAX_SIZE
		+ CTAP_USER_ENTITY_ID_MAX_SIZE
		+ CTAP_USER_ENTITY_NAME_MAX_SIZE
		+ CTAP_USER_ENTITY_DISPLAY_NAME_MAX_SIZE;
	const ctap_storage_item_t max_sized_credential = {
		.key = CTAP_STORAGE_KEY_CREDENTIAL,
		.size = source_max_total_size,
	};
	return storage->estimate_num_remaining_items(storage, &max_sized_credential);
}

bool ctap_credential_matches_rp_id_hash(
	const ctap_credential_handle_t *credential,
	const uint8_t *rp_id_hash
) {
	return memcmp(credential->source->rp_id_hash, rp_id_hash, CTAP_SHA256_HASH_SIZE) == 0;
}

bool ctap_credential_matches_rp(
	const ctap_credential_handle_t *credential,
	const CTAP_rpId *rp_id
) {
	// if the RP ID was NOT truncated, then we can compare the exact RP ID values
	if ((credential->source->flags & CTAP_CREDENTIAL_SOURCE_CTAP_flags_truncated_rp_id) == 0u) {
		ctap_string_t cred_rp_id;
		ctap_credential_get_rp_id(credential, &cred_rp_id);
		if (ctap_string_matches(&cred_rp_id, &rp_id->id)) {
			// debugging assert: If the full RP ID match, then the hashes must be also equal.
			assert(ctap_credential_matches_rp_id_hash(credential, rp_id->hash));
			return true;
		}
		return false;
	}
	// otherwise, our only option is to compare the hashes
	return ctap_credential_matches_rp_id_hash(credential, rp_id->hash);
}

bool ctap_lookup_credential_by_desc(
	const ctap_storage_t *const storage,
	const CTAP_credDesc *cred_desc,
	ctap_credential_handle_t *credential
) {

	if (cred_desc->type != CTAP_pubKeyCredType_public_key) {
		return false;
	}

	if (cred_desc->id.size != sizeof(((ctap_credential_source_t *) NULL)->id)) {
		return false;
	}

	ctap_storage_item_t item = {
		.key = CTAP_STORAGE_KEY_CREDENTIAL,
	};

	while (storage->find_item(storage, &item) == CTAP_STORAGE_OK) {

		if (item.size < sizeof(ctap_credential_source_t)) {
			error_log("skipping invalid credential item" nl);
			continue;
		}

		const ctap_credential_source_t *const source = (ctap_credential_source_t *) item.data;

		if (memcmp(cred_desc->id.data, source->id, sizeof(source->id)) != 0) {
			continue;
		}

		credential->source = source;
		credential->item_handle = item.handle;
		return true;

	}

	return false;

}

static uint32_t ctap_find_credential_item_by_rp_id_and_user_id(
	const ctap_storage_t *const storage,
	const CTAP_rpId *const rp_id,
	const ctap_string_t *const user_id
) {

	ctap_storage_item_t item = {
		.key = CTAP_STORAGE_KEY_CREDENTIAL,
	};

	while (storage->find_item(storage, &item) == CTAP_STORAGE_OK) {

		if (item.size < sizeof(ctap_credential_source_t)) {
			error_log("skipping invalid credential item" nl);
			continue;
		}

		const ctap_credential_handle_t credential = {
			.source = (const ctap_credential_source_t *) item.data,
			.item_handle = item.handle,
		};

		if (!ctap_credential_matches_rp(&credential, rp_id)) {
			continue;
		}

		CTAP_userHandle cred_user_id;
		ctap_credential_get_user_id(&credential, &cred_user_id);
		if (!ctap_string_matches(&cred_user_id, user_id)) {
			continue;
		}

		return credential.item_handle;

	}

	return 0u;

}

uint8_t ctap_create_credential(
	const ctap_storage_t *storage,
	const ctap_crypto_t *crypto,
	bool discoverable,
	uint8_t cred_protect,
	const CTAP_rpId *rp_id,
	const CTAP_userEntity *user,
	ctap_credential_handle_t *credential
) {

	debug_log("ctap_create_credential:" nl);

	// The WebAuthn spec defines a maximum size of 64 bytes for the userHandle (user.id).
	// Note: This should already be ensured by the checks in parse_user_entity().
	if ((
		!ctap_param_is_present(user, CTAP_userEntity_id)
		|| user->id.size > CTAP_USER_ENTITY_ID_MAX_SIZE
	)) {
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
	}

	const size_t tmp_source_total_size =
		sizeof(ctap_credential_source_t)
		+ CTAP_RP_ID_MAX_SIZE
		+ CTAP_USER_ENTITY_ID_MAX_SIZE
		+ CTAP_USER_ENTITY_NAME_MAX_SIZE
		+ CTAP_USER_ENTITY_DISPLAY_NAME_MAX_SIZE;

	debug_log("  tmp_source_total_size = %" PRIsz nl, tmp_source_total_size);

	uint8_t tmp_source_buffer[tmp_source_total_size] LION_ATTR_ALIGNED(4);
	ctap_credential_source_t *const source = (ctap_credential_source_t *) tmp_source_buffer;

	assert(cred_protect <= CTAP_CREDENTIAL_SOURCE_CTAP_flags_credProtect);
	source->flags = cred_protect;
	if (discoverable) {
		source->flags |= CTAP_CREDENTIAL_SOURCE_CTAP_flags_discoverable;
	}

	ctap_crypto_check(crypto->rng_generate_data(crypto, source->id, sizeof(source->id)));
	ctap_crypto_check(crypto->rng_generate_data(crypto, source->private_key, sizeof(source->private_key)));
	ctap_crypto_check(crypto->rng_generate_data(
		crypto, source->cred_random_with_uv, sizeof(source->cred_random_with_uv)
	));
	ctap_crypto_check(crypto->rng_generate_data(
		crypto, source->cred_random_without_uv, sizeof(source->cred_random_without_uv))
	);

	uint8_t *const variable_data = &tmp_source_buffer[sizeof(ctap_credential_source_t)];

	memcpy(source->rp_id_hash, rp_id->hash, CTAP_SHA256_HASH_SIZE);
	size_t rp_id_size;
	if (ctap_maybe_truncate_rp_id(
		&rp_id->id,
		variable_data,
		CTAP_RP_ID_MAX_SIZE,
		&rp_id_size
	)) {
		source->flags |= CTAP_CREDENTIAL_SOURCE_CTAP_flags_truncated_rp_id;
	}

	source->user_id_offset = rp_id_size;
	size_t user_id_size;
	if (ctap_maybe_truncate_string(
		&user->id,
		variable_data + source->user_id_offset,
		CTAP_USER_ENTITY_ID_MAX_SIZE,
		&user_id_size
	)) {
		// This should never be reached thanks to the top-most check.
		assert(false);
	}

	source->user_name_offset = source->user_id_offset + user_id_size;
	size_t user_name_size;
	if (ctap_param_is_present(user, CTAP_userEntity_name)) {
		if (ctap_maybe_truncate_string(
			&user->name,
			variable_data + source->user_name_offset,
			CTAP_USER_ENTITY_NAME_MAX_SIZE,
			&user_name_size
		)) {
			source->flags |= CTAP_CREDENTIAL_SOURCE_CTAP_flags_truncated_user_name;
		}
		source->flags |= CTAP_CREDENTIAL_SOURCE_CTAP_flags_present_user_name;
	} else {
		user_name_size = 0;
	}

	source->user_display_name_offset = source->user_name_offset + user_name_size;
	size_t user_display_name_size;
	if (ctap_param_is_present(user, CTAP_userEntity_displayName)) {
		if (ctap_maybe_truncate_string(
			&user->displayName,
			variable_data + source->user_display_name_offset,
			CTAP_USER_ENTITY_DISPLAY_NAME_MAX_SIZE,
			&user_display_name_size
		)) {
			source->flags |= CTAP_CREDENTIAL_SOURCE_CTAP_flags_truncated_user_display_name;
		}
		source->flags |= CTAP_CREDENTIAL_SOURCE_CTAP_flags_present_user_display_name;
	} else {
		user_display_name_size = 0;
	}

	source->variable_data_end_offset = source->user_display_name_offset + user_display_name_size;
	const size_t source_total_size = sizeof(ctap_credential_source_t) + source->variable_data_end_offset;
	debug_log("  source_total_size = %" PRIsz nl, source_total_size);
	assert(source_total_size <= tmp_source_total_size);

	ctap_storage_item_t item = {
		.key = CTAP_STORAGE_KEY_CREDENTIAL,
		.size = source_total_size,
		.data = tmp_source_buffer
	};

	// 6.1.2. authenticatorMakeCredential Algorithm, Step 17:
	//   https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#op-makecred-step-rk
	//   If the "rk" option is set to true (discoverable credential requested) and if a credential
	//   for the same RP ID and user.id already exists on the authenticator, overwrite that credential.
	if (discoverable) {
		item.handle = ctap_find_credential_item_by_rp_id_and_user_id(storage, rp_id, &user->id);
		if (item.handle != 0u) {
			debug_log(yellow("  overwriting existing credential") nl);
		}
	}

	const ctap_storage_status_t result = storage->create_or_update_item(storage, &item);

	if (result == CTAP_STORAGE_OUT_OF_MEMORY_ERROR) {
		return CTAP2_ERR_KEY_STORE_FULL;
	}

	if (result != CTAP_STORAGE_OK) {
		error_log(red("an error occurred while storing the credential item") nl);
		return CTAP1_ERR_OTHER;
	}

	credential->source = (const ctap_credential_source_t *) item.data;
	credential->item_handle = item.handle;

	return CTAP2_OK;

}

uint8_t ctap_credential_update_user_information(
	const ctap_storage_t *const storage,
	ctap_credential_handle_t *const credential,
	const CTAP_userEntity *const updated_user
) {

	debug_log("ctap_create_credential:" nl);

	// The WebAuthn spec defines a maximum size of 64 bytes for the userHandle (user.id).
	// Note: This should already be ensured by the checks in parse_user_entity().
	if ((
		!ctap_param_is_present(updated_user, CTAP_userEntity_id)
		|| updated_user->id.size > CTAP_USER_ENTITY_ID_MAX_SIZE
	)) {
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
	}

	ctap_string_t current_user_id;
	ctap_credential_get_user_id(credential, &current_user_id);

	// update of user.id is not allowed by the spec
	if (!ctap_string_matches(&updated_user->id, &current_user_id)) {
		return CTAP1_ERR_INVALID_PARAMETER;
	}

	// Replace the matching credential's PublicKeyCredentialUserEntity's
	// name, displayName with the passed-in user details.
	// If a field is not present in the passed-in user details, or it is present and empty,
	// remove it from the matching credential's PublicKeyCredentialUserEntity.

	const size_t tmp_source_total_size =
		sizeof(ctap_credential_source_t)
		+ CTAP_RP_ID_MAX_SIZE
		+ CTAP_USER_ENTITY_ID_MAX_SIZE
		+ CTAP_USER_ENTITY_NAME_MAX_SIZE
		+ CTAP_USER_ENTITY_DISPLAY_NAME_MAX_SIZE;

	debug_log("  tmp_source_total_size = %" PRIsz nl, tmp_source_total_size);

	uint8_t tmp_source_buffer[tmp_source_total_size] LION_ATTR_ALIGNED(4);
	ctap_credential_source_t *const source = (ctap_credential_source_t *) tmp_source_buffer;

	const uint32_t flags_copy_mask =
		CTAP_CREDENTIAL_SOURCE_CTAP_flags_credProtect
		| CTAP_CREDENTIAL_SOURCE_CTAP_flags_discoverable
		| CTAP_CREDENTIAL_SOURCE_CTAP_flags_truncated_rp_id;
	source->flags = (credential->source->flags & flags_copy_mask);
	memcpy(source->id, credential->source->id, sizeof(source->id));
	memcpy(source->rp_id_hash, credential->source->rp_id_hash, sizeof(source->rp_id_hash));
	memcpy(source->private_key, credential->source->private_key, sizeof(source->private_key));
	memcpy(
		source->cred_random_with_uv, credential->source->cred_random_with_uv,
		sizeof(source->cred_random_with_uv)
	);
	memcpy(
		source->cred_random_without_uv, credential->source->cred_random_without_uv,
		sizeof(source->cred_random_without_uv)
	);

	const uint8_t *const credential_source_variable_data = (uint8_t *) (credential->source + 1);
	uint8_t *const variable_data = &tmp_source_buffer[sizeof(ctap_credential_source_t)];

	size_t rp_id_size = credential->source->user_id_offset;
	memcpy(variable_data, credential_source_variable_data, rp_id_size);

	source->user_id_offset = rp_id_size;
	size_t user_id_size;
	if (ctap_maybe_truncate_string(
		&updated_user->id,
		variable_data + source->user_id_offset,
		CTAP_USER_ENTITY_ID_MAX_SIZE,
		&user_id_size
	)) {
		// This should never be reached thanks to the top-most check.
		assert(false);
	}

	source->user_name_offset = source->user_id_offset + user_id_size;
	size_t user_name_size;
	if (ctap_param_is_present(updated_user, CTAP_userEntity_name) && updated_user->name.size > 0) {
		if (ctap_maybe_truncate_string(
			&updated_user->name,
			variable_data + source->user_name_offset,
			CTAP_USER_ENTITY_NAME_MAX_SIZE,
			&user_name_size
		)) {
			source->flags |= CTAP_CREDENTIAL_SOURCE_CTAP_flags_truncated_user_name;
		}
		source->flags |= CTAP_CREDENTIAL_SOURCE_CTAP_flags_present_user_name;
	} else {
		user_name_size = 0;
	}

	source->user_display_name_offset = source->user_name_offset + user_name_size;
	size_t user_display_name_size;
	if (ctap_param_is_present(updated_user, CTAP_userEntity_displayName) && updated_user->displayName.size > 0) {
		if (ctap_maybe_truncate_string(
			&updated_user->displayName,
			variable_data + source->user_display_name_offset,
			CTAP_USER_ENTITY_DISPLAY_NAME_MAX_SIZE,
			&user_display_name_size
		)) {
			source->flags |= CTAP_CREDENTIAL_SOURCE_CTAP_flags_truncated_user_display_name;
		}
		source->flags |= CTAP_CREDENTIAL_SOURCE_CTAP_flags_present_user_display_name;
	} else {
		user_display_name_size = 0;
	}

	source->variable_data_end_offset = source->user_display_name_offset + user_display_name_size;
	const size_t source_total_size = sizeof(ctap_credential_source_t) + source->variable_data_end_offset;
	debug_log("  source_total_size = %" PRIsz nl, source_total_size);
	assert(source_total_size <= tmp_source_total_size);

	ctap_storage_item_t item = {
		.handle = credential->item_handle, // overwrite existing credential
		.key = CTAP_STORAGE_KEY_CREDENTIAL,
		.size = source_total_size,
		.data = tmp_source_buffer
	};

	const ctap_storage_status_t result = storage->create_or_update_item(storage, &item);

	if (result == CTAP_STORAGE_OUT_OF_MEMORY_ERROR) {
		return CTAP2_ERR_KEY_STORE_FULL;
	}

	if (result != CTAP_STORAGE_OK) {
		error_log(red("an error occurred while storing the credential item") nl);
		return CTAP1_ERR_OTHER;
	}

	credential->source = (const ctap_credential_source_t *) item.data;
	credential->item_handle = item.handle;

	return CTAP2_OK;

}

uint8_t ctap_increment_global_signature_counter(
	const ctap_storage_t *const storage,
	const ctap_crypto_t *const crypto,
	uint32_t *const counter_new_value
) {
	uint32_t increment;
	if (crypto->rng_generate_data(crypto, (uint8_t *) &increment, sizeof(increment)) != CTAP_CRYPTO_OK) {
		error_log(red("ctap_increment_global_signature_counter: rng_generate_data() failed") nl);
		return CTAP1_ERR_OTHER;
	}
	// transform the increment so that it is a random number in range [1, 4]
	increment &= 0x3;
	increment += 1;
	debug_log("ctap_increment_global_signature_counter: increment = %" PRIu32 nl, increment);
	if (storage->increment_counter(storage, increment, counter_new_value) != CTAP_STORAGE_OK) {
		error_log(red("ctap_increment_global_signature_counter: increment_counter() failed") nl);
		return CTAP1_ERR_OTHER;
	}
	return CTAP2_OK;
}

uint8_t ctap_delete_credential(
	const ctap_storage_t *const storage,
	const ctap_credential_handle_t *const credential
) {
	if (storage->delete_item(storage, credential->item_handle) != CTAP_STORAGE_OK) {
		error_log(red("ctap_delete_credential: delete_item() failed") nl);
		return CTAP1_ERR_OTHER;
	}
	return CTAP2_OK;
}

bool ctap_should_add_credential_to_list(
	const ctap_credential_handle_t *credential,
	const bool is_from_allow_list,
	const bool response_has_uv
) {
	const uint8_t cred_protect = ctap_credential_get_cred_protect(credential);
	// 6.2.2. authenticatorGetAssertion Algorithm, 7. Locate all credentials ...
	//   https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#op-getassn-step-locate-credentials
	// 7.4. ... if credential protection for a credential
	//      is marked as userVerificationRequired, and the "uv" bit is false in the response,
	//      remove that credential from the applicable credentials list.
	if ((
		cred_protect == CTAP_extension_credProtect_3_userVerificationRequired
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
		cred_protect == CTAP_extension_credProtect_2_userVerificationOptionalWithCredentialIDList
		&& !is_from_allow_list
		&& !response_has_uv
	)) {
		// do not add this credential to the list
		return false;
	}
	return true;
}

uint8_t ctap_find_discoverable_credentials_by_rp_id(
	const ctap_storage_t *storage,
	const CTAP_rpId *rp_id,
	const uint8_t *rp_id_hash,
	const bool response_has_uv,
	ctap_credential_handle_t *credentials,
	size_t *const num_credentials,
	const size_t max_num_credentials
) {

	debug_log("ctap_find_discoverable_credentials_by_rp_id" nl);

	assert(rp_id != NULL || rp_id_hash != NULL);

	size_t credentials_num = 0;

	ctap_storage_item_t item = {
		.key = CTAP_STORAGE_KEY_CREDENTIAL,
	};

	while (storage->find_item(storage, &item) == CTAP_STORAGE_OK) {

		if (item.size < sizeof(ctap_credential_source_t)) {
			error_log("skipping invalid credential item" nl);
			continue;
		}

		const ctap_credential_handle_t credential = {
			.source = (const ctap_credential_source_t *) item.data,
			.item_handle = item.handle,
		};

		if (rp_id != NULL) {
			if (!ctap_credential_matches_rp(&credential, rp_id)) {
				continue;
			}
		} else if (rp_id_hash != NULL) {
			if (!ctap_credential_matches_rp_id_hash(&credential, rp_id_hash)) {
				continue;
			}
		} else {
			assert(false);
			continue;
		}

		if (!ctap_credential_is_discoverable(&credential)) {
			debug_log("find_credentials_by_rp_id: skipping non-discoverable credential" nl);
			continue;
		}

		if (!ctap_should_add_credential_to_list(&credential, false, response_has_uv)) {
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
		credentials[credentials_num++] = credential;

	}

	*num_credentials = credentials_num;

	return CTAP2_OK;

}

static bool is_rp_id_in_the_list(
	const uint8_t *const rp_id_hash,
	const CTAP_rpId_hash_ptr *const rp_ids,
	const size_t num_rp_ids
) {

	for (size_t i = 0; i < num_rp_ids; ++i) {
		if (memcmp(rp_ids[i].hash, rp_id_hash, CTAP_SHA256_HASH_SIZE) == 0) {
			return true;
		}
	}

	return false;

}

uint8_t ctap_enumerate_rp_ids_of_discoverable_credentials(
	const ctap_storage_t *const storage,
	CTAP_rpId_hash_ptr *const rp_ids,
	size_t *const num_rp_ids,
	const size_t max_num_rp_ids
) {

	debug_log("enumerate_rp_ids_of_discoverable_credentials" nl);

	size_t current_num_rp_ids = 0;

	ctap_storage_item_t item = {
		.key = CTAP_STORAGE_KEY_CREDENTIAL,
	};

	while (storage->find_item(storage, &item) == CTAP_STORAGE_OK) {

		if (item.size < sizeof(ctap_credential_source_t)) {
			error_log("skipping invalid credential item" nl);
			continue;
		}

		const ctap_credential_handle_t credential = {
			.source = (const ctap_credential_source_t *) item.data,
			.item_handle = item.handle,
		};

		if (!ctap_credential_is_discoverable(&credential)) {
			debug_log("enumerate_rp_ids_of_discoverable_credentials: skipping non-discoverable credential" nl);
			continue;
		}

		if (is_rp_id_in_the_list(credential.source->rp_id_hash, rp_ids, current_num_rp_ids)) {
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
		CTAP_rpId_hash_ptr *const rp_id = &rp_ids[current_num_rp_ids++];
		rp_id->hash = credential.source->rp_id_hash;
		ctap_credential_get_rp_id(&credential, &rp_id->id);
	}

	*num_rp_ids = current_num_rp_ids;

	return CTAP2_OK;

}

uint8_t ctap_credential_compute_public_key(
	const ctap_crypto_t *const crypto,
	const ctap_credential_handle_t *const credential,
	uint8_t *const public_key
) {
	ctap_crypto_check(crypto->ecc_secp256r1_compute_public_key(
		crypto,
		credential->source->private_key,
		public_key
	));
	return CTAP2_OK;
}

uint8_t ctap_credential_compute_signature(
	const ctap_crypto_t *const crypto,
	const ctap_credential_handle_t *const credential,
	const uint8_t *const message_hash,
	const size_t message_hash_size,
	uint8_t *const signature
) {
	ctap_crypto_check(crypto->ecc_secp256r1_sign(
		crypto,
		credential->source->private_key,
		message_hash,
		message_hash_size,
		signature,
		NULL
	));
	return CTAP2_OK;
}
