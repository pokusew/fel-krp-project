#ifndef LIONKEY_CREDENTIALS_STORE_H
#define LIONKEY_CREDENTIALS_STORE_H

#include "ctap_parse.h"
#include "ctap_storage.h"
#include "ctap_crypto.h"

// credProtect value (1, 2, or 3) (from the credProtect extension)
#define CTAP_CREDENTIAL_SOURCE_CTAP_flags_credProtect                  ((1u << 0) | (1u << 1))
// discoverable (true/false)
#define CTAP_CREDENTIAL_SOURCE_CTAP_flags_discoverable                 (1u << 2)
// optional user.name is present
#define CTAP_CREDENTIAL_SOURCE_CTAP_flags_present_user_name            (1u << 3)
// optional user.displayName is present
#define CTAP_CREDENTIAL_SOURCE_CTAP_flags_present_user_display_name    (1u << 4)
// RP ID was truncated for storage
#define CTAP_CREDENTIAL_SOURCE_CTAP_flags_truncated_rp_id              (1u << 5)
// user.name was truncated for storage
#define CTAP_CREDENTIAL_SOURCE_CTAP_flags_truncated_user_name          (1u << 6)
// user.displayName was truncated for storage
#define CTAP_CREDENTIAL_SOURCE_CTAP_flags_truncated_user_display_name  (1u << 7)

typedef struct LION_ATTR_PACKED ctap_credential_source {
	uint32_t flags;
	uint8_t id[32] LION_ATTR_ALIGNED(4);
	uint8_t rp_id_hash[CTAP_SHA256_HASH_SIZE];
	// the actual private key
	uint8_t private_key[32] LION_ATTR_ALIGNED(4);
	// hmac-secret extension
	uint8_t cred_random_with_uv[32] LION_ATTR_ALIGNED(4);
	uint8_t cred_random_without_uv[32] LION_ATTR_ALIGNED(4);
	// data (fixed part)
	uint16_t user_id_offset;
	uint16_t user_name_offset;
	uint16_t user_display_name_offset;
	uint16_t variable_data_end_offset;
	// data (variable part)
	//
	// (rp_id_size = user_id_offset)
	// (user_id_size = user_name_offset - user_id_offset)
	// (user_name_size = user_display_name_offset - user_name_offset)
	// (user_display_name_size = variable_data_end_offset - user_display_name_offset)
	//
	// uint8_t rp_id_data[rp_id_size];
	// uint8_t user_id_data[user_id_size];
	// uint8_t user_name_data[user_name_size];
	// uint8_t user_display_name_data[user_display_name_size];
} ctap_credential_source_t;

typedef struct ctap_credential_handle {
	const ctap_credential_source_t *source;
	uint32_t item_handle;
} ctap_credential_handle_t;

LION_ATTR_ALWAYS_INLINE static inline uint32_t ctap_credential_get_flags(
	const ctap_credential_handle_t *const credential
) {
	return credential->source->flags;
}

LION_ATTR_ALWAYS_INLINE static inline uint8_t ctap_credential_is_discoverable(
	const ctap_credential_handle_t *const credential
) {
	return (credential->source->flags & CTAP_CREDENTIAL_SOURCE_CTAP_flags_discoverable) != 0u;
}

LION_ATTR_ALWAYS_INLINE static inline void ctap_credential_get_id(
	const ctap_credential_handle_t *const credential,
	ctap_string_t *id
) {
	id->size = sizeof(credential->source->id);
	id->data = credential->source->id;
}

LION_ATTR_ALWAYS_INLINE static inline const uint8_t *ctap_credential_get_rp_id_hash(
	const ctap_credential_handle_t *const credential
) {
	return credential->source->rp_id_hash;
}

LION_ATTR_ALWAYS_INLINE static inline void ctap_credential_get_rp_id(
	const ctap_credential_handle_t *const credential,
	ctap_string_t *rp_id
) {
	rp_id->size = credential->source->user_id_offset;
	const uint8_t *source_variable_data = (uint8_t *) (credential->source + 1);
	rp_id->data = &source_variable_data[0];
}

LION_ATTR_ALWAYS_INLINE static inline void ctap_credential_get_user_id(
	const ctap_credential_handle_t *const credential,
	CTAP_userHandle *user_id
) {

	const ctap_credential_source_t *const source = credential->source;
	const uint8_t *source_variable_data = (uint8_t *) (source + 1);

	user_id->size = source->user_name_offset - source->user_id_offset;
	user_id->data = &source_variable_data[source->user_id_offset];

}

LION_ATTR_ALWAYS_INLINE static inline void ctap_credential_get_user(
	const ctap_credential_handle_t *const credential,
	CTAP_userEntity *user
) {

	const ctap_credential_source_t *const source = credential->source;
	const uint8_t *source_variable_data = (uint8_t *) (source + 1);

	user->present = ctap_param_to_mask(CTAP_userEntity_id); // user.id is always present in the credential source

	user->id.size = source->user_name_offset - source->user_id_offset;
	user->id.data = &source_variable_data[source->user_id_offset];

	if ((source->flags & CTAP_CREDENTIAL_SOURCE_CTAP_flags_present_user_name) != 0u) {
		ctap_set_present(user, CTAP_userEntity_name);
		user->name.size = source->user_display_name_offset - source->user_name_offset;
		user->name.data = &source_variable_data[source->user_name_offset];
	} else {
		user->name.size = 0;
		user->name.data = NULL;
	}

	if ((source->flags & CTAP_CREDENTIAL_SOURCE_CTAP_flags_present_user_display_name) != 0u) {
		ctap_set_present(user, CTAP_userEntity_displayName);
		user->displayName.size = source->variable_data_end_offset - source->user_display_name_offset;
		user->displayName.data = &source_variable_data[source->user_display_name_offset];
	} else {
		user->displayName.size = 0;
		user->displayName.data = NULL;
	}

}

LION_ATTR_ALWAYS_INLINE static inline uint8_t ctap_credential_get_cred_protect(
	const ctap_credential_handle_t *const credential
) {
	return (credential->source->flags & CTAP_CREDENTIAL_SOURCE_CTAP_flags_credProtect);
}

LION_ATTR_ALWAYS_INLINE static inline const uint8_t *ctap_credential_get_cred_random(
	const ctap_credential_handle_t *const credential,
	const bool uv
) {
	return uv
		? credential->source->cred_random_with_uv
		: credential->source->cred_random_without_uv;
}

uint8_t ctap_credential_compute_public_key(
	const ctap_crypto_t *crypto,
	const ctap_credential_handle_t *credential,
	uint8_t *public_key
);

uint8_t ctap_credential_compute_signature(
	const ctap_crypto_t *crypto,
	const ctap_credential_handle_t *credential,
	const uint8_t *message_hash,
	size_t message_hash_size,
	uint8_t *signature
);

size_t ctap_count_num_stored_credentials(const ctap_storage_t *storage, bool only_discoverable);

size_t ctap_count_num_stored_discoverable_credentials(const ctap_storage_t *storage);

size_t ctap_get_num_max_possible_remaining_discoverable_credentials(const ctap_storage_t *storage);

bool ctap_credential_matches_rp_id_hash(
	const ctap_credential_handle_t *credential,
	const uint8_t *rp_id_hash
);

bool ctap_credential_matches_rp(
	const ctap_credential_handle_t *credential,
	const CTAP_rpId *rp_id
);

bool ctap_lookup_credential_by_desc(
	const ctap_storage_t *storage,
	const CTAP_credDesc *cred_desc,
	ctap_credential_handle_t *credential
);

uint8_t ctap_create_credential(
	const ctap_storage_t *storage,
	const ctap_crypto_t *crypto,
	bool discoverable,
	uint8_t cred_protect,
	const CTAP_rpId *rp_id,
	const CTAP_userEntity *user,
	ctap_credential_handle_t *credential
);

uint8_t ctap_credential_update_user_information(
	const ctap_storage_t *storage,
	ctap_credential_handle_t *credential,
	const CTAP_userEntity *updated_user
);

uint8_t ctap_increment_global_signature_counter(
	const ctap_storage_t *storage,
	const ctap_crypto_t *crypto,
	uint32_t *counter_new_value
);

uint8_t ctap_delete_credential(
	const ctap_storage_t *storage,
	const ctap_credential_handle_t *credential
);

bool ctap_should_add_credential_to_list(
	const ctap_credential_handle_t *credential,
	bool is_from_allow_list,
	bool response_has_uv
);

uint8_t ctap_find_discoverable_credentials_by_rp_id(
	const ctap_storage_t *storage,
	const CTAP_rpId *rp_id,
	const uint8_t *rp_id_hash,
	bool response_has_uv,
	ctap_credential_handle_t *credentials,
	size_t *num_credentials,
	size_t max_num_credentials
);

uint8_t ctap_enumerate_rp_ids_of_discoverable_credentials(
	const ctap_storage_t *storage,
	CTAP_rpId_hash_ptr *rp_ids,
	size_t *num_rp_ids,
	size_t max_num_rp_ids
);

#endif // LIONKEY_CREDENTIALS_STORE_H
