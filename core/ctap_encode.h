#ifndef LIONKEY_CTAP_ENCODE_H
#define LIONKEY_CTAP_ENCODE_H

#include "ctap_parse.h"

uint8_t ctap_encode_ctap_string_as_byte_string(
	CborEncoder *encoder,
	const ctap_string_t *str
);

uint8_t ctap_encode_ctap_string_as_text_string(
	CborEncoder *encoder,
	const ctap_string_t *str
);

uint8_t ctap_encode_public_key(
	CborEncoder *encoder,
	const uint8_t *public_key
);

uint8_t ctap_encode_pub_key_cred_desc(
	CborEncoder *encoder,
	const ctap_string_t *cred_id
);

uint8_t ctap_encode_pub_key_cred_user_entity(
	CborEncoder *encoder,
	const CTAP_userEntity *user,
	bool include_user_identifiable_info
);

uint8_t ctap_encode_rp_entity(
	CborEncoder *encoder,
	const ctap_string_t *rp_id
);

#endif // LIONKEY_CTAP_ENCODE_H
