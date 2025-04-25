#include "ctap_test.h"
#include <ctap.h>

bool test_validate_cbor(const uint8_t *data, const size_t data_size) {
	CborError err;
	CborParser parser;
	CborValue it;
	if (ctap_init_cbor_parser(data, data_size, &parser, &it) != CTAP2_OK) {
		error_log(red("CBOR validation error: ctap_init_cbor_parser() returned error") nl);
		return false;
	}
	// see 8. Message Encoding, CTAP2 canonical CBOR encoding form
	//   https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#ctap2-canonical-cbor-encoding-form
	// Note that the following flags might not ensure all the CTAP2 canonical CBOR encoding form's rules,
	// but they provide a good start that should catch most issues.
	const uint32_t flags =
		CborValidateCanonicalFormat
		| CborValidateMapKeysAreUnique
		| CborValidateNoUndefined
		| CborValidateNoTags
		| CborValidateCompleteData;
	if ((err = cbor_value_validate(&it, flags)) != CborNoError) {
		error_log(red("CBOR validation error: 0x%x (%d) (%s)") nl, err, err, cbor_error_string(err));
		return false;
	}
	return true;
}
