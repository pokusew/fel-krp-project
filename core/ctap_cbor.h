#ifndef LIONKEY_CTAP_CBOR_H
#define LIONKEY_CTAP_CBOR_H

#include "ctap_common.h"

#include <cbor.h>

#define lionkey_cbor_error_log(err, line, filename) \
	debug_log(red("CborError: 0x%x (%d) (%s) at %s:%d") nl, err, err, cbor_error_string(err), filename, line)

#define ctap_cbor_ensure_type(result)                          \
	if (!(result)) {                                           \
		debug_log(                                             \
			red("CTAP2_ERR_CBOR_UNEXPECTED_TYPE at %s:%d") nl, \
			__FILE__, __LINE__                                 \
		);                                                     \
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;                 \
	}                                                          \
	((void) 0)

#define cbor_decoding_check(r)                           \
    if ((err = (r)) != CborNoError) {                    \
        lionkey_cbor_error_log(err, __LINE__, __FILE__); \
        return CTAP2_ERR_INVALID_CBOR;                   \
    }                                                    \
    ((void) 0)

#define cbor_encoding_check(r)                           \
    if ((err = (r)) != CborNoError) {                    \
        lionkey_cbor_error_log(err, __LINE__, __FILE__); \
        return CTAP1_ERR_OTHER;                          \
    }                                                    \
    ((void) 0)

#endif // LIONKEY_CTAP_CBOR_H
