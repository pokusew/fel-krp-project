#ifndef LIONKEY_CTAP_ASN1_H
#define LIONKEY_CTAP_ASN1_H

#include <stddef.h>
#include <stdint.h>

void ctap_convert_to_asn1_der_ecdsa_sig_value(
	const uint8_t *signature,
	uint8_t *asn1_der_signature,
	size_t *asn1_der_signature_size
);

#endif // LIONKEY_CTAP_ASN1_H
