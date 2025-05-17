#ifndef LIONKEY_CTAP_COMMON_H
#define LIONKEY_CTAP_COMMON_H

#include "ctap_errors.h"

#define ctap_check(expr)                                                   \
	if ((ret = (expr)) != CTAP2_OK) {                                      \
		debug_log(                                                         \
			red("ctap_check: 0x%02" wPRIx8 " (%" wPRIu8 ") at %s:%d") nl,  \
			ret, ret, __FILE__, __LINE__                                   \
		);                                                                 \
		return ret;                                                        \
	}                                                                      \
	((void) 0)

#define CTAP_SHA256_HASH_SIZE  32

uint32_t ctap_get_current_time(void);

#endif // LIONKEY_CTAP_COMMON_H
