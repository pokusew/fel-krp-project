// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdio.h>
#include "device.h"
#include "util.h"
#include "ctap.h"
#include "u2f.h"

#if defined(STUB_CTAPHID) || defined(STUB_CTAP)



void ctap_init()
{
	printf1(TAG_GEN,"STUB: ctap_init\r\n");
}
#endif

#if defined(STUB_CTAPHID)
void ctaphid_init()
{
	printf1(TAG_GEN,"STUB: ctaphid_init\r\n");
}
void ctaphid_handle_packet(uint8_t * hidmsg)
{
	printf1(TAG_GEN,"STUB: ctaphid_handle_packet\r\n");
}

void ctaphid_check_timeouts()
{

}

#endif


#ifdef STUB_CTAP

void ctap_reset_state()
{
	printf1(TAG_GEN,"STUB: ctap_reset_state\r\n");
}

void ctap_response_init(CTAP_RESPONSE * resp)
{
}

void u2f_request(struct u2f_request_apdu* req, CTAP_RESPONSE * resp)
{
	printf1(TAG_GEN,"STUB: u2f_request\r\n");
}

uint8_t ctap_request(uint8_t * pkt_raw, int length, CTAP_RESPONSE * resp)
{
	printf1(TAG_GEN,"STUB: ctap_request\r\n");
	return 0;
}
#endif
