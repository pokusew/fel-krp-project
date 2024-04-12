#ifndef POKUSEW_APP_H
#define POKUSEW_APP_H

#define SOLO_VERSION_MAJ 9
#define SOLO_VERSION_MIN 8
#define SOLO_VERSION_PATCH 7

#include <stdnoreturn.h>
#include <stdbool.h>
#include "main.h"
#include "ctaphid.h"

typedef struct app_state {
	bool blue_led;
	ctaphid_state_t ctaphid;
} app_state_t;

extern app_state_t *main_app;

void app_init(app_state_t *app);

int usbhid_recv(uint8_t *msg);

noreturn void app_run(app_state_t *app);

#endif // POKUSEW_APP_H
