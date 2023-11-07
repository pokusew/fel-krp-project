#ifndef POKUSEW_APP_H
#define POKUSEW_APP_H

#include <stdnoreturn.h>
#include "main.h"

typedef struct app_state {

} app_state_t;

extern app_state_t *main_app;

void app_init(app_state_t *app);

int usbhid_recv(uint8_t * msg);

noreturn void app_run(app_state_t *app);

#ifndef SOLO_VERSION_MAJ

#define SOLO_VERSION_MAJ 9
#define SOLO_VERSION_MIN 8
#define SOLO_VERSION_PATCH 7

#endif // SOLO_VERSION_MAJ

#endif // POKUSEW_APP_H
