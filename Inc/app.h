#ifndef POKUSEW_APP_H
#define POKUSEW_APP_H

#include <stdnoreturn.h>
#include "main.h"

typedef struct app_state {

} app_state_t;

extern app_state_t *main_app;

void app_init(app_state_t *app);

noreturn void app_run(app_state_t *app);

#endif // POKUSEW_APP_H
