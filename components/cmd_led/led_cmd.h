#pragma once

#include "esp_err.h"
#include "openthread/error.h"

extern esp_err_t init_led(void);
otError turn_on_led_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
otError turn_off_led_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);