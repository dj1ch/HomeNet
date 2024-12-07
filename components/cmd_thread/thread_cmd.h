#pragma once

#define OT_ARRAY_LENGTH(aArray) (sizeof(aArray) / sizeof(aArray[0]))

#include "openthread/instance.h"
#include "nvs_flash.h"
#include "nvs.h"

void register_thread(void);
extern nvs_handle_t handle;
extern otInstance *otInstancePtr;
extern otInstance *get_ot_instance(void);