#pragma once

#define OT_ARRAY_LENGTH(aArray) (sizeof(aArray) / sizeof(aArray[0]))

#include "openthread/instance.h"

void register_thread(void);
extern otInstance *otInstancePtr;
extern otInstance *get_ot_instance(void);