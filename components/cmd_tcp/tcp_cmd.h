#pragma once

#include "openthread/tcp.h"
#include "openthread/tcp_ext.h"
#include "esp_openthread.h"
#include "openthread/error.h"

otError send_message_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
void register_tcp(void);