#pragma once

#include "openthread/error.h"

void register_chat(void);
otError set_nickname_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
otError get_nickname_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
otError get_ipv6_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);