#pragma once

#include "openthread/error.h"

otError set_nickname_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
otError get_nickname_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
otError get_ipv6_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
otError list_nvs_entries_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);