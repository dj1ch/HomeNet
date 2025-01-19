#pragma once

#include "openthread/error.h"
#include "esp_types.h"
#include "esp_err.h"

otError set_nickname_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
otError get_nickname_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
otError get_ipv6_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
otError get_lfs_entries_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
otError clear_lfs_entries_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);

esp_err_t set_nickname(const char *peerAddr, const char *nickname);
esp_err_t get_nickname(const char *peerAddr, char *nickname, size_t len);
esp_err_t get_ipv6(const char *nickname, char *peerAddr, size_t len);