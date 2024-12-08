/**
 * Developer note:
 * In this file, we handle what is too specific to not be in thread_cmd.c.
 * Specifically, instead of handling thread, we use thread to handle specific
 * functions with the chatting.
 * 
 * Most of the stuff here is miscallenous and are more QOL if anything.
 */

#include "chat_cmd.h"
#include "thread_cmd.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "openthread/instance.h"
#include "openthread/thread.h"
#include "openthread/message.h"
#include "openthread/udp.h"
#include "openthread/instance.h"
#include "openthread/ip6.h"
#include "openthread/logging.h"
#include "openthread/cli.h"
#include "openthread/platform/misc.h"
#include "openthread/thread.h"
#include "openthread/diag.h"
#include "esp_netif.h"
#include "esp_netif_types.h"
#include "esp_openthread.h"
#include "esp_openthread_cli.h"
#include "esp_openthread_lock.h"
#include "esp_openthread_netif_glue.h"
#include "esp_openthread_types.h"
#include "esp_ot_config.h"
#include "esp_vfs_eventfd.h"
#include "esp_console.h"
#include "argtable3/argtable3.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "nvs.h"

/**
 * Function declarations
 */
static esp_err_t set_nickname(const char *peerAddr, const char *nickname);
static esp_err_t get_nickname(const char *peerAddr, char *nickname, size_t len);
static esp_err_t iterate_nvs_keys(const char *nickname, char *peerAddr, size_t len);
static esp_err_t get_ipv6(const char *nickname, char *peerAddr, size_t len);

/**
 * Set the nickname of a discovered client
 * in the format ("peerAddr", "nickname")
 */
static esp_err_t set_nickname(const char *peerAddr, const char *nickname)
{
    if (!peerAddr || !nickname)
    {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = nvs_open("storage", NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        err = nvs_set_str(handle, peerAddr, nickname);
        if (err == ESP_OK) {
            err = nvs_commit(handle);
        }
        nvs_close(handle);
    }
    return err;
}

/**
 * Get the requested nickname(s) from NVS
 */
static esp_err_t get_nickname(const char *peerAddr, char *nickname, size_t len)
{
    if (!peerAddr || !nickname || len == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = nvs_open("storage", NVS_READONLY, &handle);
    if (err == ESP_OK)
    {
        err = nvs_get_str(handle, peerAddr, nickname, &len);
        nvs_close(handle);
    }
    return err;
}

/**
 * Does a search through NVS to find an ipv6 address given a nickname
 * Keep in mind the nickname and NVS are stored using a method
 * which has the address set as the key, then the value set as the nickname
 */
static esp_err_t iterate_nvs_keys(const char *nickname, char *peerAddr, size_t len)
{
    nvs_iterator_t it;
    esp_err_t err = nvs_entry_find(NVS_DEFAULT_PART_NAME, "storage", NVS_TYPE_STR, &it);

    // check if the iterator matches the requested address
    while (it != NULL)
    {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);
        if (strcmp(info.key, nickname) == 0)
        {
            err = nvs_get_str(handle, info.key, peerAddr, &len);
            nvs_release_iterator(it);
            return err;
        }
        err = nvs_entry_next(&it);
        if (err != ESP_OK) break;
    }
    return ESP_ERR_NOT_FOUND;
}


/**
 * Finds the ipv6 address through a nickname
 */
static esp_err_t get_ipv6(const char *nickname, char *peerAddr, size_t len)
{
    if (!nickname || !peerAddr || len == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = nvs_open("storage", NVS_READONLY, &handle);
    if (err != ESP_OK)
    {
        return err;
    }
    esp_err_t result = iterate_nvs_keys(nickname, peerAddr, len);
    nvs_close(handle);
    return result;
}

/**
 * Command to set the nickname
 */
otError set_nickname_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    if (aArgsLength != 3)
    {
        printf("Usage: set_nickname <peer_address> <nickname>\n");
        return OT_ERROR_FAILED;
    }

    const char *peerAddr = aArgs[1];
    const char *nickname = aArgs[2];
    esp_err_t err = set_nickname(peerAddr, nickname);

    if (err == ESP_OK)
    {
        printf("Set nickname for %s as '%s'\n", peerAddr, nickname);
        return OT_ERROR_NONE;
    }
    else 
    {
        printf("Error setting nickname '%s' for %s", nickname, peerAddr);
        return OT_ERROR_FAILED;
    }
}

/**
 * Command to get the nickname
 */
otError get_nickname_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    if (aArgsLength != 2)
    {
        printf("Usage: get_nickname <peerAddr>\n");
        return OT_ERROR_FAILED;
    }

    const char *peerAddr = aArgs[1];
    char nickname[64];
    esp_err_t err = get_nickname(peerAddr, nickname, sizeof(nickname));

    if (err == ESP_OK) {
        printf("Nickname for %s: %s\n", peerAddr, nickname);
        return OT_ERROR_NONE;
    } 
    else if (err == ESP_ERR_NOT_FOUND)
    {
        printf("No nickname found for %s\n", peerAddr);
        return OT_ERROR_FAILED;
    }
    else {
        printf("Error retrieving nickname for %s: %s\n", peerAddr, esp_err_to_name(err));
        return OT_ERROR_FAILED;
    }
}

/**
 * Command to get the ipv6 address
 */
otError get_ipv6_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    if (aArgsLength != 2)
    {
        printf("Usage: get_ipv6 <nickname>\n");
        return OT_ERROR_FAILED;
    }

    const char *nickname = aArgs[1];
    char peerAddr[64];
    esp_err_t err = get_ipv6(nickname, peerAddr, sizeof(peerAddr));

    if (err == ESP_OK) {
        printf("IPv6 address for nickname '%s': %s\n", nickname, peerAddr);
        return OT_ERROR_NONE;
    }
    else if (err == ESP_ERR_NOT_FOUND)
    {
        printf("No IPv6 address found for nickname '%s'\n", nickname);
        return OT_ERROR_FAILED;
    }
    else
    {
        printf("Error retrieving IPv6 address for nickname '%s': %s\n", nickname, esp_err_to_name(err));
        return OT_ERROR_FAILED;
    }
}
