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
 * Set the nickname of a discovered client
 * in the format ("ipv6_addr", "nickname")
 */
static esp_err_t set_nickname(const char *ipv6_addr, const char *nickname)
{
    if (!ipv6_addr || !nickname)
    {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        err = nvs_set_str(handle, ipv6_addr, nickname);
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
static esp_err_t get_nickname(const char *ipv6_addr, char *nickname, size_t len)
{
    if (!ipv6_addr || !nickname || len == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &handle);
    if (err == ESP_OK)
    {
        err = nvs_get_str(handle, ipv6_addr, nickname, &len);
        nvs_close(handle);
    }
    return err;
}

/**
 * Does a search through NVS to find an ipv6 address given a nickname
 * Keep in mind the nickname and NVS are stored using a method
 * which has the address set as the key, then the value set as the nickname
 */
static esp_err_t iterate_nvs_keys(nvs_handle_t handle, const char *nickname, char *ipv6_addr, size_t len)
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
            err = nvs_get_str(handle, info.key, ipv6_addr, &len);
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
static esp_err_t get_ipv6(const char *nickname, char *ipv6_addr, size_t len)
{
    if (!nickname || !ipv6_addr || len == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t handle;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &handle);
    if (err != ESP_OK)
    {
        return err;
    }
    esp_err_t result = iterate_nvs_keys(handle, nickname, ipv6_addr, len);
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
        printf("Usage: set_nickname <ipv6_addr> <nickname>\n");
        return -1;
    }

    const char *ipv6_addr = aArgs[1];
    const char *nickname = aArgs[2];
    esp_err_t err = set_nickname(ipv6_addr, nickname);

    if (err == ESP_OK)
    {
        printf("Set nickname for %s as '%s'\n", ipv6_addr, nickname);
        return 0;
    }
    else 
    {
        printf("Error setting nickname '%s' for %s", nickname, ipv6_addr);
        return -1;
    }
}

/**
 * Command to get the nickname
 */
otError get_nickname_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    if (aArgsLength != 2)
    {
        printf("Usage: get_nickname <ipv6_addr>\n");
        return -1;
    }

    const char *ipv6_addr = aArgs[1];
    char nickname[64];
    esp_err_t err = get_nickname(ipv6_addr, nickname, sizeof(nickname));

    if (err == ESP_OK) {
        printf("Nickname for %s: %s\n", ipv6_addr, nickname);
        return 0;
    } 
    else if (err == ESP_ERR_NOT_FOUND)
    {
        printf("No nickname found for %s\n", ipv6_addr);
        return -1;
    }
    else {
        printf("Error retrieving nickname for %s: %s\n", ipv6_addr, esp_err_to_name(err));
        return -1;
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
        return -1;
    }

    const char *nickname = aArgs[1];
    char ipv6_addr[64];
    esp_err_t err = get_ipv6(nickname, ipv6_addr, sizeof(ipv6_addr));

    if (err == ESP_OK) {
        printf("IPv6 address for nickname '%s': %s\n", nickname, ipv6_addr);
        return 0;
    }
    else if (err == ESP_ERR_NOT_FOUND)
    {
        printf("No IPv6 address found for nickname '%s'\n", nickname);
        return -1;
    }
    else
    {
        printf("Error retrieving IPv6 address for nickname '%s': %s\n", nickname, esp_err_to_name(err));
        return -1;
    }
}
