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

#define TAG "homenet"

/**
 * Function declarations
 */
esp_err_t set_nickname(const char *peerAddr, const char *nickname);
esp_err_t get_nickname(const char *peerAddr, char *nickname, size_t len);
esp_err_t get_ipv6(const char *nickname, char *peerAddr, size_t len);
esp_err_t get_nvs_entries();
esp_err_t clear_nvs_entries();

/**
 * Hash function to generate a shorter key
 */
uint16_t hash_peer_addr(const char *peerAddr)
{
    uint16_t hash = 0;
    while (*peerAddr)
    {
        hash = (hash << 5) - hash + (uint8_t)(*peerAddr++);
    }
    return hash;
}

/**
 * Set the nickname of a discovered client
 * in the format ("peerAddr", "nickname")
 */
esp_err_t set_nickname(const char *peerAddr, const char *nickname)
{
    if (!peerAddr || !nickname)
    {
        printf("Invalid arguments: peerAddr=%s, nickname=%s\n", peerAddr ? peerAddr : "NULL", nickname ? nickname : "NULL");
        return ESP_ERR_INVALID_ARG;
    }

    printf("Setting nickname: peerAddr=%s, nickname=%s\n", peerAddr, nickname);

    // generate a shorter key using the hash function
    char key[16];
    snprintf(key, sizeof(key), "%04x", hash_peer_addr(peerAddr));

    nvs_handle_t handle;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &handle);
    if (err != ESP_OK)
    {
        printf("Failed to open NVS handle: %s\n", esp_err_to_name(err));
        return err;
    }

    err = nvs_set_str(handle, key, nickname);
    if (err != ESP_OK)
    {
        printf("Failed to set string in NVS: %s\n", esp_err_to_name(err));
        nvs_close(handle);
        return err;
    }

    err = nvs_set_str(handle, nickname, key);
    if (err != ESP_OK)
    {
        printf("Failed to set string in NVS: %s\n", esp_err_to_name(err));
        nvs_close(handle);
        return err;
    }

    err = nvs_commit(handle);
    if (err != ESP_OK)
    {
        printf("Failed to commit NVS handle: %s\n", esp_err_to_name(err));
    }
    else
    {
        printf("Nickname set successfully\n");
    }

    nvs_close(handle);
    return err;
}

/**
 * Get the requested nickname(s) from NVS
 */
esp_err_t get_nickname(const char *peerAddr, char *nickname, size_t len)
{
    if (!peerAddr || !nickname)
    {
        printf("Invalid arguments\n");
        return ESP_ERR_INVALID_ARG;
    }

    // generate a shorter key using the hash function
    char key[16];
    snprintf(key, sizeof(key), "%04x", hash_peer_addr(peerAddr));

    nvs_handle_t handle;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &handle);
    if (err != ESP_OK)
    {
        printf("Failed to open NVS handle: %s\n", esp_err_to_name(err));
        return err;
    }

    err = nvs_get_str(handle, key, nickname, &len);
    if (err != ESP_OK)
    {
        printf("Failed to get string from NVS: %s\n", esp_err_to_name(err));
    }

    nvs_close(handle);
    return err;
}

/**
 * Finds the ipv6 address through a nickname
 */
esp_err_t get_ipv6(const char *nickname, char *peerAddr, size_t len)
{
    if (!nickname || !peerAddr || len == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &handle);
    if (err != ESP_OK)
    {
        printf("Failed to open NVS handle: %s\n", esp_err_to_name(err));
        return err;
    }

    err = nvs_get_str(handle, nickname, peerAddr, &len);
    if (err != ESP_OK)
    {
        printf("Failed to get string from NVS: %s\n", esp_err_to_name(err));
    }

    nvs_close(handle);
    return err;
}

/**
 * List all NVS key-value entries
 */
esp_err_t get_nvs_entries()
{
    nvs_iterator_t it = NULL;
    esp_err_t err = nvs_entry_find(NVS_DEFAULT_PART_NAME, "storage", NVS_TYPE_ANY, &it);
    if (err != ESP_OK)
    {
        printf("No entries found in NVS\n");
        return err;
    }
    if (it == NULL)
    {
        printf("No entries found in NVS");
        return ESP_FAIL;
    }

    while (it != NULL)
    {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);

        printf("Namespace: %s, Key: %s, Type: %d\n", info.namespace_name, info.key, info.type);

        // open NVS handle to read the value
        nvs_handle_t handle;
        err = nvs_open("storage", NVS_READONLY, &handle);
        if (err != ESP_OK)
        {
            printf("Failed to open NVS handle: %s\n", esp_err_to_name(err));
            nvs_release_iterator(it);
            return err;
        }

        // Read the value based on the type
        if (info.type == NVS_TYPE_STR)
        {
            size_t required_size;
            err = nvs_get_str(handle, info.key, NULL, &required_size);
            if (err == ESP_OK)
            {
                char *value = malloc(required_size);
                if (value != NULL)
                {
                    err = nvs_get_str(handle, info.key, value, &required_size);
                    if (err == ESP_OK)
                    {
                        printf("Value: %s\n", value);
                    }
                    free(value);
                }
            }
        }
        else if (info.type == NVS_TYPE_BLOB)
        {
            size_t required_size;
            err = nvs_get_blob(handle, info.key, NULL, &required_size);
            if (err == ESP_OK)
            {
                void *value = malloc(required_size);
                if (value != NULL)
                {
                    err = nvs_get_blob(handle, info.key, value, &required_size);
                    if (err == ESP_OK)
                    {
                        printf("Value: (blob of size %zu)\n", required_size);
                    }
                    free(value);
                }
            }
        }
        else if (info.type == NVS_TYPE_U8)
        {
            uint8_t value;
            err = nvs_get_u8(handle, info.key, &value);
            if (err == ESP_OK)
            {
                printf("Value: %u\n", value);
            }
        }
        else if (info.type == NVS_TYPE_I8)
        {
            int8_t value;
            err = nvs_get_i8(handle, info.key, &value);
            if (err == ESP_OK)
            {
                printf("Value: %" PRId8 "\n", value);
            }
        }
        else if (info.type == NVS_TYPE_U16)
        {
            uint16_t value;
            err = nvs_get_u16(handle, info.key, &value);
            if (err == ESP_OK)
            {
                printf("Value: %u\n", value);
            }
        }
        else if (info.type == NVS_TYPE_I16)
        {
            int16_t value;
            err = nvs_get_i16(handle, info.key, &value);
            if (err == ESP_OK)
            {
                printf("Value: %" PRId16 "\n", value);
            }
        }
        else if (info.type == NVS_TYPE_U32)
        {
            uint32_t value;
            err = nvs_get_u32(handle, info.key, &value);
            if (err == ESP_OK)
            {
                printf("Value: %" PRIu32 "\n", value);
            }
        }
        else if (info.type == NVS_TYPE_I32)
        {
            int32_t value;
            err = nvs_get_i32(handle, info.key, &value);
            if (err == ESP_OK)
            {
                printf("Value: %" PRId32 "\n", value);
            }
        }
        else if (info.type == NVS_TYPE_U64)
        {
            uint64_t value;
            err = nvs_get_u64(handle, info.key, &value);
            if (err == ESP_OK)
            {
                printf("Value: %" PRIu64 "\n", value);
            }
        }
        else if (info.type == NVS_TYPE_I64)
        {
            int64_t value;
            err = nvs_get_i64(handle, info.key, &value);
            if (err == ESP_OK)
            {
                printf("Value: %" PRId64 "\n", value);
            }
        }

        nvs_close(handle);
        err = nvs_entry_next(&it);
        if (err != ESP_OK)
        {
            break;
        }
    }

    nvs_release_iterator(it);
    return ESP_OK;
}

esp_err_t clear_nvs_entries()
{
    esp_err_t err = nvs_flash_erase();
    if (err != ESP_OK)
    {
        printf("Failed to erase NVS: %s\n", esp_err_to_name(err));
        return err;
    }

    err = nvs_flash_init();
    if (err != ESP_OK)
    {
        printf("Failed to initialize NVS: %s\n", esp_err_to_name(err));
        return err;
    }

    printf("NVS erased and re-initialized successfully\n");
    return ESP_OK;
}

/**
 * Command to set the nickname
 */
otError set_nickname_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    if (aArgsLength != 2)
    {
        printf("Usage: set_nickname <peer_address> <nickname>\n");
        return OT_ERROR_FAILED;
    }

    const char *peerAddr = aArgs[0];
    const char *nickname = aArgs[1];
    esp_err_t err = set_nickname(peerAddr, nickname);

    if (err == ESP_OK)
    {
        printf("Set nickname for %s as '%s'\n", peerAddr, nickname);
        return OT_ERROR_NONE;
    }
    else 
    {
        printf("Error setting nickname '%s' for %s\n", nickname, peerAddr);
        return OT_ERROR_FAILED;
    }
}

/**
 * Command to get the nickname
 */
otError get_nickname_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    if (aArgsLength != 1)
    {
        printf("Usage: get_nickname <peerAddr>\n");
        return OT_ERROR_FAILED;
    }

    const char *peerAddr = aArgs[0];
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
    if (aArgsLength != 1)
    {
        printf("Usage: get_ipv6 <nickname>\n");
        return OT_ERROR_FAILED;
    }

    const char *nickname = aArgs[0];
    char peerAddr[64];
    esp_err_t err = get_ipv6(nickname, peerAddr, sizeof(peerAddr));

    if (err == ESP_OK)
    {
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

otError get_nvs_entries_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    esp_err_t err = get_nvs_entries();
    if (err != ESP_OK)
    {
        printf("Failed to get NVS entries\n");
        return OT_ERROR_FAILED;
    }
    return OT_ERROR_NONE;
}

otError clear_nvs_entries_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    esp_err_t err = clear_nvs_entries();
    if (err != ESP_OK)
    {
        printf("Failed to clear NVS entries\n");
        return OT_ERROR_FAILED;
    }
    return OT_ERROR_NONE;
}