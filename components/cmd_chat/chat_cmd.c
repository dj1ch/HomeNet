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
#include "esp_littlefs.h"
#include <dirent.h>

#define TAG "homenet"
#define MAX_PATH_LENGTH 320

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
 * Set the nickname of a discovered client,
 * where the nickname is stored as a file with the peer address in it
 */
esp_err_t set_nickname(const char *peerAddr, const char *nickname)
{
    if (!peerAddr || !nickname)
    {
        printf("Invalid arguments: peerAddr=%s, nickname=%s\n", peerAddr ? peerAddr : "NULL", nickname ? nickname : "NULL");
        return ESP_ERR_INVALID_ARG;
    }
    char path[MAX_PATH_LENGTH];
    snprintf(path, sizeof(path), "/littlefs" "/%s", nickname);

    FILE *f = fopen(path, "w");
    if (f == NULL)
    {
        printf("Failed to open file for writing\n");
        return ESP_FAIL;
    }

    fprintf(f, "%s", peerAddr);
    fclose(f);

    printf("Set nickname for %s as '%s'\n", peerAddr, nickname);
    return ESP_OK;
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

    DIR *d = opendir("/littlefs");
    if (d == NULL)
    {
        printf("Failed to open directory\n");
        return ESP_FAIL;
    }

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL)
    {
        char path[MAX_PATH_LENGTH];
        snprintf(path, sizeof(path), "/littlefs" "%s", entry->d_name);

        FILE *f = fopen(path, "r");
        if (f == NULL)
        {
            continue;
        }

        char storedPeerAddr[64];
        fgets(storedPeerAddr, sizeof(storedPeerAddr), f);
        fclose(f);

        if (strcmp(storedPeerAddr, peerAddr) == 0)
        {
            strncpy(nickname, entry->d_name, len);
            closedir(d);
            return ESP_OK;
        }
    }

    closedir(d);
    return ESP_FAIL;
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

    char path[MAX_PATH_LENGTH];
    snprintf(path, sizeof(path), "/littlefs" "/%s", nickname);

    FILE *f = fopen(path, "r");
    if (f == NULL)
    {
        printf("Nickname '%s' not found\n", nickname);
        return ESP_FAIL;
    }

    fgets(peerAddr, len, f);
    fclose(f);

    printf("Found IPv6 address '%s' for nickname '%s'\n", peerAddr, nickname);
    return ESP_OK;
}

/**
 * List all NVS key-value entries
 */
esp_err_t get_nvs_entries()
{
    DIR *d = opendir("/littlefs");
    if (d == NULL)
    {
        printf("Failed to open directory\n");
        return ESP_FAIL;
    }

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL)
    {
        char path[MAX_PATH_LENGTH];
        snprintf(path, sizeof(path), "/littlefs" "/%s", entry->d_name);

        FILE *f = fopen(path, "r");
        if (f == NULL)
        {
            continue;
        }

        char peerAddr[64];
        fgets(peerAddr, sizeof(peerAddr), f);
        fclose(f);

        printf("Nickname: %s, IPv6 Address: %s\n", entry->d_name, peerAddr);
    }

    closedir(d);
    return ESP_OK;
}

esp_err_t clear_nvs_entries()
{
    DIR *d = opendir("/littlefs");
    if (d == NULL)
    {
        printf("Failed to open directory\n");
        return ESP_FAIL;
    }

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL)
    {
        char path[MAX_PATH_LENGTH];
        snprintf(path, sizeof(path), "/littlefs" "/%s", entry->d_name);

        if (remove(path) != 0)
        {
            printf("Failed to remove file: %s\n", path);
        }
    }

    closedir(d);
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