/**
 * Developer note:
 * In this file, we handle what is too specific to not be in thread_cmd.c.
 * Specifically, instead of handling thread, we use thread to handle specific
 * functions with the chatting.
 * 
 * Most of the stuff here is miscallenous and are more QOL if anything.
 */

#include "chat_cmd.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

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

static esp_err_t get_ipv6(const char *nickname, char *ipv6_addr, size_t len)
{
    if (!nickname || !ipv6_addr || len == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &handle);
    if (err != ESP_OK) {
        return err;
    }

    // iterate through all keys
    size_t req_size;
    err = nvs_get_all_keys(handle, NULL, &req_size);
    if (err != ESP_OK) {
        nvs_close(handle);
        return err;
    }

    // get the list
    char *keys = malloc(req_size);
    if (keys == NULL) {
        nvs_close(handle);
        return ESP_ERR_NO_MEM;
    }

    err = nvs_get_all_keys(handle, keys, &req_size);
    if (err != ESP_OK) {
        free(keys);
        nvs_close(handle);
        return err;
    }

    // look for a match
    esp_err_t result = ESP_ERR_NOT_FOUND; // not found
    for (size_t i = 0; i < req_size / sizeof(char*); ++i) {
        if (strcmp(&keys[i * sizeof(char*)], nickname) == 0) {
            // if the key matches the nickname, find the addr
            err = nvs_get_str(handle, &keys[i * sizeof(char*)], ipv6_addr, &len);
            if (err == ESP_OK) {
                result = ESP_OK;
            }
            break;
        }
    }

    free(keys);
    nvs_close(handle);
    return result;
}


static void cmd_get_nickname(int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage: get_nickname <ipv6_addr>\n");
        return;
    }

    const char *ipv6_addr = argv[1];
    char nickname[64];
    esp_err_t err = get_nickname(ipv6_addr, nickname, sizeof(nickname));

    if (err == ESP_OK) {
        printf("Nickname for %s: %s\n", ipv6_addr, nickname);
    } else if (err == ESP_ERR_NOT_FOUND) {
        printf("No nickname found for %s\n", ipv6_addr);
    } else {
        printf("Error retrieving nickname for %s: %s\n", ipv6_addr, esp_err_to_name(err));
    }
}

static void cmd_get_ipv6(int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage: get_ipv6 <nickname>\n");
        return;
    }

    const char *nickname = argv[1];
    char ipv6_addr[64];
    esp_err_t err = get_ipv6_by_nickname(nickname, ipv6_addr, sizeof(ipv6_addr));

    if (err == ESP_OK) {
        printf("IPv6 address for nickname '%s': %s\n", nickname, ipv6_addr);
    } else if (err == ESP_ERR_NOT_FOUND) {
        printf("No IPv6 address found for nickname '%s'\n", nickname);
    } else {
        printf("Error retrieving IPv6 address for nickname '%s': %s\n", nickname, esp_err_to_name(err));
    }
}



static void register_chat(void)
{
    const esp_console_cmd_t get_nickname_cmd_struct = {
        .command = "get_nickname",
        .help = "Get nickname through ipv6 address",
        .func = get_nickname,
    };

    const esp_console_cmd_t get_ipv6_cmd_struct = {
        .command = "get_ipv6",
        .help = "Get ipv6 address through nickname",
        .func = get_ipv6,
    };

    ESP_ERROR_CHECK(esp_console_cmd_register(&get_nickname_cmd_struct));
    ESP_ERROR_CHECK(esp_console_cmd_register(&get_ipv6_cmd_struct));

    printf("Chat system registered and ready.\n");
}
