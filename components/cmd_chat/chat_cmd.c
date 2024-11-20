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

#include "esp_system.h"
#include "nvs_flash.h"
#include "nvs.h"

/**
 * Set the nickname of a discovered client
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
static esp_err_t get_nickname(const char *ipv6_addr, char *nickname, size_t max_len)
{
    if (!ipv6_addr || !nickname || max_len == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &handle);
    if (err == ESP_OK)
    {
        err = nvs_get_str(handle, ipv6_addr, nickname, &max_len);
        nvs_close(handle);
    }
    return err;
}

static void register_chat(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    printf("Chat system registered and ready.\n");
}
