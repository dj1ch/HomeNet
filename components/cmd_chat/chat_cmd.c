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

// temporary for now
bool clientDiscovered = false;

/**
 * Get the status of the chat, such as connection
 */
static void get_status(void)
{

}

/**
 * Set the nickname of a discovered client
 */
static esp_err_t set_nickname(const char *ipv6_addr, const char *nickname)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        err = nvs_set_str(handle, ipv6_addr, nickname);
        nvs_commit(handle);
        nvs_close(handle);
    }
    return err;
}

/**
 * Get the requested nickname(s) from NVS
 */
static esp_err_t get_nickname(const char *ipv6_addr, const char *nickname, size_t max_len) 
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &handle);
    if (err == ESP_OK)
    {
        err = nvs_get_str(handle, ipv6_addr, nickname, &max_len);
        nvs_close(handle);
    }
    return err;
}

/**
 * Starts chat with a discovered client
 */
static void start_chat(void)
{
    // start with a scan
    if (clientDiscovered)
    {
        printf("Would you like to set a nickname for the client? (y/n)\n");
        char ans;
        scanf(" %c", &ans);

        if (ans == 'y')
        {
            printf("Enter nickname: ");
            char nick[64];
            scanf("%63s", nick);  // limit input to 63 characters for safety

            printf("Set nickname: '%s'\n", nick);
            ans = ' ';

            printf("Is this okay? (y/n)\n");
            scanf(" %c", &ans);

            if (ans == 'y')
            {
                // placeholder for now
                const char *client_ipv6_addr = " ";
                if (set_nickname(client_ipv6_addr, nick) == ESP_OK)
                {
                    printf("Nickname '%s' set for client %s\n", nick, client_ipv6_addr);
                }
                else
                {
                    printf("Failed to set nickname for client %s\n", client_ipv6_addr);
                }
            }
        }
    }
}

static void register_chat(void)
{
    
}

