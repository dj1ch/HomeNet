#include "led_cmd.h"
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
#include "driver/gpio.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include "esp_system.h"
#include "esp_mac.h"

esp_err_t turn_on_led(void);
esp_err_t turn_off_led(void);

uint32_t LED_PIN = 7;
bool init = false;

/**
 * Make sure LED pin is set as an output pin
 */
esp_err_t init_led(void)
{
    // reset pin
    esp_err_t err = gpio_reset_pin(LED_PIN);
    if (err != ESP_OK)
    {
        return err;
    }

    err = gpio_set_direction(LED_PIN, GPIO_MODE_OUTPUT);

    if (err == ESP_OK)
    {
        init = true;
    }

    return err;
}

/**
 * Turns on the onboard LED
 */
esp_err_t turn_on_led(void)
{
    // double check
    if (!init)
    {
        init_led();
    }

    // 1 is high
    esp_err_t err = gpio_set_level(LED_PIN, 1);
    vTaskDelay(pdMS_TO_TICKS(500));

    return err;
}

/**
 * Turns off the onboard LED
 */
esp_err_t turn_off_led(void)
{
    // double check
    if (!init)
    {
        init_led();
    }

    // 0 is low
    esp_err_t err = gpio_set_level(LED_PIN, 0);
    vTaskDelay(pdMS_TO_TICKS(500));

    return err;
}

/**
 * Commannd to turn on the onboard LED
 */
otError turn_on_led_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    esp_err_t err = turn_on_led();
    if (err == ESP_OK)
    {
        return OT_ERROR_NONE;
    }
    return OT_ERROR_FAILED;
}

/**
 * Command to turn off the onboard LED
 */
otError turn_off_led_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    esp_err_t err = turn_off_led();
    if (err == ESP_OK)
    {
        return OT_ERROR_NONE;
    }
    return OT_ERROR_FAILED;
}