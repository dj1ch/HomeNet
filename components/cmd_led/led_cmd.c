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

static esp_err_t turn_on_led(void);
static esp_err_t turn_off_led(void);

/**
 * Make sure LED pin is set as an output pin
 */
esp_err_t init_led(void)
{
    esp_err_t err = gpio_set_direction(7, GPIO_MODE_OUTPUT);
    return err;
}

/**
 * Turns on the onboard LED
 */
static esp_err_t turn_on_led(void)
{
    // 1 is high
    esp_err_t err = gpio_set_level(7, 1);
    vTaskDelay(pdMS_TO_TICKS(500));

    return err;
}

/**
 * Turns off the onboard LED
 */
static esp_err_t turn_off_led(void)
{
    // 0 is low
    esp_err_t err = gpio_set_level(7, 0);
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