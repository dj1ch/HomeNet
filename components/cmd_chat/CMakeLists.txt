idf_component_register(SRCS "chat_cmd.c"
                    INCLUDE_DIRS "." "C:/Espressif/containers/v5.3/esp-idf/components/openthread/openthread/include"
                    PRIV_REQUIRES ieee802154 console esp_phy esp_system nvs_flash openthread cmd_thread littlefs)
