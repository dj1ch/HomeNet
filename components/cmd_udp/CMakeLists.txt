idf_component_register(SRCS "udp_cmd.c"
                    INCLUDE_DIRS "." "C:/Espressif/containers/v5.3/esp-idf/components/openthread/openthread/include"
                    PRIV_REQUIRES ieee802154 console esp_phy nvs_flash openthread esp_system cmd_thread cmd_chat littlefs)
