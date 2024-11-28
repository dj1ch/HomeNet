idf_component_register(SRCS "chat_cmd.c"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES ieee802154 console esp_phy esp_system nvs_flash)
