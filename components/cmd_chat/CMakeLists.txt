idf_component_register(SRCS "chat_cmd.c" "ieee802154_cmd.c"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES ieee802154 console esp_phy nvs esp_system nvs)
