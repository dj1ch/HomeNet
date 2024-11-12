idf_component_register(SRCS "thread_cmd.c" "ieee802154_cmd.c"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES ieee802154 console esp_phy)
