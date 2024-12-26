set(srcs "homenet.c")

set(include "."
            "include")

# In order for the cases defined by `TEST_CASE` to be linked into the final elf,
# the component can be registered as WHOLE_ARCHIVE
idf_component_register(SRCS ${srcs}
                       PRIV_REQUIRES ieee802154 console fatfs nvs_flash esp_phy cmd_system cmd_chat cmd_thread cmd_tcp openthread
                       WHOLE_ARCHIVE)
