/**
 * Developer Note:
 * This is an esp-idf component designed to help assist
 * in the creation of a small P2P network between a multitude
 * of clients. Messages are sent over UDP with openthread
 * and possibly other affiliated tools.
 * 
 * In simpler terms, this is the bread and butter of HomeNet's
 * main functionality.
 * 
 * Other components such as ieee802154_cmd.c have NOT
 * been created by me, rather modified to fit
 * this embedded application.
 * 
 * Thanks again, dj1ch
 */

#include "thread_cmd.h"
#include "udp_cmd.h"
#include "chat_cmd.h"
#include "led_cmd.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "esp_system.h"
#include "esp_random.h"
#include "esp_mac.h"
#include "esp_event.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include "openthread/thread.h"
#include "openthread/message.h"
#include "openthread/udp.h"
#include "openthread/instance.h"
#include "openthread/ip6.h"
#include "openthread/logging.h"
#include "openthread/cli.h"
#include "openthread/platform/misc.h"
#include "openthread/thread.h"
#include "openthread/thread_ftd.h"
#include "openthread/diag.h"
#include "esp_netif.h"
#include "esp_netif_types.h"
#include "esp_openthread.h"
#include "esp_openthread_cli.h"
#include "esp_openthread_lock.h"
#include "esp_openthread_netif_glue.h"
#include "esp_openthread_types.h"
#include "esp_ot_config.h"
#include "esp_vfs_eventfd.h"
#include "esp_console.h"
#include "argtable3/argtable3.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "driver/gpio.h"

/**
 * Special magic number
 */
uint64_t magic_num = 0x48616E616B6F;

/**
 * Important definitions
 */
#define UDP_PORT 1602
#define NETWORK_NAME "homenet"
#define NETWORK_CHANNEL 15
#define TAG "homenet"

/**
 * Something I found off of this goldmine
 * 
 * https://github.com/UCSC-ThreadAscon/ot-send/blob/8de0bb19eb1d5e9d869899572b35a1c3733aa609/components/ot_send/include/ot_send.h#L72
 */
#define EmptyMemory(pointer, size) memset((void *) pointer, 0, size)
#define DEBUG true
#define DELIMITER "************************************"
#define PRINT_DELIMIER otLogNotePlat(DELIMITER)
#define DEBUG_PRINT(ot_note) PRINT_DELIMIER; ot_note; PRINT_DELIMIER;
#define ERROR_PRINT(ot_error) otLogCritPlat(DELIMITER); ot_error; otLogCritPlat(DELIMITER);

/**
 * Function definitions
 */
otError handle_error(otError error);
void handle_message_error(otMessage *aMessage, otError error);

otIp6Address *get_ipv6_address(void);

otUdpSocket init_ot_udp_socket(otUdpSocket aSocket, otSockAddr aSockName);
otSockAddr init_ot_sock_addr(otSockAddr aSockName);
otMessageInfo init_ot_message_info(otMessageInfo aMessageInfo, otUdpSocket aSocket);
otUdpReceiver init_ot_udp_receiver(otUdpReceiver aReceiver);
otUdpSocket *ot_udp_socket_to_ptr(otUdpSocket aSocket, otUdpSocket *aSocketPtr);
otSockAddr *ot_sock_addr_to_ptr(otSockAddr aSockName, otSockAddr *aSockNamePtr);
otMessageInfo *ot_message_info_to_ptr(otMessageInfo aMessageInfo, otMessageInfo *aMessageInfoPtr);
otMessageInfo *const_ptr_ot_message_info_to_ptr(const otMessageInfo *aMessageInfo, otMessageInfo *aMessageInfoPtr);
otUdpReceiver *ot_udp_receiver_to_ptr(otUdpReceiver aReceiver, otUdpReceiver *aReceiverPtr);

static void configure_network(void);
static void configure_joiner(void);

static otError configure_network_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
static otError configure_joiner_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);

void register_thread(void);

/**
 * Static NVS handle
 */
nvs_handle_t handle;

otError handle_error(otError error) {
  if (error != OT_ERROR_NONE) {
    ERROR_PRINT(otLogCritPlat("%s", otThreadErrorToString(error)));
  }
  return error;
}

void handle_message_error(otMessage *aMessage, otError error) {
  if (handle_error(error) != OT_ERROR_NONE) {
    otMessageFree(aMessage);
  }
  return;
}

/**
 * Gets current ipv6 address to be used for other structures or functions
 */
otIp6Address *get_ipv6_address()
{
    // get local ml-eid
    const otIp6Address *addr = otThreadGetMeshLocalEid(esp_openthread_get_instance());

    otIp6Address *addrCopy;
    memcpy(&addrCopy, &addr, sizeof(addr));

    // return copied
    return addrCopy;
}

/**
 * Preferably, we call it like so...
 * 
 * otSockAddr aSockName;
 * otUdpSocket aSocket;
 * 
 * aSockName = init_ot_sock_name(aSockName);
 * aSocket = init_ot_udp_socket(aSocket, aSockName);
 */

/**
 * Initializes aSocket
 */
otUdpSocket init_ot_udp_socket(otUdpSocket aSocket, otSockAddr aSockName)
{   
    // reset
    memset(&aSocket, 0, sizeof(aSocket));

    aSocket.mSockName = aSockName;
    aSocket.mPeerName.mPort = 0;
    aSocket.mHandler = NULL;
    aSocket.mContext = NULL;
    aSocket.mHandle = NULL;

    return aSocket;
}

/**
 * Initializes aSockName
 */
otSockAddr init_ot_sock_addr(otSockAddr aSockName)
{
    // reset
    memset(&aSockName, 0, sizeof(aSockName));

    otIp6Address *ipv6Addr = get_ipv6_address();
    aSockName.mAddress = *ipv6Addr;
    aSockName.mPort = UDP_PORT;

    return aSockName;
}

/**
 * Initializes aMessageInfo
 */
otMessageInfo init_ot_message_info(otMessageInfo aMessageInfo, otUdpSocket aSocket)
{
    // reset
    memset(&aMessageInfo, 0, sizeof(aMessageInfo));

    aMessageInfo.mSockAddr = aSocket.mSockName.mAddress;
    aMessageInfo.mSockPort = aSocket.mSockName.mPort;
    otIp6AddressFromString("ff03::1", &aMessageInfo.mPeerAddr);
    aMessageInfo.mPeerPort = UDP_PORT;
    aMessageInfo.mHopLimit = 0;
    aMessageInfo.mAllowZeroHopLimit = 0;

    return aMessageInfo;
}

otUdpReceiver init_ot_udp_receiver(otUdpReceiver aReceiver)
{
    aReceiver.mContext = NULL;
    aReceiver.mHandler = NULL;
    aReceiver.mNext = NULL;

    return aReceiver;
}

otUdpSocket *ot_udp_socket_to_ptr(otUdpSocket aSocket, otUdpSocket *aSocketPtr)
{
    aSocketPtr->mSockName = aSocket.mSockName;
    aSocketPtr->mPeerName.mPort = aSocket.mPeerName.mPort;
    aSocketPtr->mHandler = aSocket.mHandler;
    aSocketPtr->mContext = aSocket.mContext;
    aSocketPtr->mHandle = aSocket.mHandle;

    return aSocketPtr;
}

otSockAddr *ot_sock_addr_to_ptr(otSockAddr aSockName, otSockAddr *aSockNamePtr)
{
    aSockNamePtr->mAddress = aSockName.mAddress;
    aSockNamePtr->mPort = aSockName.mPort;

    return aSockNamePtr;
}

otMessageInfo *ot_message_info_to_ptr(otMessageInfo aMessageInfo, otMessageInfo *aMessageInfoPtr)
{
    aMessageInfoPtr->mSockAddr = aMessageInfo.mSockAddr;
    aMessageInfoPtr->mSockPort = aMessageInfo.mSockPort;
    aMessageInfoPtr->mPeerAddr = aMessageInfo.mPeerAddr;
    aMessageInfoPtr->mPeerPort = aMessageInfo.mPeerPort;
    aMessageInfoPtr->mHopLimit = aMessageInfo.mHopLimit;
    aMessageInfoPtr->mAllowZeroHopLimit = aMessageInfo.mAllowZeroHopLimit;

    return aMessageInfoPtr;
}

otMessageInfo *const_ptr_ot_message_info_to_ptr(const otMessageInfo *aMessageInfo, otMessageInfo *aMessageInfoPtr)
{
    aMessageInfoPtr->mSockAddr = aMessageInfo->mSockAddr;
    aMessageInfoPtr->mSockPort = aMessageInfo->mSockPort;
    aMessageInfoPtr->mPeerAddr = aMessageInfo->mPeerAddr;
    aMessageInfoPtr->mPeerPort = aMessageInfo->mPeerPort;
    aMessageInfoPtr->mHopLimit = aMessageInfo->mHopLimit;
    aMessageInfoPtr->mAllowZeroHopLimit = aMessageInfo->mAllowZeroHopLimit;

    return aMessageInfoPtr;
}

otUdpReceiver *ot_udp_receiver_to_ptr(otUdpReceiver aReceiver, otUdpReceiver *aReceiverPtr)
{
    aReceiverPtr->mContext = aReceiver.mContext;
    aReceiverPtr->mHandler = aReceiver.mHandler;
    aReceiverPtr->mNext = aReceiver.mNext;

    return aReceiverPtr;
}

/**
 * Properly configures the network for use. May use TCP as well in the future
 */
static void configure_network(void)
{
    otInstance *aInstance = esp_openthread_get_instance();

    otThreadSetEnabled(aInstance, true);

    otOperationalDataset dataset;
    otTimestamp timestamp;
    memset(&dataset, 0, sizeof(dataset));

    // too lazy to make this a function, besides we're only doing this once
    timestamp.mSeconds = 1024;
    timestamp.mTicks = 1;
    timestamp.mAuthoritative = false;

    dataset.mActiveTimestamp = timestamp;
    dataset.mComponents.mIsActiveTimestampPresent = true;

    dataset.mPanId = 0x1707;
    dataset.mComponents.mIsPanIdPresent = true;

    uint8_t extPanId[8] = {0x48, 0x41, 0x4E, 0x41, 0x4B, 0x4F, 0x48, 0x4F};
    memcpy(dataset.mExtendedPanId.m8, extPanId, sizeof(extPanId));
    dataset.mComponents.mIsExtendedPanIdPresent = true;

    uint8_t networkKey[16] = {0x48, 0x41, 0x4E, 0x41, 0x00, 0x43, 0x48, 0x41, 
                              0x4E, 0x00, 0x48, 0x4F, 0x4B, 0x41, 0x4D, 0x41};
    memcpy(dataset.mNetworkKey.m8, networkKey, sizeof(networkKey));
    dataset.mComponents.mIsNetworkKeyPresent = true;

    strncpy(dataset.mNetworkName.m8, NETWORK_NAME, OT_NETWORK_NAME_MAX_SIZE);
    dataset.mComponents.mIsNetworkNamePresent = true;

    dataset.mChannel = NETWORK_CHANNEL;
    dataset.mComponents.mIsChannelPresent = true;

    otDatasetSetActive(aInstance, &dataset);

    otIp6Address *addr = get_ipv6_address();
    char addrStr[OT_IP6_ADDRESS_STRING_SIZE];
    otIp6AddressToString(addr, addrStr, sizeof(addrStr));
    printf("Mesh Local EID: %s\n", addrStr);
    printf("Copy this address to the other device to send a message!\n");

    otCliInputLine("udp open");
    otCliInputLine("udp bind :: 1602");
}

static void configure_joiner(void)
{
    otInstance *aInstance = esp_openthread_get_instance();

    otOperationalDataset dataset;

    dataset.mPanId = 0x1707;
    dataset.mComponents.mIsPanIdPresent = true;

    uint8_t extPanId[8] = {0x48, 0x41, 0x4E, 0x41, 0x4B, 0x4F, 0x48, 0x4F};
    memcpy(dataset.mExtendedPanId.m8, extPanId, sizeof(extPanId));
    dataset.mComponents.mIsExtendedPanIdPresent = true;

    uint8_t networkKey[16] = {0x48, 0x41, 0x4E, 0x41, 0x00, 0x43, 0x48, 0x41, 
                              0x4E, 0x00, 0x48, 0x4F, 0x4B, 0x41, 0x4D, 0x41};
    memcpy(dataset.mNetworkKey.m8, networkKey, sizeof(networkKey));
    dataset.mComponents.mIsNetworkKeyPresent = true;

    dataset.mChannel = NETWORK_CHANNEL;
    dataset.mComponents.mIsChannelPresent = true;

    otDatasetSetActive(aInstance, &dataset);

    otThreadSetRouterEligible(aInstance, false);

    otThreadSetEnabled(aInstance, true);

    otIp6Address *addr = get_ipv6_address();
    char addrStr[OT_IP6_ADDRESS_STRING_SIZE];
    otIp6AddressToString(addr, addrStr, sizeof(addrStr));
    printf("Mesh Local EID: %s\n", addrStr);
    printf("Copy this address to the other device to send a message!\n");

    otCliInputLine("udp open");
    otCliInputLine("udp bind :: 1602");
}

static otError configure_network_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    configure_network();

    return OT_ERROR_NONE;
}

static otError configure_joiner_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    configure_joiner();

    return OT_ERROR_NONE;
}

/**
 * Creates an instance of thread and joins or forms the network dynamically
 */
void register_thread(void)
{
    // vfs config
    esp_vfs_eventfd_config_t eventfd_config = {.max_fds = 3};
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_vfs_eventfd_register(&eventfd_config));

    // openthread platform configuration
    esp_openthread_platform_config_t config = {
        .radio_config = ESP_OPENTHREAD_DEFAULT_RADIO_CONFIG(),
        .host_config = ESP_OPENTHREAD_DEFAULT_HOST_CONFIG(),
        .port_config = ESP_OPENTHREAD_DEFAULT_PORT_CONFIG(),
    };
    ESP_ERROR_CHECK(esp_openthread_init(&config));

#if CONFIG_OPENTHREAD_STATE_INDICATOR_ENABLE
    ESP_ERROR_CHECK(esp_openthread_state_indicator_init(esp_openthread_get_instance()));
#endif

#if CONFIG_OPENTHREAD_LOG_LEVEL_DYNAMIC
    (void)otLoggingSetLevel(OT_LOG_LEVEL_NOTE);
#endif
#if CONFIG_OPENTHREAD_CLI
    esp_openthread_cli_init();
#endif

    // init network interface
    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_OPENTHREAD();
    esp_netif_t *openthread_netif = esp_netif_new(&cfg);
    assert(openthread_netif != NULL);
    ESP_ERROR_CHECK(esp_netif_attach(openthread_netif, esp_openthread_netif_glue_init(&config)));
    esp_netif_set_default_netif(openthread_netif);

    // init openthread instance
    otInstance *aInstance = otInstanceInitSingle();
    if (aInstance == NULL) {
        ESP_LOGE(TAG, "Failed to initialize OpenThread instance");
        return;
    }

    // init onboard LED
    ESP_ERROR_CHECK(init_led());

    // enable ipv6
    esp_openthread_lock_acquire(0);
    otIp6SetEnabled(aInstance, true);
    otLinkSetEnabled(aInstance, true);
    esp_openthread_lock_release();

    register_udp();

#if CONFIG_OPENTHREAD_CLI_ESP_EXTENSION
    esp_cli_custom_command_init();
#endif // CONFIG_OPENTHREAD_CLI_ESP_EXTENSION

    // register commands
#if CONFIG_OPENTHREAD_CLI
    esp_openthread_cli_create_task();
    const otCliCommand kCommands[] = {
        {"set_nickname", set_nickname_cmd},
        {"get_nickname", get_nickname_cmd},
        {"get_ipv6", get_ipv6_cmd},
        {"send_message", send_message_cmd},
        {"configure_network", configure_network_cmd},
        {"configure_joiner", configure_joiner_cmd},
        {"turn_on_led", turn_on_led_cmd},
        {"turn_off_led", turn_off_led_cmd}
    };
    otCliSetUserCommands(kCommands, OT_ARRAY_LENGTH(kCommands), aInstance);
#endif

    // auto-start thread
#if CONFIG_OPENTHREAD_AUTO_START
    otOperationalDatasetTlvs dataset;
    otError err = otDatasetGetActiveTlvs(esp_openthread_get_instance(), &dataset);
    if (err == OT_ERROR_NONE) {
        ESP_ERROR_CHECK(esp_openthread_auto_start(&dataset));
    } else {
        otThreadStart(aInstance);
    }
#endif

    /**
     * initiates device role; if this device is the leader, it starts the network
     * otherwise, it joins the existing network dynamically.
     * 
     * in theory we should start as detached
    */
    esp_openthread_launch_mainloop();

    // cleanup after mainloop stops
    esp_openthread_netif_glue_deinit();
    esp_netif_destroy(openthread_netif);
    esp_vfs_eventfd_unregister();
}
