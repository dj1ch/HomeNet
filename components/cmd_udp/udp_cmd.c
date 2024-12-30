
#include "udp_cmd.h"
#include "thread_cmd.h"
#include "openthread/tcp.h"
#include "openthread/tcp_ext.h"
#include "openthread/ip6.h"
#include "openthread/udp.h"
#include "openthread/error.h"
#include "openthread/logging.h"
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
#include "esp_openthread.h"
#include "esp_openthread_cli.h"
#include "esp_openthread_lock.h"
#include "esp_openthread_netif_glue.h"
#include "esp_openthread_types.h"
#include "esp_log.h"
#include <stdio.h>

#define MSG_SIZE 128

/**
 * Important definitions
 */
#define UDP_PORT 1602
#define NETWORK_NAME "homenet"
#define NETWORK_CHANNEL 15
#define TAG "homenet"

void udp_create_socket(otUdpSocket *aSocket,
                     otInstance *aInstance,
                     otSockAddr *aSockName)
{
    handle_error(otUdpOpen(aInstance, aSocket, NULL, NULL));
    handle_error(otUdpBind(aInstance, aSocket, aSockName, OT_NETIF_THREAD));
    return;
}

void create_rx_socket(otInstance *aInstance,
                          uint16_t port,
                          otSockAddr *aSockName,
                          otUdpSocket *aSocket)
{
    aSockName->mAddress = *otThreadGetMeshLocalEid(aInstance);
    aSockName->mPort = port;

    udp_create_socket(aSocket, aInstance, aSockName);
    return;
}

static inline uint16_t get_payload_length(const otMessage *aMessage) {
    return otMessageGetLength(aMessage) - otMessageGetOffset(aMessage);
}

static void udp_get_payload(const otMessage *aMessage, void* buffer) {
    uint16_t offset = otMessageGetOffset(aMessage);
    uint16_t length = get_payload_length(aMessage);

    uint16_t bytesRead = otMessageRead(aMessage, offset, buffer, length);
    assert(bytesRead == length);
    return;
}

/**
 * UDP message recieving callback
 */
static bool udp_msg_rcv_cb(void *aContext, const otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    uint16_t senderPort = aMessageInfo->mPeerPort;
    uint16_t receiverPort = aMessageInfo->mSockPort;

    if ((senderPort == UDP_PORT) && (receiverPort == UDP_PORT)) {
        char payload[MSG_SIZE];
        char output[MSG_SIZE];

        EmptyMemory(payload, MSG_SIZE);
        EmptyMemory(output, MSG_SIZE);

        udp_get_payload((const otMessage *) aMessage, payload);
        printf("Received: %s", payload);

        return true;
    }

  return false;
}

void udp_init_rx(otUdpReceiver *receiver) {
    receiver->mContext = NULL;
    receiver->mHandler = NULL;
    receiver->mNext = NULL;
    
    return;
}

void udp_create_rx(otInstance *aInstance, otUdpReceiver *receiver, otSockAddr *aSockName, otUdpSocket *aSocket) {
    receiver->mHandler = udp_msg_rcv_cb;
    receiver->mContext = NULL;
    receiver->mNext = NULL;
    
    handle_error(otUdpOpen(aInstance, aSocket, NULL, NULL));
    handle_error(otUdpBind(aInstance, aSocket, aSockName, OT_NETIF_THREAD));
    handle_error(otUdpAddReceiver(aInstance, receiver));
    return;
}

// quick hack to remove that annoying warning
static void send_udp(otInstance *aInstance, uint16_t port, uint16_t destPort, otUdpSocket *aSocket, otMessage *aMessage, otMessageInfo *aMessageInfo) __attribute__ ((__unused__));
static void send_udp(otInstance *aInstance, uint16_t port, uint16_t destPort, otUdpSocket *aSocket, otMessage *aMessage, otMessageInfo *aMessageInfo)
{
    otError error = otUdpSend(aInstance, aSocket, aMessage, aMessageInfo);
    handle_message_error(aMessage, error);
    if (error == OT_ERROR_NONE)
    {
        printf("Sent!\n");
    } else {
        printf("Failed to send!\n");
    }
    return;
}

/**
 * Send a message!
 */
static void send_message(otInstance *aInstance, const char *aBuf, otIp6Address *destAddr)
{
    char command[256];
    char addrStr[OT_IP6_ADDRESS_STRING_SIZE];

    // convert the address to a string
    otIp6AddressToString(destAddr, addrStr, sizeof(addrStr));
    snprintf(command, sizeof(command), "udp send %s %u %s", addrStr, UDP_PORT, aBuf);
    printf("Sending command: %s\n", command);

    // lazy hack to send a message
    otCliInputLine(command);
}

/**
 * Command which sends a message
 */
otError send_message_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    otInstance *aInstance = esp_openthread_get_instance();

    // check if the correct number of arguments is passed
    if (aArgsLength != 2)
    {
        printf("Usage: send_message <message> <ipv6_addr>\n");
        return OT_ERROR_FAILED;
    }

    // conversions
    const char *aBuf = aArgs[0];
    otIp6Address destAddr;
    otError err = otIp6AddressFromString(aArgs[1], &destAddr);
    if (err != OT_ERROR_NONE)
    {
        printf("Invalid IPv6 address: %s\n", aArgs[1]);
        return OT_ERROR_FAILED;
    }

    // send the message
    send_message(aInstance, aBuf, &destAddr);

    printf("Sent message \"%s\" to destination %s\n", aBuf, aArgs[1]);
    return OT_ERROR_NONE;
}

void register_udp()
{
    printf("doing nothing\n");
}