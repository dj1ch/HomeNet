
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

/**
 * Send command to openthread CLI instead of using otCLiInputLine
 * 
 * Source: https://github.com/nanoframework/nf-interpreter/blob/66244e0a10cf4340e88094357098d6ab397b7fc1/targets/ESP32/_Network/NF_ESP32_OpenThread.cpp#L331
 */
static void ot_cli_input(const char *inputLine)
{
    // Need to take a copy of inputLine as otCliInputLine modifies the line when parsing
    int length = strlen(inputLine);
    char *cliLine = (char *)malloc(length + 1);
    if (cliLine == NULL)
    {
        // Handle memory allocation failure
        return;
    }
    strcpy(cliLine, inputLine);

    otCliInputLine(cliLine);

    free(cliLine);
}

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

void send_commands(const char *commands[], int numCommands)
{
    for (int i = 0; i < numCommands; i++)
    {
        ot_cli_input(commands[i]);
    }
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
        return OT_ERROR_INVALID_ARGS;
    }

    // conversions
    otIp6Address destAddr;
    otError err = otIp6AddressFromString(aArgs[1], &destAddr);
    if (err != OT_ERROR_NONE)
    {
        printf("Invalid IPv6 address: %s\n", aArgs[1]);
        return err;
    }

    // initialize the UDP socket
    otUdpSocket aSocket;
    otSockAddr aSockName;

    aSockName.mPort = UDP_PORT;
    aSockName.mAddress = *otThreadGetMeshLocalEid(aInstance);
    udp_create_socket(&aSocket, aInstance, &aSockName);

    // create the message
    otMessage *aMessage = otUdpNewMessage(aInstance, NULL);
    if (aMessage == NULL)
    {
        printf("Failed to allocate message\n");
        otUdpClose(aInstance, &aSocket);
        return OT_ERROR_NO_BUFS;
    }

    // append the message
    err = otMessageAppend(aMessage, aArgs[0], strlen(aArgs[0]));
    if (err != OT_ERROR_NONE)
    {
        printf("Failed to append message: %s\n", otThreadErrorToString(err));
        otMessageFree(aMessage);
        otUdpClose(aInstance, &aSocket);
        return err;
    }

    // prepare the message info
    otMessageInfo aMessageInfo;

    memset(&aMessageInfo, 0, sizeof(aMessageInfo));
    aMessageInfo.mPeerAddr = destAddr;
    aMessageInfo.mSockAddr = aSockName.mAddress;
    aMessageInfo.mPeerPort = UDP_PORT;
    aMessageInfo.mSockPort = UDP_PORT;

    // send it
    send_udp(aInstance, UDP_PORT, UDP_PORT, &aSocket, aMessage, &aMessageInfo);

    // close the socket
    otUdpClose(aInstance, &aSocket);

    printf("Sent message \"%s\" to destination %s\n", aArgs[0], aArgs[1]);
    return OT_ERROR_NONE;
}

void register_udp()
{
    const char *udpCmds[] = {
        "udp open",
        "udp bind :: 1602"
    };

    send_commands(udpCmds, 2);
}