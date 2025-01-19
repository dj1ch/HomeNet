/**
 * Developer note:
 * 
 * Due to a constantly changing program, I am going to isolate
 * the message sending functions into a seperate file for the sake 
 * of organization. I am way too lazy to put this back into thread_cmd.c,
 * let alone rewrite it to be more efficient.
 */

#include "udp_cmd.h"
#include "thread_cmd.h"
#include "chat_cmd.h"
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
#define MAX_PATH_LENGTH 320

/**
 * This is a very "hacky" way to get the ipv6 address
 * and returning it as a string without the usage of get_ipv6,
 * which is was meant to be used for a command...
 */
char* get_ipv6_str(char *nickname, size_t len)
{
    // backup string
    char* failed = "failed";

    // get the nickname
    char path[MAX_PATH_LENGTH];
    snprintf(path, sizeof(path), "/littlefs/%s", nickname);

    FILE *f = fopen(path, "r");
    if (f == NULL)
    {
        printf("Nickname '%s' not found\n", nickname);
        return failed;
    }

    char *peerAddr = (char *)malloc(len);
    if (peerAddr == NULL)
    {
        printf("Failed to allocate memory for peer address\n");
        fclose(f);
        return failed;
    }

    if (fgets(peerAddr, len, f) == NULL)
    {
        printf("Failed to read peer address\n");
        free(peerAddr);
        fclose(f);
        return failed;
    }

    fclose(f);
    return peerAddr;
}

/**
 * Send command to openthread CLI instead of using otCLiInputLine
 * 
 * Source: https://github.com/nanoframework/nf-interpreter/blob/66244e0a10cf4340e88094357098d6ab397b7fc1/targets/ESP32/_Network/NF_ESP32_OpenThread.cpp#L331
 */
void ot_cli_input(const char *inputLine)
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

inline uint16_t get_payload_length(const otMessage *aMessage) {
    return otMessageGetLength(aMessage) - otMessageGetOffset(aMessage);
}

void udp_get_payload(const otMessage *aMessage, void* buffer) {
    uint16_t offset = otMessageGetOffset(aMessage);
    uint16_t length = get_payload_length(aMessage);

    uint16_t bytesRead = otMessageRead(aMessage, offset, buffer, length);
    assert(bytesRead == length);
    return;
}

/**
 * UDP message recieving callback
 */
bool udp_msg_rcv_cb(void *aContext, const otMessage *aMessage, const otMessageInfo *aMessageInfo)
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

void send_udp(otInstance *aInstance, uint16_t port, uint16_t destPort, otUdpSocket *aSocket, otMessage *aMessage, otMessageInfo *aMessageInfo)
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
    if (aArgsLength < 2)
    {
        printf("Usage: send_message <message> <ipv6_addr>\n");
        return OT_ERROR_INVALID_ARGS;
    }

    // conversions
    otIp6Address destAddr;
    esp_err_t err;
    otError error;

    // check LittleFS for nickname if one is provided
    char *peerAddr;
    size_t len = 64;
    peerAddr = get_ipv6_str(aArgs[aArgsLength - 1], len);
    if (strcmp(peerAddr, "failed") != 0)
    {
        printf("Found IPv6 address '%s' for nickname '%s'\n", peerAddr, aArgs[aArgsLength - 1]);
        error = otIp6AddressFromString(peerAddr, &destAddr);
        if (error != OT_ERROR_NONE)
        {
            printf("Invalid IPv6 address: %s\n", peerAddr);
            return error;
        }
        if (error == OT_ERROR_NONE)
        {
            otIp6AddressFromString(peerAddr, &destAddr);
        }
    }
    else
    {
        printf("Nickname '%s' not found, switching to command line argument\n", aArgs[aArgsLength - 1]);
        error = otIp6AddressFromString(aArgs[aArgsLength - 1], &destAddr);
        if (error != OT_ERROR_NONE)
        {
            printf("Invalid IPv6 address: %s\n", aArgs[aArgsLength - 1]);
            return error;
        }
    }

    // create into one string
    size_t messageLength = 0;
    for (uint8_t i = 0; i < aArgsLength - 1; i++)
    {
        messageLength += strlen(aArgs[i]) + 1; // +1 for space or null terminator
    }

    char *message = (char *)malloc(messageLength);
    if (message == NULL)
    {
        printf("Failed to allocate memory for message\n");
        return OT_ERROR_NO_BUFS;
    }

    message[0] = '\0';
    for (uint8_t i = 0; i < aArgsLength - 1; i++)
    {
        strcat(message, aArgs[i]);
        if (i < aArgsLength - 2)
        {
            strcat(message, " ");
        }
    }

    // initialize the UDP socket
    otUdpSocket aSocket;
    otSockAddr aSockName = {0};
    aSockName.mAddress = *otThreadGetMeshLocalEid(esp_openthread_get_instance());
    aSockName.mPort = UDP_PORT;
    udp_create_socket(&aSocket, aInstance, &aSockName);

    // create the message
    otMessage *aMessage = otUdpNewMessage(aInstance, NULL);
    if (aMessage == NULL)
    {
        printf("Failed to allocate message\n");
        otUdpClose(aInstance, &aSocket);
        free(message);
        return OT_ERROR_NO_BUFS;
    }

    // append the message
    err = otMessageAppend(aMessage, message, strlen(message));
    if (err != OT_ERROR_NONE)
    {
        printf("Failed to append message: %s\n", otThreadErrorToString(err));
        otMessageFree(aMessage);
        otUdpClose(aInstance, &aSocket);
        free(message);
        return err;
    }

    // prepare the message info
    otMessageInfo aMessageInfo = {0};
    aMessageInfo.mSockAddr = aSockName.mAddress;
    aMessageInfo.mSockPort = UDP_PORT;
    aMessageInfo.mPeerPort = UDP_PORT;
    aMessageInfo.mPeerAddr = destAddr;

    // send it
    // send_udp(aInstance, UDP_PORT, UDP_PORT, &aSocket, aMessage, &aMessageInfo);
    error = otUdpSend(aInstance, &aSocket, aMessage, &aMessageInfo);
    if (error != OT_ERROR_NONE)
    {
        printf("Failed to send message: %s\n", otThreadErrorToString(error));
        otMessageFree(aMessage);
        otUdpClose(aInstance, &aSocket);
        free(message);
        return error;
    }

    // close the socket
    otUdpClose(aInstance, &aSocket);

    printf("Sent message \"%s\" to destination %s\n", message, aArgs[aArgsLength - 1]);
    free(message);
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