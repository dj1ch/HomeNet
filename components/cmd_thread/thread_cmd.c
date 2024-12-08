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
#include "openthread/instance.h"
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
#define MSG_SIZE 128
#define ADVERT_SIZE 64
#define ADVERT_MSG_FORMAT "Thread device available, Magic Number: "
#define TIMEOUT_MS 10000
#define UDP_PORT 602
#define VERIF_PORT 603
#define MAX_PEERS 10
#define PROMPT_STR "homenet"
#define TAG "homenet"

/**
 * Function definitions
 */
static int random_range(int min, int max);
static int generate_verif_code(void);
static void random_ipv6_addr(otInstance *aInstance);
static otIp6Address get_ipv6_address(otInstance *aInstance);
static void init_udp_sock(otInstance *aInstance);
static void udp_advert_rcv_cb(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo);
static void udp_msg_rcv_cb(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo);
static void udp_verif_rcv_cb(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo);
static void send_message(otInstance *aInstance, const char *aMessage, otIp6Address *destAddr);
static void send_thread_advertisement(otInstance *aInstance);
static void start_peer_scan(otInstance *aInstance);
static void start_verif_process(otInstance *aInstance, const otMessageInfo *aMessageInfo);
static void advert_task(void *argc);
static void start_advert_task(otInstance *aInstance, uint32_t it);
static void stop_advert_task(void);
static void handshake_task(void *pvParameters);
static void listening_task(void *pvParameters);
static void sending_task(void *pvParameters);
static void start_chat(char *ipv6_addr);
static otError stop_advert_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
static otError send_advert_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
static otError start_scan_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
static otError send_verification_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
static otError start_chat_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);
void register_thread(void);

typedef struct {
    otIp6Address peerAddr;
    int expected;
    bool active;     
} peer_verif_session;

static otUdpSocket aSocket;
static otSockAddr aSockName;
static otMessageInfo aMessageInfo;

static peer_verif_session peerSessions[MAX_PEERS] = {0};

/**
 * OpenThread instance for singleton pattern
 */
otInstance *otInstancePtr = NULL;

/**
 * Advertisement task handle
 */
static TaskHandle_t advertTaskHandle = NULL;

/**
 * Stop flag for advertisement task
 */
static bool stopAdvertTask = false;

/**
 * Queue for handshakes and messaging
 */
static QueueHandle_t handshakeQueue;
static QueueHandle_t messageQueue;

/**
 * Static NVS handle
 */
nvs_handle_t handle;

/**
 * Generates a random number given a minimum and maximum range
 */
static int random_range(int min, int max) { return min + esp_random() % (max - min + 1); }

/**
 * Finds the instance of OpenThread
 * within the code and returns it.
 */
otInstance *get_ot_instance(void)
{
    if (otInstancePtr == NULL) {
        // init only once!
        otInstancePtr = otInstanceInitSingle();
        if (otInstancePtr == NULL) {
            printf("Failed to initialize OpenThread instance\n");
            return NULL;
        }
        printf("OpenThread instance initialized\n");
    } else {
        printf("OpenThread instance already initialized\n");
    }
    return otInstancePtr;
}

/**
 * Generate a random verification code, 
 * the concept isn't random, rather psuedo-random.
 * I would NOT consider this secure.
 */
static int generate_verif_code(void)
{
    int randSize = random_range(5,10);
    int verifCode = 0;

    // improved verification code generator
    for (int i = 0; i < randSize; i++)
    {
        int digit = random_range(1,9);
        verifCode = verifCode * 10 + digit;
    }

    return verifCode;
}

/**
 * Generate a random ID to use when communicating 
 * with another client
 */
static void random_ipv6_addr(otInstance *aInstance)
{
    // create an instance of the address
    otNetifAddress addr;
    memset(&addr, 0, sizeof(addr));


    // set as a local address
    addr.mAddress.mFields.m8[0] = 0xfd;

    // generate first 5 random bytes
    for (int i = 1; i < 6; i++) 
    {
        addr.mAddress.mFields.m8[i] = esp_random() & 0xff;
    }

    // fill up the remaining fields with randomness
    for (int i = 6; i < 16; i++) 
    {
        addr.mAddress.mFields.m8[i] = esp_random() & 0xff;
    }

    // set prefix length
    addr.mPrefixLength = 48;
    addr.mPreferred = true;
    addr.mValid = true;
    
    // add to thread
    otIp6AddUnicastAddress(aInstance, &addr);

    char addrStr[40];
    otIp6AddressToString(&addr.mAddress, addrStr, sizeof(addrStr));
    printf("Generated IPv6 Address: %s\n", addrStr);
}

/**
 * Gets current ipv6 address to be used for other structures or functions
 */
static otIp6Address get_ipv6_address(otInstance *aInstance)
{
    const otNetifAddress *addr = otIp6GetUnicastAddresses(aInstance);

    // check for unicast addresses, and if there are none, return nothing
    while (addr != NULL)
    {
        if ((addr->mAddress.mFields.m8[0] == 0xfe) && ((addr->mAddress.mFields.m8[1] & 0xc0) == 0x80))
        {
            return addr->mAddress;
        }
        addr = addr->mNext;
    }

    otIp6Address unspecifAddr = {0};
    return unspecifAddr;
}

/**
 * Initializes aSockName and aSocket so everything works correctly
 */
static void init_udp_sock(otInstance *aInstance)
{
    otIp6Address ipv6Addr = get_ipv6_address(aInstance);

    // default socket address info
    aSockName.mAddress = ipv6Addr;
    aSockName.mPort = UDP_PORT;

    // default info for udp socket
    aSocket.mSockName = aSockName;
    aSocket.mPeerName.mPort = 0;
    aSocket.mHandler = udp_advert_rcv_cb;
    aSocket.mContext = NULL;
    aSocket.mHandle = NULL;

    // include the default udp port for aMessageInfo
    aMessageInfo.mPeerPort = UDP_PORT;
}

/**
 * Setup UDP for communication
 * and recieve messages in a callback
 */
static void udp_advert_rcv_cb(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    char buf[MSG_SIZE];
    uint16_t len;
    otInstance *aInstance = get_ot_instance();

    len = otMessageGetLength(aMessage);
    if (len > MSG_SIZE)
    {
        printf("Message too long!\n");
        return;
    }

    // copy into buffer
    otMessageRead(aMessage, 0, buf, len);
    buf[len] = '\0';

    // check if it matches the adertisement format
    if (strncmp(buf, ADVERT_MSG_FORMAT, strlen(ADVERT_MSG_FORMAT)) == 0)
    {
        uint64_t magicNumber;
        if (sscanf(buf + strlen(ADVERT_MSG_FORMAT), "%lu", (unsigned long *)&magicNumber) == 1)
        {
            // check for magic number
            if (magicNumber == magic_num)
            {
                printf("Received advertisement from a valid peer with magic number: %lu\n", (unsigned long)magicNumber);
                
                start_verif_process(aInstance, aMessageInfo);
            }
            else
            {
                printf("Received advertisement with an invalid magic number: %lu\n", (unsigned long)magicNumber);
            }
        }
        else
        {
            printf("Failed to extract magic number!\n");
        }
    }
    else
    {
        printf("Received message does not match expected format!\n");
    }
}

/**
 * UDP message recieving callback
 */
static void udp_msg_rcv_cb(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    char buffer[128];
    int length = otMessageRead(aMessage, otMessageGetOffset(aMessage), buffer, sizeof(buffer) - 1);

    if (length >= 0)
    {
        buffer[length] = '\0';
        printf("Received message: %s\n", buffer);
    }
    else
    {
        printf("Failed to read message\n");
    }
}

/**
 * UDP verification code recieving callback
 */
static void udp_verif_rcv_cb(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    char buf[MSG_SIZE];
    int receivedCode;

    // parse the message code
    uint16_t len = otMessageGetLength(aMessage);
    if (len >= MSG_SIZE) {
        printf("Received message too long!\n");
        return;
    }
    otMessageRead(aMessage, 0, buf, len);
    buf[len] = '\0';

    // check if received code is valid
    if (sscanf(buf, "Verification Code: %d", &receivedCode) == 1) {
        for (int i = 0; i < MAX_PEERS; i++) {
            if (peerSessions[i].active && otIp6IsAddressEqual(&peerSessions[i].peerAddr, &aMessageInfo->mPeerAddr)) {
                if (receivedCode == peerSessions[i].expected) {
                    printf("Peer successfully verified with code: %d\n", receivedCode);
                    peerSessions[i].active = false;

                    // save the peer by putting their address in NVS afterwards
                    esp_err_t err = nvs_set_blob(handle, "deviceA_addr", &peerSessions[i].peerAddr, sizeof(peerSessions[i].peerAddr));
                    printf("Peer name saved in NVS!");
                    if (err != ESP_OK) {
                        printf("Failed to store peer address in NVS\n");
                    }
                } else {
                    printf("Invalid verification response code: %d\n", receivedCode);
                }
                return;
            }
        }
        printf("Verification session not found for this peer!\n");
    } else {
        printf("Failed to parse verification response!\n");
    }
}

/**
 * Send a message!
 */
static void send_message(otInstance *aInstance, const char *aMessage, otIp6Address *destAddr)
{
    otError err;
    otMessage *oMessage;

    // init
    err = otUdpOpen(aInstance, &aSocket, udp_msg_rcv_cb, NULL);
    if (err != OT_ERROR_NONE)
    {
        printf("Failed to open UDP socket: %s\n", otThreadErrorToString(err));
        return;
    }

    // create new message
    oMessage = otUdpNewMessage(aInstance, NULL);
    if (oMessage == NULL)
    {
        printf("Failed to allocate new UDP message\n");
        return;
    }

    err = otMessageAppend(oMessage, aMessage, strlen(aMessage));
    if (err != OT_ERROR_NONE)
    {
        printf("Failed to append data to message: %s\n", otThreadErrorToString(err));
        otMessageFree(oMessage);
        return;
    }

    memset(&aMessageInfo, 0, sizeof(otMessageInfo));
    aMessageInfo.mPeerAddr = *destAddr;

    // send it!
    err = otUdpSend(aInstance, &aSocket, oMessage, &aMessageInfo);
    if (err != OT_ERROR_NONE)
    {
        printf("Failed to send UDP message: %s\n", otThreadErrorToString(err));
        otMessageFree(oMessage);
    }

    // close the socket
    otUdpClose(aInstance, &aSocket);
}


/**
 * Sends advertisement for clients to find
 */
static void send_thread_advertisement(otInstance *aInstance)
{
    otError err;
    otMessage *aMessage;
    char advertMsg[ADVERT_SIZE];

    // make the message
    snprintf(advertMsg, ADVERT_SIZE, "Thread device available, Magic Number: %llu", magic_num);
    memset(&aMessageInfo, 0, sizeof(aMessageInfo));

    // add info about the device
    const otIp6Address *localAddr = otThreadGetMeshLocalEid(aInstance);
    if (localAddr == NULL)
    {
        printf("Failed to get Mesh Local EID!\n");
        return;
    }

    aMessageInfo.mPeerAddr = *localAddr;

    // make a new message
    aMessage = otUdpNewMessage(aInstance, NULL);
    if (aMessage == NULL)
    {
        printf("Failed to allocate message!\n");
        return;
    }

    // append the message
    err = otMessageAppend(aMessage, advertMsg, strlen(advertMsg));
    if (err != OT_ERROR_NONE)
    {
        printf("Failed to append data to message: %s\n", otThreadErrorToString(err));
        otMessageFree(aMessage);
        return;
    }

    // send it!
    err = otUdpOpen(aInstance, &aSocket, NULL, NULL);
    if (err != OT_ERROR_NONE)
    {
        printf("Failed to open UDP socket: %s\n", otThreadErrorToString(err));
        otMessageFree(aMessage);
        return;
    }

    err = otUdpSend(aInstance, &aSocket, aMessage, &aMessageInfo);
    if (err != OT_ERROR_NONE)
    {
        printf("Failed to send advertisement: %s\n", otThreadErrorToString(err));
        otMessageFree(aMessage);
    }

    // close socket
    otUdpClose(aInstance, &aSocket);

    printf("Advertisement sent: %s\n", advertMsg);
}


/**
 * Scan for peers
 */
static void start_peer_scan(otInstance *aInstance)
{
    otError err;

    // create UDP socket
    aSocket.mHandler = udp_advert_rcv_cb;
    err = otUdpOpen(aInstance, &aSocket, udp_advert_rcv_cb, NULL);
    if (err != OT_ERROR_NONE)
    {
        printf("Failed to open UDP socket!\n");
        return;
    }

    // bind socket to port
    err = otUdpBind(aInstance, &aSocket, &aSockName, OT_NETIF_THREAD);
    if (err != OT_ERROR_NONE)
    {
        printf("Failed to bind UDP socket!\n");
        return;
    }

    printf("Listening for peer advertisements on port %u\n", UDP_PORT);
}

/**
 * Peer interaction starts as folows:
 * 1. Device A sends advertisements
 * 2. Device B requests a verification code from device A
 * 3. Device A 'generates' a code then sends it back to device B
 * 4. Device B increments the code then resends it back to device A to complete the handshake
 * 
 * From here we can confirm peer legitimacy, then start communication.
 * Potential to do: Implement a secure HMAC verification system as well.
 * 
 */

/**
 * Starts a peer interaction by exchanging a verification code,
 * which requires physical access to both devices.
 */
static void start_verif_process(otInstance *aInstance, const otMessageInfo *aMessageInfo)
{
    int code = generate_verif_code();
    int expected = code + 1;

    char aMessage[MSG_SIZE];
    snprintf(aMessage, MSG_SIZE, "Verification Code: %d", code);

    otMessage *oMessage = otUdpNewMessage(aInstance, NULL);
    if (oMessage == NULL) {
        printf("Failed to allocate message!\n");
        return;
    }
    otMessageAppend(oMessage, aMessage, strlen(aMessage));

    otUdpSend(aInstance, &aSocket, oMessage, aMessageInfo);

    printf("Sent verification code to peer: %d\n", code);

    for (int i = 0; i < MAX_PEERS; i++) {
        if (!peerSessions[i].active) {
            peerSessions[i].peerAddr = aMessageInfo->mPeerAddr;
            peerSessions[i].expected = expected;
            peerSessions[i].active = true;
            printf("Started verification session for peer!\n");

            // open nvs
            esp_err_t err = nvs_open("storage", NVS_READWRITE, &handle);
            if (err != ESP_OK) {
                printf("Failed to open NVS handle!\n");
                return;
            }

            // set the peer addr in nvs
            err = nvs_set_blob(handle, "deviceB_addr", &peerSessions[i].peerAddr, sizeof(peerSessions[i].peerAddr));
            if (err != ESP_OK) {
                printf("Failed to store peer address in NVS\n");
                nvs_close(handle);
                return;
            }

            // commit the changes
            err = nvs_commit(handle);
            if (err != ESP_OK) {
                printf("Failed to commit to NVS handle\n");
                nvs_close(handle);
                return;
            }

            // close after commiting
            nvs_close(handle);
            break;
        }
    }

    vTaskDelay(pdMS_TO_TICKS(TIMEOUT_MS));
}

/**
 * Runs the advertisement task
 */
static void advert_task(void *argc)
{
    otInstance *aInstance = (otInstance *)argc;
    uint32_t it = *(uint32_t *)argc;
    uint32_t cnt = 0;

    while (!stopAdvertTask)
    {
        send_thread_advertisement(aInstance);
        
        if (it != 0)
        {
            cnt++;
            if (cnt >= it)
            {
                break;
            }
        }

        // add delay to avoid flooding
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    printf("Advertisement task stopped.\n");
    vTaskDelete(NULL); // delete task when done
}

/**
 * Starts the advertisement task
 */
static void start_advert_task(otInstance *aInstance, uint32_t it)
{
    if (advertTaskHandle != NULL)
    {
        printf("Advertisement task is already running.\n");
        return;
    }

    stopAdvertTask = false;
    // starts the task
    xTaskCreate(advert_task, "Advertisement", 2048, (void *)&it, 5, &advertTaskHandle);
    printf("Advertisement task started.\n");
}

/**
 * Stops the advertisement task
 */
static void stop_advert_task(void)
{
    if (advertTaskHandle == NULL)
    {
        printf("No advertisement task is running.\n");
        return;
    }

    stopAdvertTask = true;
    printf("Signaled advertisement task to stop.\n");
}

/**
 * Gets the handshake and establishes a connection
 */
static void handshake_task(void *pvParameters)
{
    otInstance *aInstance = get_ot_instance();
    otMessage *aMessage;
    int verif_code, rcv_code;

    // create queue for the handshakes
    handshakeQueue = xQueueCreate(1, sizeof(int));
    if (handshakeQueue == NULL)
    {
        printf("Failed to create handshake queue\n");
        vTaskDelete(NULL);
        return;
    }

    // open socket and set the receive callback
    otUdpOpen(aInstance, &aSocket, udp_verif_rcv_cb, NULL);

    memset(&aMessageInfo, 0, sizeof(aMessageInfo));
    otUdpBind(aInstance, &aSocket, &aSockName, OT_NETIF_UNSPECIFIED);

    // step 1: generate and send verification code
    verif_code = generate_verif_code();
    printf("Generated verification code: %d\n", verif_code);

    aMessage = otUdpNewMessage(aInstance, NULL);
    char code_str[16];
    snprintf(code_str, sizeof(code_str), "%d", verif_code);
    otMessageAppend(aMessage, code_str, strlen(code_str));

    memset(&aMessageInfo, 0, sizeof(aMessageInfo));
    otIp6AddressFromString("FF03::1", &aMessageInfo.mPeerAddr);

    otUdpSend(aInstance, &aSocket, aMessage, &aMessageInfo);
    printf("Sent verification code\n");

    // step 2: wait for the incremented verification code in the queue
    while (true)
    {
        if (xQueueReceive(handshakeQueue, &rcv_code, portMAX_DELAY) == pdTRUE)
        {
            if (rcv_code == verif_code + 1)
            {
                printf("Handshake successful. Code verified: %d\n", rcv_code);
                break;
            }
            else
            {
                printf("Invalid verification code received: %d\n", rcv_code);
            }
        }
    }

    // cleanup
    otUdpClose(aInstance, &aSocket);
    vQueueDelete(handshakeQueue);
    vTaskDelete(NULL);
}

/**
 * Task that listens for oncoming messages
 */
static void listening_task(void *pvParameters)
{
    otInstance *aInstance = get_ot_instance();

    aSocket.mHandler = udp_msg_rcv_cb;
    otUdpOpen(aInstance, &aSocket, udp_msg_rcv_cb, NULL);
    otUdpBind(aInstance, &aSocket, &aSockName, OT_NETIF_UNSPECIFIED);

    printf("Listening for incoming messages...\n");
    while (true)
    {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    otUdpClose(aInstance, &aSocket);
    vTaskDelete(NULL);
}

/**
 * Task to send messages
 */
static void sending_task(void *pvParameters)
{
    otInstance *aInstance = get_ot_instance();
    char aMessage[128];

    while (true)
    {
        if (xQueueReceive(messageQueue, aMessage, portMAX_DELAY) == pdTRUE)
        {
            otMessage *oMessage = otUdpNewMessage(aInstance, NULL);
            otMessageAppend(oMessage, aMessage, strlen(aMessage));

            memset(&aMessageInfo, 0, sizeof(aMessageInfo));
            otIp6AddressFromString("FF03::1", &aMessageInfo.mPeerAddr);

            otUdpSend(aInstance, NULL, oMessage, &aMessageInfo);
            printf("Message sent: %s\n", aMessage);
        }
    }
}

/**
 * Controls the chat between the two devices
 */
static void start_chat(char *ipv6_addr)
{
    messageQueue = xQueueCreate(5, sizeof(char) * 128);

    xTaskCreate(handshake_task, "Handshake Task", 4096, NULL, 1, NULL);

    // wait for a handshake
    vTaskDelay(pdMS_TO_TICKS(5000));

    xTaskCreate(listening_task, "Listening Task", 4096, NULL, 1, NULL);
    xTaskCreate(sending_task, "Sending Task", 4096, NULL, 1, NULL);

    char peerAddress[40];
    strncpy(peerAddress, ipv6_addr, sizeof(peerAddress) - 1);
    peerAddress[sizeof(peerAddress) - 1] = '\0';

    while (true)
    {
        char cmd[32];
        printf("Enter command (send/end_chat): ");
        scanf("%31s", cmd);

        if (strcmp(cmd, "send") == 0)
        {
            char aMessage[128];
            printf("Enter message: ");
            scanf("%127s", aMessage);
            xQueueSend(messageQueue, aMessage, 0);
        }
        else if (strcmp(cmd, "end_chat") == 0)
        {
            printf("Ending chat...\n");
            vTaskDelete(NULL);
            break;
        }
    }
}

/**
 * Command which sends a message
 */
static otError send_message_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    otInstance *aInstance = get_ot_instance();

    // check if the correct number of arguments is passed
    if (aArgsLength != 2)
    {
        printf("Usage: send_message <message> <ipv6_addr>\n");
        return OT_ERROR_FAILED;
    }

    // conversions
    const char *aMessage = aArgs[0];
    otIp6Address destAddr;
    otError err = otIp6AddressFromString(aArgs[1], &destAddr);
    if (err != OT_ERROR_NONE)
    {
        printf("Invalid IPv6 address: %s\n", aArgs[1]);
        return OT_ERROR_FAILED;
    }

    // send the message
    send_message(aInstance, aMessage, &destAddr);

    printf("Sent message \"%s\" to destination %s\n", aMessage, aArgs[1]);
    return OT_ERROR_NONE;
}

/**
 * Command to stop advertisement task
 */
static otError stop_advert_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    stop_advert_task();
    return OT_ERROR_NONE;
}

/**
 * Command to send out HomeNet advertisements
 */
static otError send_advert_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    otInstance *aInstance = get_ot_instance();

    // number of iterations (0 is forever)
    uint32_t it = 0;

    if (aArgsLength == 1) {
        it = atoi(aArgs[0]);

        if (it <= 0) {
            printf("Invalid argument. Iterations must be a non-negative integer!\n");
            return OT_ERROR_FAILED;
        }
    }

    // special output depending on args
    if (it == 0) {
        printf("Running advertisement indefinitely...\n");
        start_advert_task(aInstance, it);
    } else {
        printf("Running advertisement for %lu it...\n", (unsigned long)it);
        start_advert_task(aInstance, it);
    }

    return OT_ERROR_NONE;
}

/**
 * Command to scan for a peer
 */
static otError start_scan_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    otInstance *aInstance = get_ot_instance();

    start_peer_scan(aInstance);

    return OT_ERROR_NONE;
}

/**
 * Command to send the verification code
 */
static otError send_verification_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    otInstance *aInstance = get_ot_instance();

    if (aArgsLength != 1)
    {
        printf("Usage: send_verification <peer_address>\n");
        return OT_ERROR_FAILED;
    }

    otIp6Address peerAddr;

    if (otIp6AddressFromString(aArgs[0], &peerAddr) != OT_ERROR_NONE)
    {
        printf("Invalid peer address format\n");
        return OT_ERROR_FAILED;
    }

    start_verif_process(aInstance, &aMessageInfo);

    return OT_ERROR_NONE;
}

static otError start_chat_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    if (aArgsLength != 1)
    {
        printf("Usage: start_chat <ipv6_addr>");
        return OT_ERROR_FAILED;
    }

    char *ipv6_addr = aArgs[0];

    start_chat(ipv6_addr);
    return OT_ERROR_NONE;
}


/**
 * Creates an instance of thread and joins the network
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
    (void)otLoggingSetLevel(CONFIG_LOG_DEFAULT_LEVEL);
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

    // generate a random ipv6 address
    random_ipv6_addr(aInstance);
    init_udp_sock(aInstance);

    // init UDP for messaging system
    aSocket.mHandler = udp_advert_rcv_cb;
    ESP_ERROR_CHECK(otUdpOpen(aInstance, &aSocket, udp_advert_rcv_cb, NULL));
    ESP_ERROR_CHECK(otUdpBind(aInstance, &aSocket, &aSockName, OT_NETIF_THREAD));

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
        {"start_chat", start_chat_cmd},
        {"send_message", send_message_cmd},
        {"send_advert", send_advert_cmd},
        {"stop_advert", stop_advert_cmd},
        {"start_scan", start_scan_cmd},
        {"send_verification", send_verification_cmd},
        {"turn_on_led", turn_on_led_cmd},
        {"turn_off_led", turn_off_led_cmd}
    };
    otCliSetUserCommands(kCommands, OT_ARRAY_LENGTH(kCommands), aInstance);
#endif
#if CONFIG_OPENTHREAD_AUTO_START
    otOperationalDatasetTlvs dataset;
    otError err = otDatasetGetActiveTlvs(esp_openthread_get_instance(), &dataset);
    ESP_ERROR_CHECK(esp_openthread_auto_start((err == OT_ERROR_NONE) ? &dataset : NULL));
#endif
    esp_openthread_launch_mainloop();

    // cleanup after mainloop stops
    esp_openthread_netif_glue_deinit();
    esp_netif_destroy(openthread_netif);
    esp_vfs_eventfd_unregister();
}
