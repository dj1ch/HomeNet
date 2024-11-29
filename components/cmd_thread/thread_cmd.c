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

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "esp_system.h"
#include "esp_random.h"
#include "esp_mac.h"

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include "openthread/instance.h"
#include "openthread/thread.h"
#include "openthread/message.h"
#include "openthread/udp.h"

#include "esp_console.h"
#include "argtable3/argtable3.h"
#include "esp_log.h"

#include <openthread/instance.h>

#include "nvs_flash.h"
#include "nvs.h"

// aww
uint64_t magic_num = 0x48616E616B6F;

#define MSG_SIZE 128
#define ADVERT_SIZE 64

#define ADVERT_MSG_FORMAT "Thread device available, Magic Number: "

#define TIMEOUT_MS 10000
#define UDP_PORT 602
#define VERIF_PORT 603

#define MAX_PEERS 10

static int random_range(int min, int max);
static otInstance *get_ot_instance(void);
static int generate_verif_code(void);
static void random_ipv6_addr(otInstance *aInst);
static void udp_advert_rcv_cb(void *aContext, otMessage *aMsg, const otMessageInfo *aMsgInfo);
static void send_udp_msg(otInstance *aInst, const char *msg, otIp6Address destAddr);
static void send_thread_advertisement(otInstance *aInst);
static void start_peer_scan(otInstance *aInst);
static void start_verif_process(otInstance *aInst, const otMessageInfo *aMsgInfo);
static void advert_task(void *argc);
static void start_advert_task(otInstance *aInst, uint32_t iterations);
static void stop_advert_task(void);
static esp_err_t stop_advert_cmd(int argc, char **argv);
static esp_err_t send_advert_cmd(int argc, char **argv);
static esp_err_t start_scan_cmd(int argc, char **argv);
static esp_err_t send_verification_cmd(int argc, char **argv);
static void rcv_verif_code(otMessage *aMsg, otMessageInfo *aMsgInfo);
void register_thread(void);

typedef struct {
    otIp6Address peerAddr;
    int expected;
    bool active;     
} peer_verif_session;

static peer_verif_session peerSessions[MAX_PEERS] = {0};

/**
 * OpenThread instance for singleton pattern
 */
static otInstance *otInstancePtr = NULL;

// advertisement task handle
static TaskHandle_t advertTaskHandle = NULL;

// stop flag for advertisement
static bool stopAdvertTask = false;

static int random_range(int min, int max) { return min + esp_random() % (max - min + 1); }

/**
 * Finds the instance of OpenThread
 * within the code and returns it.
 */
static otInstance *get_ot_instance(void)
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
static void random_ipv6_addr(otInstance *aInst)
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
    otIp6AddUnicastAddress(aInst, &addr);

    char addrStr[40];
    otIp6AddressToString(&addr.mAddress, addrStr, sizeof(addrStr));
    printf("Generated IPv6 Address: %s\n", addrStr);
}

/**
 * Setup UDP for communication
 * and recieve messages in a callback
 */
static void udp_advert_rcv_cb(void *aContext, otMessage *aMsg, const otMessageInfo *aMsgInfo)
{
    char buf[MSG_SIZE];
    uint16_t len;
    otInstance *aInst = get_ot_instance();

    len = otMessageGetLength(aMsg);
    if (len > MSG_SIZE)
    {
        printf("Message too long!\n");
        return;
    }

    // copy into buffer
    otMessageRead(aMsg, 0, buf, len);
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
                
                // to-do: handle this peer interaction
                start_verif_process(aInst, aMsgInfo);
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
 * Send a message!
 */
static void send_udp_msg(otInstance *aInst, const char *msg, otIp6Address destAddr)
{
    otError error;
    otMessageInfo msgInfo;
    otMessage *udpMsg;
    otUdpSocket udpSock;

    // init
    memset(&udpSock, 0, sizeof(otUdpSocket));
    error = otUdpOpen(aInst, &udpSock, NULL, NULL);
    if (error != OT_ERROR_NONE)
    {
        printf("Failed to open UDP socket: %s\n", otThreadErrorToString(error));
        return;
    }

    // create new message
    udpMsg = otUdpNewMessage(aInst, NULL);
    if (udpMsg == NULL)
    {
        printf("Failed to allocate new UDP message\n");
        return;
    }

    // append
    error = otMessageAppend(udpMsg, msg, strlen(msg));
    if (error != OT_ERROR_NONE)
    {
        printf("Failed to append data to message: %s\n", otThreadErrorToString(error));
        otMessageFree(udpMsg);
        return;
    }

    // set up info
    memset(&msgInfo, 0, sizeof(otMessageInfo));
    msgInfo.mPeerAddr = destAddr;
    msgInfo.mPeerPort = UDP_PORT;

    // send it!
    error = otUdpSend(aInst, &udpSock, udpMsg, &msgInfo);
    if (error != OT_ERROR_NONE)
    {
        printf("Failed to send UDP message: %s\n", otThreadErrorToString(error));
        otMessageFree(udpMsg);
    }

    // close the socket
    otUdpClose(aInst, &udpSock);
}


/**
 * Sends advertisement for clients to find
 */
static void send_thread_advertisement(otInstance *aInst)
{
    otError error;
    otMessage *msg;
    otMessageInfo msgInfo;
    char advertMsg[ADVERT_SIZE];

    // make the message
    snprintf(advertMsg, ADVERT_SIZE, "Thread device available, Magic Number: %llu", magic_num);
    memset(&msgInfo, 0, sizeof(msgInfo));

    // add info about the device
    const otIp6Address *localAddr = otThreadGetMeshLocalEid(aInst);
    if (localAddr == NULL)
    {
        printf("Failed to get Mesh Local EID!\n");
        return;
    }

    msgInfo.mPeerAddr = *localAddr;
    msgInfo.mPeerPort = UDP_PORT;

    // make a new message
    msg = otUdpNewMessage(aInst, NULL);
    if (msg == NULL)
    {
        printf("Failed to allocate message!\n");
        return;
    }

    // append the message
    error = otMessageAppend(msg, advertMsg, strlen(advertMsg));
    if (error != OT_ERROR_NONE)
    {
        printf("Failed to append data to message: %s\n", otThreadErrorToString(error));
        otMessageFree(msg);
        return;
    }

    // send it!
    otUdpSocket udpSock;
    error = otUdpOpen(aInst, &udpSock, NULL, NULL);
    if (error != OT_ERROR_NONE)
    {
        printf("Failed to open UDP socket: %s\n", otThreadErrorToString(error));
        otMessageFree(msg);
        return;
    }

    error = otUdpSend(aInst, &udpSock, msg, &msgInfo);
    if (error != OT_ERROR_NONE)
    {
        printf("Failed to send advertisement: %s\n", otThreadErrorToString(error));
        otMessageFree(msg);
    }

    // close socket
    otUdpClose(aInst, &udpSock);

    printf("Advertisement sent: %s\n", advertMsg);
}


/**
 * Scan for peers
 */
static void start_peer_scan(otInstance *aInst)
{
    otUdpSocket udpSocket;
    otError error;
    otSockAddr sockAddr = { .mPort = UDP_PORT };

    // create UDP socket
    error = otUdpOpen(aInst, &udpSocket, udp_advert_rcv_cb, NULL);
    if (error != OT_ERROR_NONE)
    {
        printf("Failed to open UDP socket!\n");
        return;
    }

    // bind socket to port
    error = otUdpBind(aInst, &udpSocket, &sockAddr, OT_NETIF_THREAD);
    if (error != OT_ERROR_NONE)
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
static void start_verif_process(otInstance *aInst, const otMessageInfo *aMsgInfo)
{
    int code = generate_verif_code();
    int expected = code + 1;
    nvs_handle_t handle;

    otUdpSocket udpSocket = {};

    char msg[MSG_SIZE];
    snprintf(msg, MSG_SIZE, "Verification Code: %d", code);

    otMessage *oMsg = otUdpNewMessage(aInst, NULL);
    if (oMsg == NULL) {
        printf("Failed to allocate message!\n");
        return;
    }
    otMessageAppend(oMsg, msg, strlen(msg));

    otMessageInfo respInfo = *aMsgInfo;
    respInfo.mPeerPort = VERIF_PORT;

    otUdpSend(aInst, &udpSocket, oMsg, &respInfo);

    printf("Sent verification code to peer: %d\n", code);

    for (int i = 0; i < MAX_PEERS; i++) {
        if (!peerSessions[i].active) {
            peerSessions[i].peerAddr = aMsgInfo->mPeerAddr;
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
    otInstance *aInst = (otInstance *)argc;
    uint32_t iterations = *(uint32_t *)argc;
    uint32_t counter = 0;

    while (!stopAdvertTask)
    {
        send_thread_advertisement(aInst);
        
        if (iterations != 0)
        {
            counter++;
            if (counter >= iterations)
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
static void start_advert_task(otInstance *aInst, uint32_t iterations)
{
    if (advertTaskHandle != NULL)
    {
        printf("Advertisement task is already running.\n");
        return;
    }

    stopAdvertTask = false;
    // starts the task
    xTaskCreate(advert_task, "Advertisement", 2048, (void *)&iterations, 5, &advertTaskHandle);
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
 * Command which stops advertisement task
 */
static int stop_advert_cmd(int argc, char **argv)
{
    stop_advert_task();
    return 0;
}

/**
 * Command which sends out the HomeNet advertisements
 */
static int send_advert_cmd(int argc, char **argv) {
    otInstance *aInst = get_ot_instance();
    
    // number of iterations (0 is forever)
    uint32_t iterations = 0;

    // check for args
    if (argc == 2) {
        iterations = atoi(argv[1]);

        if (iterations <= 0) {
            printf("Invalid argument. Iterations must be a non-negative integer!\n");
            return -1;
        }
    }

    // special output depending on args
    if (iterations == 0) {
        printf("Running advertisement indefinitely...\n");
        start_advert_task(aInst, iterations);
    } else {
        printf("Running advertisement for %lu iterations...\n", (unsigned long)iterations);
        start_advert_task(aInst, iterations);
    }

    return 0;
}


/**
 * Command which scans for a peer
 */
static int start_scan_cmd(int argc, char **argv) {
    otInstance *aInst = get_ot_instance();

    start_peer_scan(aInst);

    return 0;
}

/**
 * Command to send the verification code
 */
static int send_verification_cmd(int argc, char **argv) {
    otInstance *aInst = get_ot_instance();

    if (argc != 2) {
        printf("Usage: send_verification <peer_address>\n");
        return -1;
    }

    otIp6Address peerAddr;

    // convert the string to the correct structure
    if (otIp6AddressFromString(argv[1], &peerAddr) != OT_ERROR_NONE) {
        printf("Invalid peer address format\n");
        return -1;
    }

    otMessageInfo msgInfo = {
        .mPeerAddr = peerAddr,
        .mPeerPort = VERIF_PORT
    };

    start_verif_process(aInst, &msgInfo);

    return 0;
}

/**
 * Finish last steps of verification
 */
static void rcv_verif_code(otMessage *aMsg, otMessageInfo *aMsgInfo)
{
    char buf[MSG_SIZE];
    int receivedCode;
    nvs_handle_t handle;

    // parse the message code
    uint16_t len = otMessageGetLength(aMsg);
    if (len >= MSG_SIZE) {
        printf("Received message too long!\n");
        return;
    }
    otMessageRead(aMsg, 0, buf, len);
    buf[len] = '\0';

    // check if received code is valid
    if (sscanf(buf, "Verification Code: %d", &receivedCode) == 1) {
        for (int i = 0; i < MAX_PEERS; i++) {
            if (peerSessions[i].active && otIp6IsAddressEqual(&peerSessions[i].peerAddr, &aMsgInfo->mPeerAddr)) {
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
 * Creates an instance of thread and joins the network
 */
void register_thread(void)
{
    // register commands
    const esp_console_cmd_t send_advert_cmd_struct = {
        .command = "send_advert",
        .help = "Send a thread advertisement",
        .func = send_advert_cmd,
    };

    const esp_console_cmd_t stop_advert_cmd_struct = {
        .command = "stop_advert",
        .help = "Stop thread advertisement",
        .func = stop_advert_cmd,
    };

    const esp_console_cmd_t start_scan_cmd_struct = {
        .command = "start_scan",
        .help = "Start scanning for peers",
        .func = start_scan_cmd,
    };

    const esp_console_cmd_t send_verification_cmd_struct = {
        .command = "send_verification",
        .help = "Send verification code to peer",
        .func = send_verification_cmd,
    };
    
    ESP_ERROR_CHECK(esp_console_cmd_register(&send_advert_cmd_struct));
    ESP_ERROR_CHECK(esp_console_cmd_register(&stop_advert_cmd_struct));
    ESP_ERROR_CHECK(esp_console_cmd_register(&start_scan_cmd_struct));
    ESP_ERROR_CHECK(esp_console_cmd_register(&send_verification_cmd_struct));

    // create an instance
    otInstance *inst = otInstanceInitSingle();

    // start interface
    otIp6SetEnabled(inst, true);
    otThreadSetEnabled(inst, true);
    random_ipv6_addr(inst);

    // init UDP for messaging system
    otUdpSocket udpSock;
    otSockAddr sockAddr = {.mPort = UDP_PORT};
    otUdpOpen(inst, &udpSock, udp_advert_rcv_cb, NULL);
    otUdpBind(inst, &udpSock, &sockAddr, OT_NETIF_THREAD);
}
