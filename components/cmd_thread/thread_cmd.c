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

#include <stdio.h>

#include "esp_system.h"
#include "esp_mac.h"

#include "openthread/instance.h"
#include "openthread/thread.h"
#include "openthread/message.h"
#include "openthread/udp.h"

// aww
#define MAGIC_NUM 0x48616E616B6F
#define UDP_SOCK 602

#define MSG_SIZE 128
#define ADVERT_SIZE 64

#define ADVERT_MSG_FORMAT "Thread device available, Magic Number: "

static struct {
    struct arg_char *command;
    struct arg_end *end;
} thread_net_args;

static int random(int min, int max) { return min + esp_random() % (max - min + 1); }

/**
 * Generate a random verification code, 
 * the concept isn't random, rather psuedo-random.
 * I would NOT consider this secure.
 */
static int generate_verif_code(void)
{
    int randSize = random(5,10);
    int code[randSize] = {0, randSize};
    int verifCode = 0;
    bool success = false;

    // put as an array for the sake of multiple checks
    for (int i = 0; i < randSize; i++) 
    {
        code[i] = random(1,9);
    }

    // check beforehand
    if ((code[0] == 0) && (code[1] == randSize)) 
    {
        success = false;
    } else {
        success = true;
        code = {};
    }

    // append to an int then return if it works fine...
    if (success)
    {
        for (int j = 0; j < randSize; j++)
        {
            verifCode += code[j];
        }
    } else {
        printf("Failed to generate verification code. Please try again.\n");
        return;
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
static void udp_rcv_cb(void *aCntxt, otMessage *aMsg, const otMessageInfo *aMsgInfo)
{
    char buf[MSG_SIZE];
    uint16_t len;

    len = otMessageGetLength(aMessage);
    if (len > MAX_MSG_LEN)
    {
        printf("Message too long!\n");
        return;
    }

    // copy into buffer
    otMessageRead(aMessage, 0, buf, len);
    buf[len] = '\0';

    // Check if the message contains the expected advertisement format
    if (strncmp(buf, ADVERT_MSG_FORMAT, strlen(ADVERT_MSG_FORMAT)) == 0)
    {
        uint32_t magicNumber;
        if (sscanf(buf + strlen(ADVERT_MSG_FORMAT), "%u", &magicNumber) == 1)
        {
            // Check if the magic number matches the expected one for your project
            if (magicNumber == MAGIC_NUM)
            {
                printf("Received advertisement from a valid peer with magic number: %u\n", magicNumber);
                
                // to-do: handle this peer interaction
            }
            else
            {
                printf("Received advertisement with an invalid magic number: %u\n", magicNumber);
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
    // create message + info
    otError error;
    otMessageInfo msgInfo;
    otMessage *udpMsg = otUdpNewMessage(aInst, NULL);
    
    otUdpSocket udpSock;
    otSockAddr sockAddr = {.mPort = UDP_SOCK}; // to-do: make this publicly accessible or perhaps make a configuration file

    // find errors, and if not, send
    error = otMessageAppend(udpMsg, msg, strlen(msg));
    if (error == OT_ERROR_NONE)
    {
        memset(&msgInfo, 0, sizeof(msgInfo));
        msgInfo.mPeerAddr = destAddr;
        msgInfo.mPeerPort = UDP_SOCK; // put some BS info ig

        error = otUdpSend(aInst, &udpSock, udpMsg, &msgInfo);
    }

    // error handling...?
    if (error != OT_ERROR_NONE) {
        printf("Failed to send message: %s\n", otThreadErrorToString(error));
        otMessageFree(udpMsg);
    }
}

/**
 * Sends advertisement for clients to find
 */
static void send_thread_advertisement(otInstance *aInstance)
{
    otMessage *msg;
    otMessageInfo msgInfo;
    char advertMsg[ADVERT_SIZE];

    // create the message
    snprintf(advertMsg, ADVERT_SIZE, "Thread device available, Magic Number: %u", MAGIC_NUM);
    memset(&msgInfo, 0, sizeof(msgInfo));
    
    msgInfo.mPeerAddr = *otThreadGetMeshLocalEid(aInstance);
    msg = otUdpNewMessage(aInstance, NULL);

    // another check to make sure this works
    if (msg == NULL)
    {
        printf("Failed to allocate message!\n");
        return;
    }

    // append advert and send it!
    otMessageAppend(msg, advertMsg, strlen(advertMsg));
    otUdpSend(aInstance, msg, &msgInfo);

    printf("Advertisement sent: %s\n", advertMsg);
}

/**
 * Scan for peers
 */
static void start_peer_scan(otInstance *aInstance)
{
    otUdpSocket udpSocket;
    otError error;

    // create UDP socket
    error = otUdpOpen(aInstance, &udpSocket, udp_receive_callback, NULL);
    if (error != OT_ERROR_NONE)
    {
        printf("Failed to open UDP socket!\n");
        return;
    }

    // bind socket to port
    error = otUdpBind(aInstance, &udpSocket, UDP_SOCK);
    if (error != OT_ERROR_NONE)
    {
        printf("Failed to bind UDP socket!\n");
        return;
    }

    printf("Listening for peer advertisements on port %u\n", UDP_SOCK);
}

/**
 * Creates an instance of thread and joins the network
 */
static void register_thread_net(void)
{
    otInstance *inst = otInstanceInitSingle();

    // start interface
    otIp6SetEnabled(inst, true);
    otThreadSetEnabled(inst, true);
    random_ipv6_addr(inst);

    // init UDP for messaging system
    otUdpSocket udpSock;
    otSockAddr sockAddr = {.mPort = UDP_SOCK};
    otUdpOpen(inst, &udpSock, udp_rcv_cb, NULL);
    otUdpBind(inst, &udpSock, &sockAddr, OT_NETIF_THREAD);
}
