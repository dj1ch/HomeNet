/**
 * Developer Note:
 * This is an esp-idf component designed to help assist
 * in the creation of a small P2P network between a multitude
 * of clients. Messages are sent over UDP with openthread
 * and possibly other affiliated tools.
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

static struct {
    struct arg_char *command;
    struct arg_end *end;
} thread_net_args;

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
    char msg[128]; // to-do: allow configurable message size

    // process message
    int len = otMessageRead(aMsg, otMessageGetOffset(aMsg), msg, sizeof(msg) -1);
    msg[len] = '\0';

    // show message
    printf("Recieved message: %s\n", msg);
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
    otSockAddr sockAddr = {.mPort = 1234}; // to-do: make this publicly accessible or perhaps make a configuration file

    // find errors, and if not, send
    error = otMessageAppend(udpMsg, msg, strlen(msg));
    if (error == OT_ERROR_NONE)
    {
        memset(&msgInfo, 0, sizeof(msgInfo));
        msgInfo.mPeerAddr = destAddr;
        msgInfo.mPeerPort = 1234; // put some BS info ig

        error = otUdpSend(aInst, &udpSock, udpMsg, &msgInfo);
    }

    // error handling...?
    if (error != OT_ERROR_NONE) {
        printf("Failed to send message: %s\n", otThreadErrorToString(error));
        otMessageFree(udpMsg);
    }
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
    otSockAddr sockAddr = {.mPort = 1234};
    otUdpOpen(inst, &udpSock, udp_rcv_cb, NULL);
    otUdpBind(inst, &udpSock, &sockAddr, OT_NETIF_THREAD);
}
