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

#include "openthread/instance.h"
#include "openthread/thread.h"
#include "openthread/message.h"
#include "openthread/udp.h"

/**
 * Setup UDP for communication
 * and recieve messages in a callback
 */
void udp_rcv_cb(void *aCntxt, otMessage *aMsg, const otMessageInfo *aMsgInfo)
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
void send_udp_msg(otInstance *aInst, const char *msg, otIp6Address destAddr)
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
void register_thread_net(void)
{
    otInstance *inst = otInstanceInitSingle();

    // start interface
    otIp6SetEnabled(inst, true);
    otThreadSetEnabled(inst, true);

    // init UDP for messaging system
    otUdpSocket udpSock;
    otSockAddr sockAddr = {.mPort = 1234};
    otUdpOpen(inst, &udpSock, udp_rcv_cb, NULL);
    otUdpBind(inst, &udpSock, &sockAddr, OT_NETIF_THREAD);
}
