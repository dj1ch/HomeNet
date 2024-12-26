
#include "tcp_cmd.h"
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
#define TCP_PORT 1602
#define NETWORK_NAME "homenet"
#define NETWORK_CHANNEL 15
#define TAG "homenet"

otError send_message_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[]);

/**
 * Connection is established
 */
void tcp_est_cb(otTcpEndpoint *aEndpoint)
{
    otLogNotePlat("TCP connection established");
}

/**
 * UDP message recieving callback
 */
void tcp_msg_rcv_cb(otTcpEndpoint *aEndpoint, size_t aBytesAvailable, bool aEndOfStream, size_t aBytesRemaining)
{
    const otLinkedBuffer *aBuffer;
    otTcpReceiveByReference(aEndpoint, &aBuffer);
    otTcpReceiveContiguify(aEndpoint);

    char payload[MSG_SIZE] = {0};
    memcpy(payload, aBuffer->mData, aBytesAvailable);
    otTcpCommitReceive(aEndpoint, aBytesAvailable, 0);

    ESP_LOGI(TAG, "Received Message: %s", payload);
}

/**
 * Connection is closed
 */
void tcp_dsc_cb(otTcpEndpoint *aEndpoint, otTcpDisconnectedReason aReason)
{
    otLogNotePlat("TCP connection disconnected");
    otTcpEndpointDeinitialize(aEndpoint);
}

void handle_accept_done(otTcpListener *aListener, otTcpEndpoint *aEndpoint, const otSockAddr *aPeer)
{
    char addr; 
    otIp6AddressToString((const otIp6Address *)&aPeer->mAddress, &addr, OT_IP6_ADDRESS_STRING_SIZE);
    uint16_t port = aPeer->mPort;

    if (aEndpoint != NULL)
    {
        printf("Accepted connection from peer: %s:%d", &addr, port);
    }
    else
    {
        printf("Error in accepting connection.");
    }
}

otTcpIncomingConnectionAction handle_accept_ready(otTcpListener *aListener, const otSockAddr *aPeer, otTcpEndpoint **aAcceptInto)
{
    char addr; 
    otIp6AddressToString((const otIp6Address *)&aPeer->mAddress, &addr, OT_IP6_ADDRESS_STRING_SIZE);
    uint16_t port = aPeer->mPort;

    ESP_LOGI(TAG, "Incoming connection request from %s:%d", &addr, port);

    if (*aAcceptInto != NULL)
    {
        return OT_TCP_INCOMING_CONNECTION_ACTION_ACCEPT;
    }
    else
    {
        ESP_LOGE(TAG, "Failed to allocate TCP endpoint for incoming connection");
        return OT_TCP_INCOMING_CONNECTION_ACTION_DEFER;
    }
}

void handle_send_done(otTcpEndpoint *aEndpoint, otLinkedBuffer *aData)
{
    ESP_LOGI(TAG, "Data sent successfully");
}

void handle_disconnect_done(otTcpEndpoint *aEndpoint, otError aError)
{
    if (aError == OT_ERROR_NONE)
    {
        ESP_LOGI(TAG, "Connection closed successfully");
    }
    else
    {
        ESP_LOGE(TAG, "Error in disconnecting: %s", otThreadErrorToString(aError));
    }
}

/**
 * Initialize and bind the TCP endpoint
 */
otTcpEndpoint init_ot_tcp_endpoint(otInstance *aInstance, otTcpEndpoint aEndpoint)
{
    otTcpEndpointInitializeArgs endpointArgs = {
        .mEstablishedCallback = tcp_est_cb,
        .mReceiveAvailableCallback = tcp_msg_rcv_cb,
        .mDisconnectedCallback = tcp_dsc_cb,
        .mContext = NULL,
    };

    otTcpEndpointInitialize(aInstance, &aEndpoint, &endpointArgs);

    otSockAddr aSockName = init_ot_sock_addr(aSockName);

    if (otTcpBind(&aEndpoint, &aSockName) != OT_ERROR_NONE)
    {
        ESP_LOGE(TAG, "Failed to bind TCP endpoint");
    }

    return aEndpoint;
}


otLinkedBuffer init_ot_linked_buffer(otLinkedBuffer aBuffer, char *message)
{
    aBuffer.mNext = NULL;
    aBuffer.mLength = strlen(message);
    aBuffer.mData = (const uint8_t *)message;

    return aBuffer;
}

otTcpListener init_ot_tcp_listener(otTcpListener aListener)
{
    otTcpListenerInitializeArgs listenerArgs = {
        .mAcceptReadyCallback = handle_accept_ready,
        .mAcceptDoneCallback = handle_accept_done,
        .mContext = NULL,
    };

    otTcpListenerInitialize(esp_openthread_get_instance(), &aListener, &listenerArgs);

    return aListener;
}

otError send_message(char *message)
{
    otInstance *aInstance = esp_openthread_get_instance();

    otTcpEndpoint aEndpoint = init_ot_tcp_endpoint(aInstance, aEndpoint);
    otLinkedBuffer aBuffer = init_ot_linked_buffer(aBuffer, message);

    otError error = otTcpSendByReference(&aEndpoint, &aBuffer, 0);
    if (error != OT_ERROR_NONE)
    {
        printf("Failed to send message: %d\n", error);
        return error;
    }

    return OT_ERROR_NONE;
}

otError send_message_cmd(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    if (aArgsLength != 2)
    {
        printf("Usage: send_message <message>");
    }

    char *message = aArgs[1];

    otError err = send_message(message);

    return err;
}

void register_tcp(void)
{
    otInstance *aInstance = esp_openthread_get_instance();

    // create TCP endpoint
    otTcpEndpoint aEndpoint = init_ot_tcp_endpoint(aInstance, aEndpoint);
    otTcpListener aListener = init_ot_tcp_listener(aListener);

    otTcpEndpointInitializeArgs aArgs = {
        .mEstablishedCallback = tcp_est_cb,
        .mReceiveAvailableCallback = tcp_msg_rcv_cb,
        .mDisconnectedCallback = tcp_dsc_cb,
        .mContext = NULL,
    };

    // register callbacks for TCP events
    otTcpEndpointInitialize(aInstance, &aEndpoint, &aArgs);

    // bind the endpoint to a port
    otSockAddr aSockName = init_ot_sock_addr(aSockName);
    otError error = otTcpBind(&aEndpoint, &aSockName);
    if (error != OT_ERROR_NONE)
    {
        ESP_LOGE(TAG, "Failed to bind TCP endpoint: %s", otThreadErrorToString(error));
        return;
    }

    // start listening for incoming connections
    error = otTcpListen(&aListener, &aSockName);
    if (error != OT_ERROR_NONE)
    {
        ESP_LOGE(TAG, "Failed to listen on TCP endpoint: %s", otThreadErrorToString(error));
        return;
    }
}
