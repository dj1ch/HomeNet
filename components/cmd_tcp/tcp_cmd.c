
#include "tcp_cmd.h"
#include "thread_cmd.h"
#include "openthread/tcp.h"
#include "openthread/tcp_ext.h"
#include "openthread/ip6.h"
#include "openthread/udp.h"
#include "openthread/error.h"
#include "esp_openthread.h"
#include <stdio.h>

#define MSG_SIZE 128

/**
 * Important definitions
 */
#define TCP_PORT 1602
#define NETWORK_NAME "homenet"
#define NETWORK_CHANNEL 15
#define TAG "homenet"

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
    char payload[MSG_SIZE];
    size_t bytesToRead = (aBytesAvailable < MSG_SIZE) ? aBytesAvailable : MSG_SIZE;

    otTcpReceiveByReference(aEndpoint, NULL);
    otTcpReceiveContiguify(aEndpoint);
    otTcpCommitReceive(aEndpoint, bytesToRead, 0);

    emptyMemory(payload, MSG_SIZE);
    otTcpReceive(aEndpoint, payload, bytesToRead);

    char output[MSG_SIZE];
    snprintf(output, MSG_SIZE, "Received Message: %s", payload);
    otLogNotePlat(output);
}

/**
 * Connection is closed
 */
void tcp_dsc_cb(otTcpEndpoint *aEndpoint, otTcpDisconnectedReason aReason)
{
    otLogNotePlat("TCP connection disconnected");
    otTcpEndpointDeinitialize(aEndpoint);
}

/**
 * Initialize and bind the TCP endpoint
 */
void init_tcp_endpoint(otInstance *aInstance, otTcpEndpoint aEndpoint)
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
        otLogWarnPlat("Failed to bind TCP endpoint");
        return;
    }
}

otTcpEndpoint init_ot_tcp_endpoint_ptr(otTcpEndpoint *aEndpoint, char *message)
{
    aEndpoint->mNext = nullptr;
    aEndpoint->mLength = strlen(message);
    aEndpoint->mData = reinterpret_cast<const uint8_t *>(message);

    return aEndpoint;
}

otLinkedBuffer init_ot_linked_buffer(otLinkedBuffer aBuffer, char *message)
{
    aBuffer.mNext = nullptr;
    aBuffer.mLength = strlen(message);
    aBuffer.mData = reinterpret_cast<const uint8_t *>(message);

    return aBuffer;
}

otError send_message(char *message)
{
    otTcpEndpoint *aEndpoint = init_ot_tcp_endpoint_ptr(aEndpoint, message );
    otLinkedBuffer aBuffer = init_ot_linked_buffer(aBuffer, message)

    otError error = otTcpSendByReference(aEndpoint, &aBuffer, 0);
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

void handle_accept_done(otTcpEndpoint *aEndpoint, otTcpEndpoint *aChildEndpoint, otError aError)
{
    if (aError == OT_ERROR_NONE)
    {
        ESP_LOGI(TAG, "Accepted connection from client");
    }
    else
    {
        ESP_LOGE(TAG, "Error in accepting connection: %s", otThreadErrorToString(aError));
    }
}

void handle_receive_ready(otTcpEndpoint *aEndpoint, size_t aBytesAvailable, otError aError)
{
    if (aError == OT_ERROR_NONE)
    {
        uint8_t buffer[128];
        size_t bytesRead = otTcpReceive(aEndpoint, buffer, sizeof(buffer), NULL);
        if (bytesRead > 0)
        {
            ESP_LOGI(TAG, "Received %zu bytes: %.*s", bytesRead, bytesRead, buffer);
        }
    }
    else
    {
        ESP_LOGE(TAG, "Error in receiving data: %s", otThreadErrorToString(aError));
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

void register_tcp(void)
{
    otInstance *aInstance = esp_openthread_get_instance();

    // create TCP endpoint
    otTcpEndpoint *aEndpoint = init_ot_tcp_endpoint_ptr(aEndpoint);

    otTcpEndpointInitializeArgs aArgs = {
        .mEstablishedCallback = tcp_est_cb,
        .mReceiveAvailableCallback = tcp_msg_rcv_cb,
        .mDisconnectedCallback = tcp_dsc_cb,
        .mContext = NULL,
    };

    // register callbacks for TCP events
    otTcpEndpointInitialize(aInstance, aEndpoint, &aArgs);

    otTcpEndpointSetCallbacks(aEndpoint, &(otTcpEndpointCallbacks){
        .mAcceptDone = handle_accept_done,
        .mConnectDone = handle_connect_done,
        .mReceiveReady = handle_receive_ready,
        .mSendDone = handle_send_done,
        .mDisconnectDone = handle_disconnect_done,
    });

    // bind the endpoint to a port
    otSockAddr aSockName = init_ot_sock_addr(aSockName);
    otError error = otTcpBind(aEndpoint, &aSockName);
    if (error != OT_ERROR_NONE)
    {
        ESP_LOGE(TAG, "Failed to bind TCP endpoint: %s", otThreadErrorToString(error));
        return;
    }

    // start listening for incoming connections
    error = otTcpListen(aEndpoint, NULL);
    if (error != OT_ERROR_NONE)
    {
        ESP_LOGE(TAG, "Failed to listen on TCP endpoint: %s", otThreadErrorToString(error));
        return;
    }
}
