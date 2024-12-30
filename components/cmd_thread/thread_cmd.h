#pragma once

#define OT_ARRAY_LENGTH(aArray) (sizeof(aArray) / sizeof(aArray[0]))
#define EmptyMemory(pointer, size) memset((void *) pointer, 0, size)

#include "nvs_flash.h"
#include "nvs.h"
#include "openthread/ip6.h"
#include "openthread/udp.h"

void register_thread(void);
extern nvs_handle_t handle;

otError handle_error(otError error);
void handle_message_error(otMessage *aMessage, otError error);

otIp6Address *get_ipv6_address(void);

otUdpSocket init_ot_udp_socket(otUdpSocket aSocket, otSockAddr aSockName);
otSockAddr init_ot_sock_addr(otSockAddr aSockName);
otMessageInfo init_ot_message_info(otMessageInfo aMessageInfo, otSockAddr aSockName);
otUdpReceiver init_ot_udp_receiver(otUdpReceiver aReceiver);
otUdpSocket *ot_udp_socket_to_ptr(otUdpSocket aSocket, otUdpSocket *aSocketPtr);
otSockAddr *ot_sock_addr_to_ptr(otSockAddr aSockName, otSockAddr *aSockNamePtr);
otMessageInfo *ot_message_info_to_ptr(otMessageInfo aMessageInfo, otMessageInfo *aMessageInfoPtr);
otMessageInfo *const_ptr_ot_message_info_to_ptr(const otMessageInfo *aMessageInfo, otMessageInfo *aMessageInfoPtr);
otUdpReceiver *ot_udp_receiver_to_ptr(otUdpReceiver aReceiver, otUdpReceiver *aReceiverPtr);