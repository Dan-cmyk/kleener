#ifndef SYM_STATE
#define SYM_STATE

#include "klee/Protocols/coap/coap_messages.h"
#include <stdbool.h>
#include <stdint.h>

#define INIT -1

#define CONF_RCVD 0
#define NON_CONF_RCVD 1
#define ACK_RCVD 2
#define RESET_RCVD 3

int state_to_message_type(int state);
void CoAP_server_state_machine(MESSAGE *msg, MESSAGE *shadow_msg,
                               size_t counter, int8_t *server_current_state);
void CoAP_client_state_machine(MESSAGE *msg, MESSAGE *shadow_msg,
                               size_t counter, int8_t *client_current_state);

#endif