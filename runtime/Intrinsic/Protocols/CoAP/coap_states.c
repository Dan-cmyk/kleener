#include "klee/Protocols/coap/coap_states.h"
#include "klee/Protocols/coap/coap_messages.h"
#include "klee/Support/Protocols/helper.h"
#include "klee/klee.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

void CoAP_server_state_machine(MESSAGE *message, MESSAGE *shadow_message,
                               size_t counter, int8_t *server_current_state) {
  MESSAGE *shadow_msg = shadow_message + counter;

  if (shadow_msg->type == CONFIRMABLE_MSG) {
    *server_current_state = CONF_RCVD;
    printf("\n[Server-model-log] Confirmable message has been parsed\n");

  } else if (shadow_msg->type == NON_CONFIRMABLE_MSG) {
    *server_current_state = NON_CONF_RCVD;
    printf("\n[Server-model-log] Non-Confirmable message has been parsed\n");

  } else if (shadow_msg->type == ACKNOWLEDGEMENT_MSG) {
    printf("\n[Server-model-log] Acknowledgement has been parsed\n");

  } else if (shadow_msg->type == RESET_MSG) {
    *server_current_state = RESET_RCVD;
    printf("\n[Server-model-log] Reset message has been parsed\n");
  }
}

void CoAP_client_state_machine(MESSAGE *message, MESSAGE *shadow_message,
                               size_t counter, int8_t *client_current_state) {
  MESSAGE *shadow_msg = shadow_message + counter;

  if (shadow_msg->type == CONFIRMABLE_MSG) {
    *client_current_state = CONF_RCVD;
    printf("\n[Client-model-log] Confirmable message has been parsed\n");

  } else if (shadow_msg->type == NON_CONFIRMABLE_MSG) {
    *client_current_state = NON_CONF_RCVD;
    printf("\n[Client-model-log] Non-Confirmable message has been parsed\n");

  } else if (shadow_msg->type == ACKNOWLEDGEMENT_MSG) {
    printf("\n[Client-model-log] Acknowledgement has been parsed\n");

  } else if (shadow_msg->type == RESET_MSG) {
    *client_current_state = RESET_RCVD;
    printf("\n[Client-model-log] Reset message has been parsed\n");
  }
}