#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/klee.h"

coap_monitor_handle set_coap_monitor_handle(int experiment,
                                            SIDE side_to_check) {
  static const struct entry {
    coap_monitor_handle server_mon;
    coap_monitor_handle client_mon;
  } table[] = {// TODO: add functions instead of null
               [version_requirement] = {is_version_valid_server, NULL},
               [type_requirement] = {NULL, NULL},
               [message_id_requirement] = {NULL, NULL},
               [id_unique] = {NULL, NULL},
               [token_requirement] = {NULL, NULL},
               [token_unique] = {NULL, NULL},
               [token_length_requirement] = {NULL, NULL},
               [token_length_correlation] = {NULL, NULL},
               [payload_marker_requirement] = {NULL, NULL},
               [empty_message_requirement] = {NULL, NULL},
               [code_requirement] = {NULL, NULL}};

  const struct entry *entry = &table[experiment];

  if (side_to_check == CLIENT)
    return entry->client_mon;
  else if (side_to_check == SERVER)
    return entry->server_mon;
  else
    return NULL;
}

int determine_coap_state_to_check(allowed_coap_states as, SIDE side_to_check) {
  if (side_to_check == NONE) {
    return -1;
  } else {
    int state_to_check;
    kleener_make_symbolic(&state_to_check, sizeof(state_to_check),
                          "state_to_check");
    bool condition = false;
    if (side_to_check == SERVER) {
      if (as & AS_CONF_RCVD)
        condition |= (state_to_check == CONF_RCVD);
      if (as & AS_NON_CONF_RCVD)
        condition |= (state_to_check == NON_CONF_RCVD);
      if (as & AS_ACK_RCVD)
        condition |= (state_to_check == ACK_RCVD);
      if (as & AS_RESET_RCVD)
        condition |= (state_to_check == RESET_RCVD);
    } else if (side_to_check == CLIENT) {
      if (as & AS_CONF_RCVD)
        condition |= (state_to_check == CONF_RCVD);
      if (as & AS_NON_CONF_RCVD)
        condition |= (state_to_check == NON_CONF_RCVD);
      if (as & AS_ACK_RCVD)
        condition |= (state_to_check == ACK_RCVD);
      if (as & AS_RESET_RCVD)
        condition |= (state_to_check == RESET_RCVD);
    }

    klee_assume(condition);
    return state_to_check;
  }
}