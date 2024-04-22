#ifndef COAP_MONITORS
#define COAP_MONITORS

#include "klee/Protocols/coap/coap_messages.h"
#include "klee/Protocols/coap/coap_states.h"

// Experiments
// TODO: set values (Are values important?)
#define version_requirement 1
#define type_requirement 2
#define message_id_requirement 3
#define id_unique 4
#define token_requirement 5
#define token_unique 6
#define token_length_requirement 7
#define token_length_correlation 8
#define payload_marker_requirement 9
#define empty_message_requirement 10
#define code_requirement 11

// typedef enum allowed_states allowed_states;
typedef enum allowed_coap_states {
  AS_CONF_RCVD = 1 << CONF_RCVD,         // 0th bit set
  AS_NON_CONF_RCVD = 1 << NON_CONF_RCVD, // 1st bit set
  AS_ACK_RCVD = 1 << ACK_RCVD,           // 2nd bit set
  AS_RESET_RCVD = 1 << RESET_RCVD,       // 3rd bit set
} allowed_coap_states;

typedef void (*coap_monitor_handle)(MESSAGE *message,
                                    bool is_message_client_generated);

typedef struct {
  coap_monitor_handle handle;
  allowed_coap_states valid_states;
} COAP_MONITOR;

coap_monitor_handle set_coap_monitor_handle(int experiment, SIDE side_to_check);
allowed_coap_states set_coap_monitor_valid_states(int experiment,
                                                  SIDE side_to_check);
int determine_coap_state_to_check(allowed_coap_states as, SIDE side_to_check);

// Experiment funcs
// TODO: Add all
void is_version_valid_server(MESSAGE *message, bool is_record_client_generated);

#endif // COAP_MONITORS