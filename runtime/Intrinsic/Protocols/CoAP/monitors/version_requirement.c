#include "klee/Protocols/coap/coap_messages.h"
#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/klee.h"
#include <assert.h>

enum STATES {
  Init,
  Rcvd,
  End,
};
static STATE local_state = Init;

uint16_t message_id = 0;

void is_version_valid_server(MESSAGE *message, bool sent_from_client) {
  if (sent_from_client && message->type == CONFIRMABLE_MSG &&
      local_state == Init) {
    message_id = message->msg_id;
    kleener_make_symbolic(&message->version, sizeof(message->version),
                          "message->version");
    klee_assume(message->version != 1);
    local_state = Rcvd;
  } else if (!sent_from_client && local_state == Rcvd) {
    assert(message->msg_id != message_id);
    local_state = End;
  } else if (sent_from_client && local_state == Rcvd) {
    local_state = End;
  }
}
