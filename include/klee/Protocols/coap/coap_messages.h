#ifndef COAP_MESSAGES_H
#define COAP_MESSAGES_H

typedef struct MESSAGE_struct MESSAGE;

#include "klee/Protocols/coap/coap_states.h"
#include "klee/Support/Protocols/helper.h"
#include "memory.h"
#include "stdint.h"
#include <stdbool.h>

// Message Types
#define CONFIRMABLE_MSG 0
#define NON_CONFIRMABLE_MSG 1
#define ACKNOWLEDGEMENT_MSG 2
#define RESET_MSG 3

// Message Header Size in Bytes
#define HEADER_SIZE 4

// Message Header Lengths
#define VERSION_LENGTH 2     // Bits
#define TYPE_LENGTH 2        // Bits
#define TOKEN_SIZE_LENGTH 4  // Bits
#define CODE_LENGTH 8        // Bits
#define MESSAGE_ID_LENGTH 16 // Bits

// Options Lengths
#define OP_DELTA 4  // Bits
#define OP_LENGTH 4 // Bits

struct MESSAGE_struct {
  uint8_t version;
  uint8_t type;
  uint8_t *token;
  uint8_t token_length;
  uint8_t code;
  uint16_t msg_id;
  bool has_payload_marker;
  uint8_t *payload;
  uint16_t payload_size;
  bool is_client_generated;
  uint16_t size;
};

/////////
int parse_message(const uint8_t *datagram, MESSAGE *message,
                  size_t datagram_size, bool is_client_originated);
int serialize_message(uint8_t **out_buffer, MESSAGE *message, size_t rcvsize,
                      MESSAGE *shadow_msg);
#endif // COAP_MESSAGES_H