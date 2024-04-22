#include "klee/Protocols/coap/coap_messages.h"
#include "klee/Protocols/coap/coap_states.h"
#include "klee/Support/Protocols/helper.h"
#include <assert.h>
#include <errno.h>
#include <memory.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/////////////////////// Parser Functions

void parse_header(uint8_t *msg, MESSAGE *message) {
  uint8_t msg_header[HEADER_SIZE];

  memcpy(msg_header, msg, HEADER_SIZE);
  msg += HEADER_SIZE;

  message->version = msg_header[0] & 0xC0 >> 6;
  message->type = msg_header[0] & 0x30 >> 4;
  message->token_length = msg_header[0] & 0xF0;

  message->code = msg_header[1];

  // endian load
  message->msg_id = ((uint16_t)msg_header[2] << 8) | msg_header[3];
}

void parse_token(uint8_t *msg, MESSAGE *message) {
  // NOTE: Does this need to handle endianness?
  message->token = malloc(message->token_length);
  memcpy(message->token, msg, message->token_length);
  msg += message->token_length;
}

void parse_payload(uint8_t *msg, MESSAGE *message, size_t datagram_size,
                   uint8_t *point_to_beginning) {
  int bytesRemaining = datagram_size - (msg - point_to_beginning);
  message->size = datagram_size;
  message->has_payload_marker = false;
  message->payload = NULL;
  message->payload_size = 0;

  if (bytesRemaining > 0) {
    uint8_t payload_marker;
    memcpy(&payload_marker, msg, 1);
    msg += 1;

    // Check for payload marker
    if (payload_marker == 0xff) {
      message->has_payload_marker = true;

      size_t payload_size = datagram_size - (msg - point_to_beginning);

      if (payload_size > 0) {
        message->payload_size = payload_size;
        message->payload = malloc(payload_size);
        memcpy(message->payload, msg, payload_size);
        msg += payload_size;
      }
    }
  }
}

int parse_message(const uint8_t *datagram, MESSAGE *message,
                  size_t datagram_size, bool is_client_originated) {
  const uint8_t *msg = (uint8_t *)datagram;
  uint8_t *point_to_beginning = (uint8_t *)datagram;

  message->is_client_generated = is_client_originated;

  parse_header(msg, message);
  parse_token(msg, message);
  // NOTE: Options are assumed to not be used
  parse_payload(msg, message, datagram_size, point_to_beginning);

  // Parse Options
  //   while (bytesRemaining > 0) {
  //     uint8_t options_header;
  //     memcpy(&options_header, msg, 1);
  //     msg += 1;

  //         // Parse Options
  //         uint16_t delta = (options_header & 0xf0) >> 4;
  //     uint16_t op_len = (options_header & 0x0f);

  //     if (delta == 13) {
  //       memcpy(&delta, msg, 1);
  //       msg += 1;

  //       delta += 13;

  //     } else if (delta == 14) {
  //       uint8_t delta_temp[2];
  //       memcpy(delta_temp, msg, 2);
  //       msg += 2;

  //       delta = (((uint16_t)delta_temp[0] << 8) | delta_temp[1]) + 269;
  //     }

  //     if (op_len == 13) {
  //       memcpy(&op_len, msg, 1);
  //       msg += 1;

  //       op_len += 13;
  //     } else if (op_len == 14) {
  //       uint8_t op_len_temp[2];
  //       memcpy(op_len_temp, msg, 2);
  //       msg += 2;

  //       op_len = (((uint16_t)op_len_temp[0] << 8) | op_len_temp[1]) + 269;
  //     }

  //     uint8_t *option_value = malloc(op_len);
  //     memcpy(option_value, msg, op_len);
  //     msg += op_len;
  //     //////////
  //   }

  return msg - point_to_beginning;
}

/////////////////////// Serializer Functions
int serialize_message(uint8_t **out_buffer, MESSAGE *msg, size_t rcvsize,
                      MESSAGE *shadow_msg) {
  uint8_t *pointer_to_beginning = *out_buffer;
  assert(rcvsize > HEADER_SIZE); // Sanity check to reject records with
                                 // length lower than the minimum

  uint8_t *point_to_beginning = *out_buffer;

  uint8_t header[HEADER_SIZE];

  header[0] = msg->version << 6;
  header[0] |= msg->type << 4;
  header[0] |= msg->token_length;

  header[1] = msg->code;

  header[2] = (msg->msg_id & 0xff00) >> 8;
  header[3] = (msg->msg_id & 0x00ff);

  memcpy(*out_buffer, header, HEADER_SIZE); // Copy the Message header
  *out_buffer += HEADER_SIZE;               // Get past the Message Header

  memcpy(*out_buffer, msg->token,
         shadow_msg->token_length);        // Copy the Message Token
  *out_buffer += shadow_msg->token_length; // Get past the Message Token

  size_t payload_size = rcvsize - HEADER_SIZE - shadow_msg->token_length;

  // NOTE: Ignores Options

  memcpy(*out_buffer, msg->payload,
         payload_size);        // Copy the Message Payload
  *out_buffer += payload_size; // Get past the Message Payload

  return *out_buffer - pointer_to_beginning;
}
