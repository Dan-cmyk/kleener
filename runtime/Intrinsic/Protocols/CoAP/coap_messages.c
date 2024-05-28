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

/**
 * @brief Parses a single option field from a CoAP message.
 *
 * This function extracts and parses a CoAP option field from a given buffer. It
 * reads the option delta and length fields according to the CoAP specification,
 * adjusting for special cases where values are extended to multiple bytes. The
 * option number is updated cumulatively, and the function returns the total
 * size of the option including its header and value.
 *
 * Special cases:
 * - If the delta is 13 or 14, the delta field will span additional bytes for
 * encoding.
 * - A delta value of 15 is a payload marker indicating the start of the message
 * payload.
 * - If the length field is 13 or 14, additional bytes are used to represent the
 * actual length.
 *
 * @param buffer Pointer to the start of the option field in the CoAP message.
 * @param remaining_length The remaining bytes available in the buffer after the
 * option field starts.
 * @param current_number Pointer to the current cumulative option number, which
 * is updated by adding the parsed delta.
 * @param option_value Pointer to a variable that will hold the starting address
 * of the option value in the buffer.
 * @param option_length Pointer to a variable that will hold the length of the
 * option value.
 * @return int The total size of the option including the header and value, or
 * -1 if an error occurs (e.g., insufficient remaining length).
 */
static int parse_option(const uint8_t *buffer, int remaining_length,
                        uint16_t *current_number, uint8_t **option_value,
                        uint16_t *option_length) {
  if (remaining_length < 1)
    return -1; //

  uint8_t *option = (uint8_t *)buffer;
  uint16_t delta = (option[0] >> 4) & 0x0F;
  uint16_t length = option[0] & 0x0F;
  int header_length = 1;

  // Parse extended delta field
  if (delta == 13) {
    if (remaining_length < 2)
      return -1;
    delta = option[1] + 13;
    header_length += 1;
  } else if (delta == 14) {
    if (remaining_length < 3)
      return -1;
    delta = ((option[1] << 8) | option[2]) + 269;
    header_length += 2;
  } else if (delta == 15) {
    return 0; // This is the payload marker
  }

  // Parse extended length field
  if (length == 13) {
    if (remaining_length < header_length + 1)
      return -1;
    length = option[header_length] + 13;
    header_length += 1;
  } else if (length == 14) {
    if (remaining_length < header_length + 2)
      return -1;
    length = ((option[header_length] << 8) | option[header_length + 1]) + 269;
    header_length += 2;
  }

  // Ensure remaining length is sufficient
  if (remaining_length < header_length + length)
    return -1;

  // Update cumulative option number and set pointers
  *current_number += delta;
  *option_value = option + header_length;
  *option_length = length;

  return header_length + length;
}

/**
 * @brief Parses a CoAP message from a given packet into a CoapMessage
 * structure.
 *
 * This function takes a byte array representing a CoAP packet and extracts the
 * message header, token, options, and payload, storing them in the provided
 * `CoapMessage` structure. The function first checks that the packet length is
 * sufficient for the CoAP header, and then proceeds to parse the header fields,
 * the token, and the options, following the CoAP protocol specifications. If a
 * payload marker is found, the payload data is extracted as well.
 *
 * Error codes:
 * -1: The packet length is less than the minimum CoAP header size.
 * -2: The token length field in the header exceeds the maximum allowed value
 * of 8. -3: The total packet length is insufficient to contain both the header
 * and the specified token length. -4: An error occurred while parsing an
 * option, or the number of options exceeded the maximum limit.
 *
 * @param packet Pointer to the byte array representing the CoAP packet.
 * @param packet_len Size of the CoAP packet in bytes.
 * @param message Pointer to the `CoapMessage` structure where the parsed data
 * will be stored.
 * @return int Returns 0 if the message was successfully parsed, or a negative
 * error code if an error occurred.
 */
int parse_coap_message(const uint8_t *packet, size_t packet_len,
                       CoapMessage *message) {
  if (packet_len < COAP_HEADER_SIZE)
    return -1;

  // Parse header
  message->header.version = (packet[0] >> 6) & 0x03;
  message->header.type = (packet[0] >> 4) & 0x03;
  message->header.tokenLength = packet[0] & 0x0F;
  message->header.code = packet[1];
  message->header.messageId = (packet[2] << 8) | packet[3];

  if (message->header.tokenLength > 8)
    return -2;
  if (COAP_HEADER_SIZE + message->header.tokenLength > packet_len)
    return -3;

  // Extract token
  memcpy(message->header.token, packet + 4, message->header.tokenLength);

  // Start parsing options after token
  uint16_t current_option_number = 0;
  int offset = 4 + message->header.tokenLength;
  message->options_count = 0;

  while (offset < packet_len && packet[offset] != COAP_PAYLOAD_MARKER) {
    uint8_t *option_value;
    uint16_t option_length;
    int res =
        parse_option(packet + offset, packet_len - offset,
                     &current_option_number, &option_value, &option_length);
    if (res == 0)
      break; // Payload marker reached
    if (res < 0 || message->options_count >= 16)
      return -4; // Error or too many options

    message->options[message->options_count].number = current_option_number;
    message->options[message->options_count].length = option_length;
    message->options[message->options_count].value = option_value;
    message->options_count++;

    offset += res;
  }

  // Check for the payload marker and set the payload data
  if (packet[offset] == COAP_PAYLOAD_MARKER && offset + 1 < packet_len) {
    message->payload = (uint8_t *)(packet + offset + 1);
    message->payload_len = packet_len - (offset + 1);
  } else {
    message->payload = NULL;
    message->payload_len = 0;
  }

  return 0;
}

/////////////////////// Serializer Functions
/**
 * @brief Serializes a CoAP option into a given buffer.
 *
 * This function converts a CoAP option structure into its wire format
 * representation and stores it in the provided buffer. It computes and encodes
 * the option delta (the difference between the current option number and the
 * last option number) and the option length according to the CoAP
 * specification. Extended encoding is used if the delta or length values exceed
 * certain thresholds.
 *
 * Special encoding:
 * - If the delta or length value is 13 or 14, it uses additional bytes to
 * encode the full value.
 * - A delta value of 15 is reserved and not allowed in CoAP options.
 *
 * @param buffer Pointer to the byte array where the option will be serialized.
 * @param option Pointer to the `CoapOption` structure containing the current
 * option to be serialized.
 * @param shadow_option Pointer to the `CoapOption` structure representing the
 * shadow option for copying values.
 * @param last_option_number The cumulative option number from the last
 * serialized option.
 * @return int The total size of the serialized option including its header and
 * value, or a negative error code if an error occurred.
 */
static int serialize_option(uint8_t *buffer, const CoapOption *option,
                            const CoapOption *shadow_option,
                            uint16_t last_option_number) {
  uint16_t delta = option->number - last_option_number;
  uint16_t length = option->length;
  int index = 0;

  // Encode option delta
  if (delta < 13) {
    buffer[0] = delta << 4;
  } else if (delta < 269) {
    buffer[0] = 13 << 4;
    buffer[++index] = delta - 13;
  } else {
    buffer[0] = 14 << 4;
    buffer[++index] = ((delta - 269) >> 8) & 0xFF;
    buffer[++index] = (delta - 269) & 0xFF;
  }

  // Encode option length
  if (length < 13) {
    buffer[0] |= length;
  } else if (length < 269) {
    buffer[0] |= 13;
    buffer[++index] = length - 13;
  } else {
    buffer[0] |= 14;
    buffer[++index] = ((length - 269) >> 8) & 0xFF;
    buffer[++index] = (length - 269) & 0xFF;
  }

  index++; // Move past the current byte that has now been fully written

  // Copy the option value
  memcpy(buffer + index, option->value, shadow_option->length);
  return index + shadow_option->length; // Return the full size of the option
                                        // including its header
}

/**
 * @brief Serializes a CoAP message into a byte buffer.
 *
 * This function converts a `CoapMessage` structure into its wire format
 * representation and writes it into the provided buffer. The function
 * serializes the CoAP header, token, options, and payload, following the CoAP
 * protocol specification. A `shadow_message` is used for copying values and
 * validating field sizes.
 *
 * Error codes:
 * -1: The provided buffer is too small to contain the CoAP header or the
 * subsequent fields.
 *
 * @param message Pointer to the `CoapMessage` structure containing the CoAP
 * message to be serialized.
 * @param shadow_message Pointer to a `CoapMessage` structure that serves as a
 * reference for field sizes.
 * @param buffer Pointer to the byte array where the serialized CoAP message
 * will be written.
 * @param buffer_len The size of the buffer in bytes.
 * @return int The total size of the serialized CoAP message, or -1 if the
 * buffer is too small or an error occurred.
 */
int serialize_coap_message(const CoapMessage *message,
                           const CoapMessage *shadow_message, uint8_t *buffer,
                           size_t buffer_len) {
  if (buffer_len < 4)
    return -1;

  // Serialize header
  buffer[0] = (message->header.version << 6) | (message->header.type << 4) |
              (message->header.tokenLength);
  buffer[1] = message->header.code;
  buffer[2] = message->header.messageId >> 8;
  buffer[3] = message->header.messageId & 0xFF;

  int index = 4;
  if (index + shadow_message->header.tokenLength > buffer_len)
    return -1;
  memcpy(buffer + index, message->header.token,
         shadow_message->header.tokenLength);
  index += shadow_message->header.tokenLength;

  // Serialize options
  uint16_t last_option_number = 0;
  for (int i = 0; i < shadow_message->options_count; i++) {
    int opt_size =
        serialize_option(buffer + index, &message->options[i],
                         &shadow_message->options[i], last_option_number);
    if (opt_size < 0 || (index + opt_size) > buffer_len)
      return -1;
    index += opt_size;
    last_option_number = message->options[i].number;
  }

  // Serialize payload
  if (message->payload && shadow_message->payload_len > 0) {
    if ((index + shadow_message->payload_len + 1) > buffer_len)
      return -1;
    buffer[index++] = COAP_PAYLOAD_MARKER;
    memcpy(buffer + index, message->payload, shadow_message->payload_len);
    index += shadow_message->payload_len;
  }
  return index;
}