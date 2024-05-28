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

#define COAP_HEADER_SIZE 4
#define COAP_PAYLOAD_MARKER 0xFF

/**
 * @brief Extracts the version field from the CoAP header.
 *
 * This macro retrieves the 2-bit version field from the first byte of the CoAP
 * message. The version field is stored in bits 6-7 of the first byte and is
 * extracted using a bitmask and shift.
 *
 * @param data Pointer to the start of the CoAP message.
 * @return uint8_t The version field (0-3).
 */
#define COAP_HEADER_VERSION(data) ((0xC0 & (data)[0]) >> 6)

/**
 * @brief Extracts the type field from the CoAP header.
 *
 * This macro retrieves the 2-bit type field from the first byte of the CoAP
 * message. The type field is stored in bits 4-5 of the first byte and is
 * extracted using a bitmask and shift.
 *
 * @param data Pointer to the start of the CoAP message.
 * @return uint8_t The type field (0-3).
 */
#define COAP_HEADER_TYPE(data) ((0x30 & (data)[0]) >> 4)

/**
 * @brief Extracts the Token Length (TKL) field from the CoAP header.
 *
 * This macro retrieves the 4-bit Token Length (TKL) field from the first byte
 * of the CoAP message. The TKL field is stored in bits 0-3 of the first byte
 * and is extracted using a bitmask.
 *
 * @param data Pointer to the start of the CoAP message.
 * @return uint8_t The TKL field (0-15), indicating the length of the token.
 */
#define COAP_HEADER_TKL(data) ((0x0F & (data)[0]) >> 0)

/**
 * @brief Extracts the code field from the CoAP header.
 *
 * This macro retrieves the 8-bit code field from the second byte of the CoAP
 * message. The code field determines the type of request or response in the
 * CoAP protocol.
 *
 * @param data Pointer to the start of the CoAP message.
 * @return uint8_t The code field.
 */
#define COAP_HEADER_CODE(data) ((data)[1])

/**
 * @brief Extracts the Message ID (MID) field from the CoAP header.
 *
 * This macro retrieves the 16-bit Message ID (MID) field from the third and
 * fourth bytes of the CoAP message. The MID is used to match requests and
 * responses in the CoAP protocol.
 *
 * @param data Pointer to the start of the CoAP message.
 * @return uint16_t The 16-bit Message ID field.
 */
#define COAP_HEADER_MID(data) (((data)[2] << 8) | (data)[3])

typedef struct {
  unsigned version : 2;
  unsigned type : 2;
  unsigned tokenLength : 4;
  uint8_t code;
  uint16_t messageId;
  uint8_t token[8];
} CoapHeader;

typedef struct {
  uint16_t number;
  uint16_t length;
  uint8_t *value;
} CoapOption;

typedef struct {
  CoapHeader header;
  CoapOption options[20]; // Support up to 20 options for simplicity
  int options_count;
  uint8_t *payload;     // Pointer to the payload
  uint16_t payload_len; // Length of the payload
} CoapMessage;

int parse_coap_message(const uint8_t *packet, size_t packet_len,
                       CoapMessage *message);
int serialize_coap_message(const CoapMessage *message,
                           const CoapMessage *shadow_message, uint8_t *buffer,
                           size_t buffer_len);
#endif // COAP_MESSAGES_H