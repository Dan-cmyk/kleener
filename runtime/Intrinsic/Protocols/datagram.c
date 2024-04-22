#include "klee/Protocols/coap/coap_messages.h"
#include "klee/Protocols/coap/coap_monitors.h"
#include "klee/Protocols/dtls/dtls_monitors.h"
#include "klee/Protocols/dtls/dtls_records.h"
#include "klee/Protocols/quic/quic_monitors.h"
#include "klee/Protocols/quic/quic_packets.h"
#include "klee/Protocols/quic/quic_states.h"

// records that are exchanged between client and server
static RECORD records[60];
static RECORD shadow_records[60];
// number of records that are exchanged so far
static size_t record_counter = 0;
int8_t server_current_state = INIT;
int8_t client_current_state = INIT;
int8_t accumulative_state = INIT;
static bool is_monitor_enabled = false;
int handle_DTLS_datagram(uint8_t *datagram, size_t datagram_size,
                         uint8_t *out_datagram, bool is_client_originated,
                         monitor_handle monitor_handle, int state_to_check) {

  size_t off = 0;
  size_t shadow_offset = 0;
  /*
   * This loop repeats a set of operations for each record in a datagram:
   * 1- It first parses each received record into a RECORD structure
   * 2- We also parse each received record into a shadow RECORD structure
   * 3- Based on the origin of the received record (if it is generated by the
   * client or server), we update the state of the server or client and the
   * accumulative state of the SUT. 4- When the accumulative state of the SUT is
   * greater equal to state_to_check, we enable the monitor 5- Based on the
   * requirement, the monitor make some part of the record symbolic and put some
   * assumptions on it. 6- Finally, with the aid of the shadow record, we
   * serialize the record back to datagram buffer.
   */
  while (off != datagram_size) {
    parse_record(datagram, &records[record_counter], &off, datagram_size,
                 is_client_originated);

    parse_record(datagram, &shadow_records[record_counter], &shadow_offset,
                 datagram_size, is_client_originated);

    if (is_client_originated) {
      DTLS_server_state_machine(records, shadow_records, record_counter,
                                &server_current_state);
      accumulative_state = server_current_state;
    } else {
      DTLS_client_state_machine(records, shadow_records, record_counter,
                                &client_current_state);
      accumulative_state = client_current_state;
    }

    if (accumulative_state >= state_to_check) {
      is_monitor_enabled = true;
    }
    if (is_monitor_enabled) {
      if (monitor_handle != NULL) {
        RECORD *record = records + record_counter;
        monitor_handle(record, is_client_originated);
      }
    }

    serialize_record(&out_datagram, &records[record_counter], datagram_size,
                     &shadow_records[record_counter]);
    record_counter++;
  }
  return 0;
}

/*
 * - We repeat the followings until the offset is equal to the datagram size:
 *  1- We parse the packet header
 *  1-1- We parse the frames it contains
 *  2- We parse the packet in a shadow data structure to use later for
 * serialization 3- We call the state machine and make our preferred parts
 * symbolic 4- We serialize the packet into the final buffer
 */

static Packet packets[30];
static Packet shadow_packets[30];
static size_t packet_counter = 0;
static quic_state quic_client_state = {.frame_index = INIT,
                                       .frame_type = INIT,
                                       .packet_number = INIT,
                                       .packet_type = INIT};
static quic_state quic_server_state = {.frame_index = INIT,
                                       .frame_type = INIT,
                                       .packet_number = INIT,
                                       .packet_type = INIT};
static quic_state quic_accumulative_state = {.frame_index = INIT,
                                             .frame_type = INIT,
                                             .packet_number = INIT,
                                             .packet_type = INIT};
static bool is_quic_monitor_enabled = false;

int handle_quic_datagram(uint8_t *datagram, size_t datagram_size,
                         uint8_t *out_datagram, bool is_client_originated,
                         QUIC_MONITOR monitor, quic_state state_to_check) {
  size_t off = 0;
  size_t shadow_offset = 0;

  while (off != datagram_size) {

    if (process_packet(datagram, &packets[packet_counter], &off, datagram_size,
                       is_client_originated) < 0) {
      printf("Error Processing the packet %zul in the datagram!\n",
             packet_counter);
      return -1;
    }
    if (process_packet(datagram, &shadow_packets[packet_counter],
                       &shadow_offset, datagram_size,
                       is_client_originated) < 0) {
      printf("Error Processing the packet %zul in the datagram!\n",
             packet_counter);
      return -1;
    }

    if (is_client_originated) {
      QUIC_server_packet_state_machine(&packets[packet_counter],
                                       &quic_server_state);
      copy_state(&quic_accumulative_state, &quic_server_state);
    } else {
      QUIC_client_packet_state_machine(&packets[packet_counter],
                                       &quic_client_state);
      copy_state(&quic_accumulative_state, &quic_client_state);
    }
    /////
    if (monitor.is_packet_level) {
      if (!is_quic_monitor_enabled) {
        if (is_state_equal(quic_accumulative_state, state_to_check)) {
          is_quic_monitor_enabled = true;
        }
      }
      if (is_quic_monitor_enabled) {
        if (monitor.handle != NULL) {
          monitor.handle(&packets[packet_counter], is_client_originated);
        }
      }
    }
    /////
    Frame *frame = packets[packet_counter].frame;
    while (frame != NULL) {
      if (is_client_originated) {
        QUIC_server_frame_state_machine(frame, &quic_server_state);
        copy_state(&quic_accumulative_state, &quic_server_state);
      } else {
        QUIC_client_frame_state_machine(frame, &quic_client_state);
        copy_state(&quic_accumulative_state, &quic_client_state);
      }
      if (!monitor.is_packet_level) {
        if (!is_quic_monitor_enabled) {
          if (is_state_equal(quic_accumulative_state, state_to_check)) {
            is_quic_monitor_enabled = true;
            packets[packet_counter].enabled_frame = frame;
          }
        }
        if (is_quic_monitor_enabled) {
          if (monitor.handle != NULL) {
            monitor.handle(&packets[packet_counter], is_client_originated);
          }
        }
      }
      frame = frame->next_frame;
    }
    ////
    if (serialize_packet(&packets[packet_counter],
                         &shadow_packets[packet_counter], &out_datagram,
                         is_client_originated) < 0) {
      printf("Error Serializing the packet %zul in the datagram!\n",
             packet_counter);
      return -1;
    }
    packet_counter++;
  }
  out_datagram -= datagram_size;
  return 0;
}

// messages that are exchanged between client and server
static MESSAGE messages[60];
static MESSAGE shadow_messages[60];
// number of messages that are exchanged so far
static size_t message_counter = 0;
int8_t coap_server_current_state = INIT;
int8_t coap_client_current_state = INIT;
int8_t coap_accumulative_state = INIT;
static bool is_coap_monitor_enabled = false;
int handle_CoAP_datagram(uint8_t *datagram, size_t datagram_size,
                         uint8_t *out_datagram, bool is_client_originated,
                         coap_monitor_handle monitor_handle,
                         int state_to_check) {

  parse_message(datagram, &messages[message_counter], datagram_size,
                is_client_originated);

  parse_message(datagram, &shadow_messages[message_counter], datagram_size,
                is_client_originated);

  if (is_client_originated) {
    CoAP_server_state_machine(messages, shadow_messages, message_counter,
                              &coap_server_current_state);
    coap_accumulative_state = coap_server_current_state;
  } else {
    CoAP_client_state_machine(messages, shadow_messages, message_counter,
                              &coap_client_current_state);
    coap_accumulative_state = coap_client_current_state;
  }

  if (coap_accumulative_state >= state_to_check) {
    is_coap_monitor_enabled = true;
  }
  if (is_coap_monitor_enabled) {
    if (monitor_handle != NULL) {
      MESSAGE *message = messages + message_counter;
      monitor_handle(message, is_client_originated);
    }
  }

  serialize_message(&out_datagram, &messages[message_counter], datagram_size,
                    &shadow_messages[message_counter]);
  message_counter++;
  return 0;
}