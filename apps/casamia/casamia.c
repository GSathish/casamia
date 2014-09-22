/*
 * Copyright (c) 2013, RADICAL-UBC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * \file
 *      Main functions for Casa Mia.
 *
 *      Casa Mia is described and evaluated in the paper "Casa Mia: enabling
 *      reprogrammable in-network processing in IoT-based WSNs",
 *      D. Alessandrelli, M. Petracca, and P. Pagano, in Proceedings of IEEE
 *      DCoSS 2013 Conference and Workshops.
 *
 * \author
 *      Sathish Gopalakrishnan <sathish@ece.ubc.ca>
 */


#include <string.h>

#include "contiki.h"
#include "erbium.h"
#include "pm.h"

#include "tres.h"
#include "casamia-pymite.h"
#include "list_unrename.h"
#include "casamia-interface.h"

#define DEBUG 0
#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINTFLN(format, ...) printf(format "\n", ##__VA_ARGS__)
#define PRINT6ADDR(addr) PRINTF("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:"        \
                                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x]",       \
                                ((uint8_t *)addr)[0], ((uint8_t *)addr)[1],    \
                                ((uint8_t *)addr)[2], ((uint8_t *)addr)[3],    \
                                ((uint8_t *)addr)[4], ((uint8_t *)addr)[5],    \
                                ((uint8_t *)addr)[6], ((uint8_t *)addr)[7],    \
                                ((uint8_t *)addr)[8], ((uint8_t *)addr)[9],    \
                                ((uint8_t *)addr)[10], ((uint8_t *)addr)[11],  \
                                ((uint8_t *)addr)[12], ((uint8_t *)addr)[13],  \
                                ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])
#else
#define PRINTF(...)
#define PRINT6ADDR(addr)
#define PRINTFLN(...)
#endif


/*----------------------------------------------------------------------------*/
/*                              Global variables                              */
/*----------------------------------------------------------------------------*/

PROCESS(pf_process, "Casa Mia processing function process");

extern struct tres_pm_io_s tres_pm_io;

/// The heap for the Python VM. Make it far memory, dword-aligned.
static uint8_t heap[TRES_PM_HEAP_SIZE]
  __attribute__ ((aligned((2 * sizeof(int)))));

static process_event_t new_input_event;

/*----------------------------------------------------------------------------*/
/*                            Forward Declarations                            */
/*----------------------------------------------------------------------------*/
static tres_is_t *find_is(tres_res_t *task, coap_observee_t *obs);

/*----------------------------------------------------------------------------*/
/*                                Helper functions                            */
/*----------------------------------------------------------------------------*/
static tres_is_t *
find_is(tres_res_t *task, coap_observee_t *obs)
{
  tres_is_t *is;

  for(is = list_head(task->is_list); is != NULL; is = list_item_next(is)) {
    if(is->obs == obs) {
      return is;
    }
  }
  return NULL;
}

/*----------------------------------------------------------------------------*/
/*
static void 
print_byte_array(uint8_t *bytes, uint16_t len)
{
  uint32_t i;
  for (i = 0; i < len; i++) {
    PRINTF("%02X ", bytes[i]);
    if ((i % 8) == 7) {
      PRINTF("\n");
    } 
  }
  PRINTF("\n");
}
*/

/*----------------------------------------------------------------------------*/
#if TRES_RELIABLE
static void
client_chunk_handler(void *callback_data, void *response)
{
  const uint8_t *chunk;

  coap_get_payload(response, &chunk);
  //PRINTF("|%.*s\n", len, (char *)chunk);
}
/*----------------------------------------------------------------------------*/
static void
send_reliable(uip_ipaddr_t *addr, uint16_t port, char *path, uint8_t *payload)
{
  coap_packet_t request[1];
  coap_transaction_t *t;
  uint8_t *token_ptr;
  uint8_t token_len;

  coap_init_message(request, COAP_TYPE_CON, COAP_PUT, coap_get_mid());
  coap_set_header_uri_path(request, path);
  coap_set_payload(request, payload, strlen((char *)payload));
  token_len = coap_get_token(&token_ptr);
  coap_set_header_token(request, token_ptr, token_len);
  t = coap_new_transaction(request->mid, addr, port);
  if(t) {
    t->callback = &client_chunk_handler;
    t->packet_len = coap_serialize_message(request, t->packet);
    PRINTF("send_reliable: sending reliably to");
    PRINT6ADDR(&t->addr);
    PRINTFLN();
    coap_send_transaction(t);
  } else {
    PRINTFLN("send_reliable: could not allocate transaction");
  }
}

#else /* !TRES_RELIABLE */

/*----------------------------------------------------------------------------*/
static void
send_unreliable(uip_ipaddr_t *addr, uint16_t port, char *path, uint8_t *payload)
{
  coap_packet_t request[1];
  size_t len;

  coap_init_message(request, COAP_TYPE_NON, COAP_PUT, coap_get_mid());
  coap_set_header_uri_path(request, path);
  coap_set_payload(request, payload, strlen((char *)payload));
  // no advantage in using transactions with NON messages, therefore we use
  // coap_send_message
  len = coap_serialize_message(request, uip_appdata);
  PRINTF("Sending unreliably to ");
  PRINT6ADDR(addr);
  PRINTFLN();
  coap_send_message(addr, port, uip_appdata, len);
}
#endif /* TRES_RELIABLE */

/*----------------------------------------------------------------------------*/
static void
tres_send_output(tres_res_t *task)
{
  PRINTFLN("--Requesting %s--", task->od->path);
  PRINT6ADDR(&task->od->addr);
  PRINTFLN(" : %u", UIP_HTONS(TRES_REMOTE_PORT));
  tres_send(task->od->addr, TRES_REMOTE_PORT, task->od->path,
            task->last_output);
  PRINTFLN("--Done--");
}


/*----------------------------------------------------------------------------*/
static void
run_processing_func(tres_res_t *task)
{
  //PmReturn_t retval;

  //printf("F?\n");
  pm_init(heap, sizeof(heap), MEMSPACE_PROG, NULL);
  tres_pm_io.in = (char *)task->last_input;
  tres_pm_io.out = (char *)task->last_output;
  tres_pm_io.out[0] = '\0';
  tres_pm_io.tag = (char *)task->last_input_tag;
  tres_pm_io.output_set = 0;
  tres_pm_io.state = task->state;
  tres_pm_io.state_len = &task->state_len;
  pm_run_from_img((uint8_t *)"pf", MEMSPACE_PROG, task->pf_img);
  //printf("F!\n");
  //PRINTF("Python finished, return of 0x%02x\n", retval);
  // send output to destination
  if(tres_pm_io.output_set) {
    if(!uip_is_addr_unspecified(task->od->addr)) {
      tres_send_output(task);
    }
    lo_event_handler(task);
  }
}

/*----------------------------------------------------------------------------*/
PROCESS_THREAD(pf_process, ev, data)
{
  PROCESS_BEGIN();
  PRINTF("PF process\n");

  new_input_event = process_alloc_event();
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(ev == new_input_event);
    run_processing_func((tres_res_t *)data);
  }
  PROCESS_END();
}

/*----------------------------------------------------------------------------*/
static void
is_notification_callback(coap_observee_t *obs, void *notification,
                         coap_notification_flag_t flag)
{
  int len = 0;
  tres_res_t *task;
  const uint8_t *payload = NULL;
  tres_is_t *is;

  PRINTF("Notification handler\n");
  PRINTF("Subject URI: %s\n", obs->url);
  task = obs->data;
  is = find_is(task, obs);
  if(notification) {
    len = coap_get_payload(notification, &payload);
  }
  switch (flag) {
  case NOTIFICATION_OK:
    PRINTF("NOTIFICATION OK: %*s\n", len, (char *)payload);
    if(len > REST_MAX_CHUNK_SIZE) {
      len = REST_MAX_CHUNK_SIZE;
    }
    memcpy(task->last_input, payload, len);
    task->last_input[len] = '\0';
    task->last_input_tag = is->tag;
    process_post(&pf_process, new_input_event, task);
    break;
  case OBSERVE_OK:
    PRINTF("OBSERVE_OK: %*s\n", len, (char *)payload);
    // ignore response and check whether we must observe additional input 
    // resources
    for(is = list_head(task->is_list); is != NULL; is = list_item_next(is)) {
      if(is->obs == NULL) {
        is->obs = coap_obs_request_registration(is->addr, TRES_REMOTE_PORT,
                                                is->path,
                                                is_notification_callback, task);
        return;
      }
    }
    break;
  case OBSERVE_NOT_SUPPORTED:
    printf("Casa Mia: ERROR: observe not supported\n");
    PRINTF("OBSERVE_NOT_SUPPORTED: %*s\n", len, (char *)payload);
    is->obs = NULL;
    break;
  case ERROR_RESPONSE_CODE:
    printf("Casa Mia: ERROR: error response to observe request\n");
    PRINTF("ERROR_RESPONSE_CODE: %*s\n", len, (char *)payload);
    is->obs = NULL;
    break;
  case NO_REPLY_FROM_SERVER:
    printf("Casa Mia: ERROR: not reply to observe request\n");
    PRINTF("NO_REPLY_FROM_SERVER: "
           "removing observe registration with token %x%x\n",
           obs->token[0], obs->token[1]);
    is->obs = NULL;
    break;
  }
}

/*----------------------------------------------------------------------------*/
// FIXME: change to static when Casa Mia evaluation is completed
//static uint8_t
uint8_t
tres_start_monitoring(tres_res_t *task)
{
  PRINTF("tres_start_monitoring()\n");
  tres_is_t *is;

  // check if input sources list is not empty
  if(list_length(task->is_list) == 0) {
    return -1;
  }
  // start monitoring input resources:
  // find first resource to observe and issue an observe request, that will 
  // cause a chain reaction causing all other sources to be observed as well, 
  // see is_handle_notification().
  for(is = list_head(task->is_list); is != NULL; is = list_item_next(is)) {
    if(is->obs == NULL) {
      is->obs = coap_obs_request_registration(is->addr, TRES_REMOTE_PORT,
                                              is->path,
                                              is_notification_callback, task);
      task->monitoring = 1;
      return 1;
    }
  }
  return 0;
}

/*----------------------------------------------------------------------------*/
// FIXME: change to static when Casa Mia evaluation is completed
//static uint8_t
uint8_t
tres_stop_monitoring(tres_res_t *task)
{
  PRINTF("tres_stop_monitoring()\n");
  tres_is_t *is;

  // stop monitoring input resource
  for(is = list_head(task->is_list); is != NULL; is = list_item_next(is)) {
    coap_remove_obs_subject(is->obs);
    is->obs = NULL;
  }
  task->monitoring = 0;
  return 1;
}

/*----------------------------------------------------------------------------*/
uint8_t
tres_toggle_monitoring(tres_res_t *task)
{
  PRINTF("tres_toggle_monitoring()\n");

  if(task->monitoring) {
    tres_stop_monitoring(task);
  } else {
    tres_start_monitoring(task);
  }
  return task->monitoring;
}

/*----------------------------------------------------------------------------*/
/*                                Global functions                            */
/*----------------------------------------------------------------------------*/
void
tres_init(void)
{
  tres_mem_init();

  tres_interface_init();

  process_start(&pf_process, NULL);
}
