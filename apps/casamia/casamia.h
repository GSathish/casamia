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
 *      Main header file of Casa Mia. Casa Mia allows intalling simple in-network
 *      processing tasks (written in Python) in IoT nodes.
 *
 *      Casa Mia is described and evaluated in the paper "Casa Mia: enabling
 *      reprogrammable in-network processing in IoT-based WSNs",
 *      D. Alessandrelli, M. Petracca, and P. Pagano, in Proceedings of IEEE
 *      DCoSS 2013 Conference and Workshops.
 *
 * \author
 *      Sathish Gopalakrishnan <sathish@ece.ubc.ca>
 */

#ifndef  __TRES_H__
#define __TRES_H__

/*----------------------------------------------------------------------------*/
#include "contiki.h"
#include "erbium.h"
#include "casamia-mem.h"

#if WITH_COAP == 7
#include "er-coap-07-engine.h"
#include "er-coap-07-observing-client.h"
#elif WITH_COAP == 13
#include "er-coap-13-engine.h"
#include "er-coap-13-observing-client.h"
#else
#error "CoAP version defined by WITH_COAP not implemented"
#endif

/*----------------------------------------------------------------------------*/
/*                   Casa Mia default configuration values                       */
/*----------------------------------------------------------------------------*/
#ifndef TRES_CONF_PATH_MAX_LEN
#define TRES_PATH_LEN_MAX 30
#else
#define TRES_PATH_LEN_MAX TRES_CONF_PATH_MAX_LEN
#endif

#ifndef TRES_CONF_TAG_MAX_LEN
#define TRES_TAG_MAX_LEN 8
#else
#define TRES_TAG_MAX_LEN TRES_CONF_TAG_MAX_LEN
#endif


#ifndef TRES_CONF_STATE_SIZE
#define TRES_STATE_SIZE 16
#else
#define TRES_STATE_SIZE TRES_CONF_STATE_SIZE
#endif

#ifndef TRES_CONF_PF_IMG_MAX_SIZE
#define T1_PF_IMG_SIZE 1024
#else
#define T1_PF_IMG_SIZE TRES_CONF_PF_IMG_MAX_SIZE
#endif

#define TRES_REMOTE_PORT     UIP_HTONS(COAP_DEFAULT_PORT)

#ifndef TRES_CONF_RELIABLE
#define TRES_RELIABLE 0
#else
#define TRES_RELIABLE TRES_CONF_RELIABLE
#endif

// workaround for copper always using blockwise transfer if debug is enabled
#ifndef TRES_CONF_COPPER_WORKAROUND
#define TRES_COPPER_WORKAROUND 0
#else
#define TRES_COPPER_WORKAROUND TRES_CONF_COPPER_WORKAROUND
#endif

#define TRES_BASE_PATH "tasks"

//! Maximimun number of tres tasks
#define TRES_TASK_MAX_NUMBER 2

//! Maximimun number of is (shared among all tasks)
#define TRES_IS_MAX_NUMBER 3

//! Maximimun length of a task name
#define TRES_TASK_NAME_MAX_LEN (8 + 1)

/*----------------------------------------------------------------------------*/
#if TRES_RELIABLE
#define tres_send(...) send_reliable(__VA_ARGS__)
#else
#define tres_send(...) send_unreliable(__VA_ARGS__)
#endif

/*----------------------------------------------------------------------------*/
typedef struct tres_is_s {
  struct tres_is_s *next;
  uip_ipaddr_t addr[1];
  char path[TRES_PATH_LEN_MAX];
  char tag[TRES_TAG_MAX_LEN];
  coap_observee_t *obs;
} tres_is_t;

typedef struct tres_od_s {
  uip_ipaddr_t addr[1];
  char path[TRES_PATH_LEN_MAX];
} tres_od_t;

typedef struct tres_tres_s {
  char name[TRES_TASK_NAME_MAX_LEN];
  char lo_url[sizeof("tasks") + TRES_TASK_NAME_MAX_LEN + sizeof("lo")];
  uint8_t *pf_img;
  int8_t sid;
  LIST_STRUCT(is_list);
  tres_od_t od[1];
  char *last_input_tag;
  uint8_t last_input[REST_MAX_CHUNK_SIZE];
  uint8_t last_output[REST_MAX_CHUNK_SIZE];
  uint8_t state[TRES_STATE_SIZE];
  uint16_t obs_count;
  uint8_t state_len;
  uint8_t monitoring;
} tres_res_t;

/*----------------------------------------------------------------------------*/
void tres_init(void);

uint8_t tres_start_monitoring(tres_res_t *task);
uint8_t tres_stop_monitoring(tres_res_t *task);
uint8_t tres_toggle_monitoring(tres_res_t *task);

/*----------------------------------------------------------------------------*/
#endif /*  __TRES_H__  */
