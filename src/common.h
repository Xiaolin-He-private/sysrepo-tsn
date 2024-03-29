/**
 * @file common.h
 * @author Xiaolin He
 * @brief header file for common.c.
 *
 * Copyright 2019 NXP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __COMMON_H_
#define __COMMON_H_

#define XPATH_MAX_LEN		200
#define IF_NAME_MAX_LEN		20
#define NODE_NAME_MAX_LEN	80
#define MSG_MAX_LEN		100

#include <sysrepo.h>
#include <stdbool.h>
#include <sysrepo/values.h>
#include <sysrepo/plugins.h>
#include <sysrepo/trees.h>
#include "sysrepo/xpath.h"
#include <tsn/genl_tsn.h> /* must ensure no stdbool.h was included before */
#include <linux/tsn.h>

enum apply_status {
	APPLY_NONE = 0,
	APPLY_PARSE_SUC,
	APPLY_PARSE_ERR,
	APPLY_SET_SUC,
	APPLY_SET_ERR,
};

enum num_type {
	NUM_TYPE_S8 =  0x1,
	NUM_TYPE_U8 =  0x2,
	NUM_TYPE_S16 =  0x3,
	NUM_TYPE_U16 =  0x4,
	NUM_TYPE_S32 =  0x5,
	NUM_TYPE_U32 =  0x6,
	NUM_TYPE_S64 =  0x7,
	NUM_TYPE_U64 =  0x8,
};

struct cycle_time_s {
	uint64_t numerator;
	uint64_t denominator;
};

struct base_time_s {
	uint64_t seconds;
	uint64_t nanoseconds;
};

void print_change(sr_change_oper_t oper, sr_val_t *val_old, sr_val_t *val_new);
void print_config_iter(sr_session_ctx_t *session, const char *path);
void init_tsn_mutex(void);
void destroy_tsn_mutex(void);
void init_tsn_socket(void);
void close_tsn_socket(void);
int errno2sp(int errtsn);
uint64_t cal_base_time(struct base_time_s *basetime);
uint64_t cal_cycle_time(struct cycle_time_s *cycletime);
void print_ev_type(sr_notif_event_t event);
void print_subtree_changes(sr_session_ctx_t *session, const char *path);
int str_to_num(int type, char *str, uint64_t *num);
void pri2num(char *pri_str, int8_t *pri_num);
#endif
