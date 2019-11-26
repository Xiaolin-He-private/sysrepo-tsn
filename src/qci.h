/**
 * @file qci.h
 * @author Xiaolin He
 * @brief header file for qci_xxx.c.
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

#ifndef __QCI_H_
#define __QCI_H_

#include <tsn/genl_tsn.h>
#include "common.h"

#define QCISFSG_MODULE_NAME "ieee802-dot1q-stream-filters-gates"
#define QCIPSFP_MODULE_NAME "ieee802-dot1q-psfp"
#define QCISF_XPATH "/ieee802-dot1q-stream-filters-gates:stream-filters"
#define QCISG_XPATH "/ieee802-dot1q-stream-filters-gates:stream-gates"
#define QCIFM_XPATH "/ieee802-dot1q-psfp:flow-meters"
#define SFI_XPATH (QCISF_XPATH "/stream-filter-instance-table")
#define SGI_XPATH (QCISG_XPATH "/stream-gate-instance-table")
#define FMI_XPATH (QCIFM_XPATH "/flow-meter-instance-table")

struct std_sf {
	uint32_t sf_id;
	bool enable;
	struct tsn_qci_psfp_sfi_conf sfconf;
};

struct std_sf_table {
	char port[IF_NAME_MAX_LEN];
	struct std_sf *sf_ptr;
	enum apply_status apply_st;
	struct std_fm_table *pre;
	struct std_sf_table *next;
};

struct std_sg {
	uint32_t sg_handle;
	uint32_t sg_id;
	bool enable;
	struct cycle_time_s cycletime;
	bool cycletime_f;
	struct base_time_s basetime;
	bool basetime_f;
	struct tsn_qci_psfp_sgi_conf sgconf;
};

struct std_sg_table {
	char port[IF_NAME_MAX_LEN];
	struct std_sg *sg_ptr;
	enum apply_status apply_st;
	struct std_fm_table *pre;
	struct std_sg_table *next;
};

struct std_fm {
	uint32_t fm_id;
	bool enable;
	struct tsn_qci_psfp_fmi fmconf;
};

struct std_fm_table {
	char port[IF_NAME_MAX_LEN];
	struct std_fm *fm_ptr;
	enum apply_status apply_st;
	struct std_fm_table *pre;
	struct std_fm_table *next;
};

int qci_sf_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx);
int qci_sg_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx);
int qci_fm_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx);

#endif
