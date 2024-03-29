/**
 * @file qbv.c
 * @author Xiaolin He
 * @brief Application to configure TSN-QBV function based on sysrepo datastore.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <cjson/cJSON.h>

#include "common.h"
#include "main.h"
#include "qbv.h"

struct tsn_qbv_conf *malloc_qbv_memory(void)
{
	struct tsn_qbv_conf *qbvconf_ptr;
	struct tsn_qbv_entry *qbv_entry;

	/* applying memory for qbv configuration data */
	qbvconf_ptr = (struct tsn_qbv_conf *)malloc(sizeof(struct tsn_qbv_conf));
	if (!qbvconf_ptr)
		return NULL;

	qbv_entry = (struct tsn_qbv_entry *)malloc(MAX_ENTRY_SIZE);
	if (!qbv_entry) {
		free(qbvconf_ptr);
		return NULL;
	}
	qbvconf_ptr->admin.control_list = qbv_entry;
	return qbvconf_ptr;
}

void init_qbv_memory(struct sr_qbv_conf *qbvconf)
{
	struct tsn_qbv_entry *qbv_entry = NULL;

	qbv_entry = qbvconf->qbvconf_ptr->admin.control_list;
	memset(qbv_entry, 0, MAX_ENTRY_SIZE);
	memset(qbvconf->qbvconf_ptr, 0, sizeof(struct tsn_qbv_conf));
	qbvconf->qbvconf_ptr->admin.control_list = qbv_entry;
	qbvconf->cycletime_f = false;
	qbvconf->basetime_f = false;
}

void free_qbv_memory(struct tsn_qbv_conf *qbvconf_ptr)
{
	free(qbvconf_ptr->admin.control_list);
	free(qbvconf_ptr);
}

int tsn_config_qbv(sr_session_ctx_t *session, char *ifname,
		struct sr_qbv_conf *qbvconf)
{
	int rc = SR_ERR_OK;
	uint64_t time;
	char xpath[XPATH_MAX_LEN] = {0};
	char err_msg[MSG_MAX_LEN] = {0};

	if (qbvconf->basetime_f) {
		time = cal_base_time(&qbvconf->basetime);
		qbvconf->qbvconf_ptr->admin.base_time = time;
	}
	if (qbvconf->cycletime_f) {
		time = cal_cycle_time(&qbvconf->cycletime);
		qbvconf->qbvconf_ptr->admin.cycle_time = time;
	}

	rc = tsn_qos_port_qbv_set(ifname, qbvconf->qbvconf_ptr,
				  qbvconf->qbv_en);

	if (rc < 0) {
		snprintf(xpath, XPATH_MAX_LEN, "%s[name='%s']/%s:*//*",
			 IF_XPATH, ifname, QBV_MODULE_NAME);
		snprintf(err_msg, MSG_MAX_LEN, "Set Qbv error: %s",
			 strerror(-rc));
		sr_set_error(session, err_msg, xpath);

		printf("ERROR: set qbv error, %s!\n", strerror(-rc));
		rc = errno2sp(-rc);
		goto out;
	}
out:
	return rc;
}

void clr_qbv(sr_val_t *value, struct sr_qbv_conf *qbvconf)
{
	sr_xpath_ctx_t xp_ctx = {0};
	char *index;
	char *nodename;
	struct tsn_qbv_entry *entry;
	uint64_t u64_val = 0;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		return;

	if (!strcmp(nodename, "gate-enabled")) {
		qbvconf->qbv_en = false;
	} else if (!strcmp(nodename, "admin-gate-states")) {
		qbvconf->qbvconf_ptr->admin.gate_states = 0;
	} else if (!strcmp(nodename, "admin-control-list-length")) {
		qbvconf->qbvconf_ptr->admin.control_list_length = 0;
	} else if (!strcmp(nodename, "gate-states-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		entry = qbvconf->qbvconf_ptr->admin.control_list;
		(entry + u64_val)->gate_state = 0;
	} else if (!strcmp(nodename, "time-interval-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		entry = qbvconf->qbvconf_ptr->admin.control_list;
		(entry + u64_val)->time_interval = 0;
	} else if (!strcmp(nodename, "numerator")) {
		qbvconf->cycletime.numerator = 0;
	} else if (!strcmp(nodename, "denominator")) {
		qbvconf->cycletime.denominator = 1;
		qbvconf->cycletime_f = true;
	} else if (!strcmp(nodename,
			   "admin-cycle-time-extension")) {
		qbvconf->qbvconf_ptr->admin.cycle_time_extension = 0;
	} else if (!strcmp(nodename, "seconds")) {
		qbvconf->basetime.seconds = 0;
	} else if (!strcmp(nodename, "fractional-seconds")) {
		qbvconf->basetime.nanoseconds = 0;
		qbvconf->basetime_f = true;
	} else if (!strcmp(nodename, "config-change")) {
		qbvconf->qbvconf_ptr->config_change = 0;
	} else if (!strcmp(nodename, "queue-max-sdu")) {
		sr_xpath_recover(&xp_ctx);
		if (strcmp("0",
			   sr_xpath_key_value(value->xpath,
					      "max-sdu-table",
					      "traffic-class",
					      &xp_ctx)))
			qbvconf->qbvconf_ptr->maxsdu = 0;
	}
}

int parse_qbv(sr_session_ctx_t *session, sr_val_t *value,
		struct sr_qbv_conf *qbvconf)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	char *index = NULL;
	uint8_t u8_val = 0;
	uint32_t u32_val = 0;
	uint64_t u64_val = 0;
	char *nodename = NULL;
	struct tsn_qbv_entry *entry = NULL;
	char err_msg[MSG_MAX_LEN] = {0};

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto out;

	if (!strcmp(nodename, "gate-enabled")) {
		qbvconf->qbv_en = value->data.bool_val;
	} else if (!strcmp(nodename, "admin-gate-states")) {
		u8_val = value->data.uint8_val;
		qbvconf->qbvconf_ptr->admin.gate_states = u8_val;
	} else if (!strcmp(nodename, "admin-control-list-length")) {
		u32_val = value->data.uint32_val;
		qbvconf->qbvconf_ptr->admin.control_list_length = u32_val;
	} else if (!strcmp(nodename, "gate-states-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		if (u64_val >= qbvconf->qbvconf_ptr->admin.control_list_length)
			goto out;

		entry = qbvconf->qbvconf_ptr->admin.control_list;
		u8_val = value->data.uint8_val;
		(entry + u64_val)->gate_state = u8_val;
	} else if (!strcmp(nodename, "time-interval-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		if (u64_val >= qbvconf->qbvconf_ptr->admin.control_list_length)
			goto out;

		entry = qbvconf->qbvconf_ptr->admin.control_list;
		u32_val = value->data.uint32_val;
		(entry + u64_val)->time_interval = u32_val;
	} else if (!strcmp(nodename, "numerator")) {
		qbvconf->cycletime.numerator = value->data.uint32_val;
	} else if (!strcmp(nodename, "denominator")) {
		qbvconf->cycletime.denominator = value->data.uint32_val;
		if (!qbvconf->cycletime.denominator) {
			snprintf(err_msg, MSG_MAX_LEN,
				 "The value of %s is zero", value->xpath);
			sr_set_error(session, err_msg, value->xpath);

			printf("ERROR: denominator is zero!\n");
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
		qbvconf->cycletime_f = true;
	} else if (!strcmp(nodename,
			  "admin-cycle-time-extension")) {
		u32_val = value->data.uint32_val;
		qbvconf->qbvconf_ptr->admin.cycle_time_extension = u32_val;
	} else if (!strcmp(nodename, "seconds")) {
		qbvconf->basetime.seconds = value->data.uint64_val;
		qbvconf->basetime_f = true;
	} else if (!strcmp(nodename, "fractional-seconds")) {
		qbvconf->basetime.nanoseconds = value->data.uint64_val;
		qbvconf->basetime_f = true;
	} else if (!strcmp(nodename, "config-change")) {
		qbvconf->qbvconf_ptr->config_change = value->data.bool_val;
	} else if (!strcmp(nodename, "queue-max-sdu")) {
		sr_xpath_recover(&xp_ctx);
		if (strcmp("0",
			   sr_xpath_key_value(value->xpath,
					      "max-sdu-table",
					      "traffic-class",
					      &xp_ctx)))
			qbvconf->qbvconf_ptr->maxsdu = value->data.uint32_val;
	} else {
		rc = 1;
	}

out:
	return rc;
}

int config_qbv_per_port(sr_session_ctx_t *session, const char *path, bool abort,
		char *ifname)
{
	int rc = SR_ERR_OK;
	sr_change_iter_t *it;
	sr_change_oper_t oper;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_val_t *values;
	size_t count;
	size_t i;
	struct sr_qbv_conf qbvconf;
	int para = 0;
	char err_msg[MSG_MAX_LEN] = {0};

	qbvconf.qbvconf_ptr = malloc_qbv_memory();
	if (!qbvconf.qbvconf_ptr)
		return errno2sp(ENOMEM);

	init_qbv_memory(&qbvconf);

	rc = sr_get_items(session, path, &values, &count);
	if (rc != SR_ERR_OK) {
		if (rc != SR_ERR_NOT_FOUND) {
			snprintf(err_msg, MSG_MAX_LEN,
				 "Get items from %s failed", path);
			sr_set_error(session, err_msg, path);

			printf("ERROR: %s sr_get_items: %s\n", __func__,
			       sr_strerror(rc));
		}
		return rc;
	}

	init_tsn_socket();
	for (i = 0; i < count; i++) {
		if (values[i].type == SR_LIST_T
		    || values[i].type == SR_CONTAINER_PRESENCE_T)
			continue;

		if (!parse_qbv(session, &values[i], &qbvconf))
			para++;
	}
	if (!para)
		goto cleanup;

	if (abort) {
		rc = sr_get_changes_iter(session, path, &it);
		if (rc != SR_ERR_OK) {
			snprintf(err_msg, MSG_MAX_LEN,
				 "Get changes from %s failed", path);
			sr_set_error(session, err_msg, path);

			printf("ERROR: Get changes from %s failed\n", path);
			goto cleanup;
		}
		while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
						&oper, &old_value,
						&new_value))) {
			if (oper == SR_OP_DELETED) {
				if (old_value) {
					clr_qbv(old_value, &qbvconf);
					continue;
				} else {
					init_qbv_memory(&qbvconf);
				}
			}
			parse_qbv(session, new_value, &qbvconf);
		}
		if (rc == SR_ERR_NOT_FOUND)
			rc = SR_ERR_OK;
	}
	rc = tsn_config_qbv(session, ifname, &qbvconf);

cleanup:
	close_tsn_socket();
	free_qbv_memory(qbvconf.qbvconf_ptr);
	sr_free_values(values, count);

	return rc;
}

int qbv_config(sr_session_ctx_t *session, const char *path, bool abort)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	sr_change_iter_t *it;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_val_t *value;
	sr_change_oper_t oper;
	char *ifname;
	char ifname_bak[IF_NAME_MAX_LEN] = {0,};
	char xpath[XPATH_MAX_LEN] = {0,};
	char err_msg[MSG_MAX_LEN] = {0};

	rc = sr_get_changes_iter(session, path, &it);
	if (rc != SR_ERR_OK) {
		snprintf(err_msg, MSG_MAX_LEN,
			 "Get changes from %s failed", path);
		sr_set_error(session, err_msg, path);

		printf("ERROR: %s sr_get_changes_iter: %s\n", __func__,
		       sr_strerror(rc));
		goto cleanup;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
					&oper, &old_value, &new_value))) {
		value = new_value ? new_value : old_value;
		ifname = sr_xpath_key_value(value->xpath, "interface",
					    "name", &xp_ctx);
		if (!ifname)
			continue;

		if (strcmp(ifname, ifname_bak)) {
			snprintf(ifname_bak, IF_NAME_MAX_LEN, ifname);
			snprintf(xpath, XPATH_MAX_LEN,
				 "%s[name='%s']/%s:*//*", IF_XPATH, ifname,
				 QBV_MODULE_NAME);
			rc = config_qbv_per_port(session, xpath, abort, ifname);
			if (rc != SR_ERR_OK)
				break;
		}
	}
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;
cleanup:
	return rc;
}

int qbv_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

	/* Only process called by gate-parameters is enough */
	if (sr_xpath_node_name_eq(path, "ieee802-dot1q-sched:max-sdu-table"))
		return rc;

	snprintf(xpath, XPATH_MAX_LEN, "%s/%s:*//*", IF_XPATH,
		 QBV_MODULE_NAME);
	switch (event) {
	case SR_EV_VERIFY:
		if (rc)
			goto out;
		rc = qbv_config(session, xpath, false);
		break;
	case SR_EV_ENABLED:
		rc = qbv_config(session, xpath, false);
		break;
	case SR_EV_APPLY:
		break;
	case SR_EV_ABORT:
		rc = qbv_config(session, xpath, true);
		break;
	default:
		break;
	}
out:
	return rc;
}

