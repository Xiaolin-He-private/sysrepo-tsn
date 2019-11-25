/**
 * @file qci_sg.c
 * @author Xiaolin He
 * @brief Implementation of Stream Gate function based on sysrepo
 * datastore.
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
#include <arpa/inet.h>
#include <cjson/cJSON.h>

#include "common.h"
#include "main.h"
#include "qci.h"

struct std_sg_table *new_sg_table(void)
{
	struct std_sg_table *sg_table_ptr;
	struct std_sg *sg_ptr;

	sg_table_ptr = calloc(1, sizeof(struct std_sg_table));
	if (!sg_table_ptr)
		return sg_table_ptr;

	sg_ptr = calloc(1, sizeof(struct std_sg));
	if (!sg_ptr) {
		free(sg_table_ptr);
		return NULL;
	}

	sg_ptr->sgconf.admin.gcl = malloc(MAX_ENTRY_SIZE);
	if (!sg_ptr->sgconf.admin.gcl) {
		free(sg_table_ptr);
		free(sg_ptr);
		return NULL;
	}

	sg_table_ptr->sg_ptr = sg_ptr;
	sg_table_ptr->apply_st = APPLY_NONE;
	sg_table_ptr->next = NULL;
	sg_ptr->sgconf.admin.init_ipv = -1;
	printf("%p is calloced\n", (void *)sg_table_ptr);
	printf("%p is calloced\n", (void *)sg_ptr);
	printf("%p is calloced\n", (void *)sg_ptr->sgconf.admin.gcl);
	return sg_table_ptr;
}

void free_sg_table(struct std_sg_table *sg_table)
{
	struct std_sg_table *tmp_table = sg_table;
	struct std_sg_table *next_table;

	while (tmp_table) {
		next_table = tmp_table->next;
		printf("%p is freed\n", (void *)tmp_table);
		printf("%p is freed\n", (void *)tmp_table->sg_ptr);
		printf("%p is freed",
		       (void *)tmp_table->sg_ptr->sgconf.admin.gcl);
		if (tmp_table->sg_ptr) {
			if (tmp_table->sg_ptr->sgconf.admin.gcl)
				free(tmp_table->sg_ptr->sgconf.admin.gcl);
			free(tmp_table->sg_ptr);
		}
		free(tmp_table);
		tmp_table = next_table;
	}
}

void clr_qci_sg(sr_session_ctx_t *session, sr_val_t *value,
		struct std_sg *sgi)
{
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename;
	char *index;
	uint64_t u64_val;
	struct tsn_qci_psfp_gcl *entry = sgi->sgconf.admin.gcl;

	printf("%s was called\n", __func__);
	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		return;

	if (!strcmp(nodename, "gate-enable")) {
		sgi->enable = false;
	} else if (!strcmp(nodename, "stream-gate-instance-id")) {
		sgi->sg_handle = 0;
	} else if (!strcmp(nodename, "admin-gate-states")) {
		sgi->sgconf.admin.gate_states = false;
	} else if (!strcmp(nodename, "admin-ipv")) {
		sgi->sgconf.admin.init_ipv = -1;
	} else if (!strcmp(nodename, "admin-control-list-length")) {
		sgi->sgconf.admin.control_list_length = 0;
	} else if (!strcmp(nodename, "gate-state-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);

		(entry + u64_val)->gate_state = false;
	} else if (!strcmp(nodename, "ipv-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);

		(entry + u64_val)->ipv = -1;
	} else if (!strcmp(nodename, "time-interval-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);

		(entry + u64_val)->time_interval = 0;
	} else if (!strcmp(nodename, "interval-octet-max")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);

		(entry + u64_val)->octet_max = 0;
	} else if (!strcmp(nodename, "numerator")) {
		sgi->cycletime.numerator = 0;
	} else if (!strcmp(nodename, "denominator")) {
		sgi->cycletime.denominator = 0;
		sgi->cycletime_f = false;
	} else if (!strcmp(nodename, "seconds")) {
		sgi->basetime.seconds = 0;
	} else if (!strcmp(nodename, "nanoseconds")) {
		sgi->basetime.nanoseconds = 0;
		sgi->basetime_f = false;
	} else if (!strcmp(nodename, "admin-cycle-time-extension")) {
		sgi->sgconf.admin.cycle_time_extension = 0;
	} else if (!strcmp(nodename, "config-change")) {
		sgi->sgconf.config_change = false;
	} else if (!strcmp(nodename, "gate-closed-due-to-invalid-rx-enable")) {
		sgi->sgconf.block_invalid_rx_enable = false;
	} else if (!strcmp(nodename, "gate-closed-due-to-invalid-rx")) {
		sgi->sgconf.block_invalid_rx = false;
	} else if (!strcmp(nodename,
			   "gate-closed-due-octets-exceeded-enable")) {
		sgi->sgconf.block_octets_exceeded_enable = value->data.bool_val;
	} else if (!strcmp(nodename, "")) {
		sgi->sgconf.block_octets_exceeded = false;
	}
}

int parse_qci_sg(sr_session_ctx_t *session, sr_val_t *value,
		struct std_sg *sgi)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	uint8_t u8_val = 0;
	uint64_t u64_val = 0;
	char *nodename;
	char *num_str;
	char *index;
	char err_msg[MSG_MAX_LEN] = {0};
	struct tsn_qci_psfp_gcl *entry = sgi->sgconf.admin.gcl;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto out;

	printf("%s was called\n", __func__);
	if (!strcmp(nodename, "gate-enable")) {
		sgi->enable = value->data.bool_val;
		printf("sg enabled is: %d\n", sgi->enable);
	} else if (!strcmp(nodename, "stream-gate-instance-id")) {
		sgi->sg_handle = value->data.uint32_val;
		printf("sg handle is: %u\n", sgi->sg_handle);
	} else if (!strcmp(nodename, "admin-gate-states")) {
		num_str = value->data.enum_val;
		if (!strcmp(num_str, "open")) {
			sgi->sgconf.admin.gate_states = true;
		} else if (!strcmp(num_str, "closed")) {
			sgi->sgconf.admin.gate_states = false;
		} else {
			snprintf(err_msg, MSG_MAX_LEN, "Invalid '%s'", num_str);
			sr_set_error(session, err_msg, value->xpath);

			printf("ERROR: Invalid '%s' in %s!\n", num_str,
			       value->xpath);
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
		printf("sg admin-gate-states is: %d\n",
		       sgi->sgconf.admin.gate_states);
	} else if (!strcmp(nodename, "admin-ipv")) {
		pri2num(value->data.enum_val, &sgi->sgconf.admin.init_ipv);
		printf("admin priority is: %d\n", sgi->sgconf.admin.init_ipv);
	} else if (!strcmp(nodename, "admin-control-list-length")) {
		u8_val = (uint8_t)value->data.int32_val;
		sgi->sgconf.admin.control_list_length = u8_val;
		printf("admin priority is: %u\n",
		       sgi->sgconf.admin.control_list_length);
	} else if (!strcmp(nodename, "gate-state-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		if (u64_val >= sgi->sgconf.admin.control_list_length)
			goto out;

		num_str = value->data.enum_val;
		if (!strcmp(num_str, "open")) {
			(entry + u64_val)->gate_state = true;
		} else if (!strcmp(num_str, "closed")) {
			(entry + u64_val)->gate_state = false;
		} else {
			snprintf(err_msg, MSG_MAX_LEN, "Invalid '%s'", num_str);
			sr_set_error(session, err_msg, value->xpath);

			printf("ERROR: Invalid '%s' in %s!\n", num_str,
			       value->xpath);
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
		printf("index %llu gate-states is: %d\n", u64_val,
		       (entry + u64_val)->gate_state);
	} else if (!strcmp(nodename, "ipv-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		if (u64_val >= sgi->sgconf.admin.control_list_length)
			goto out;

		pri2num(value->data.enum_val, &(entry + u64_val)->ipv);
		printf("index %llu ipv is: %d\n", u64_val,
		       (entry + u64_val)->ipv);
	} else if (!strcmp(nodename, "time-interval-value")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		if (u64_val >= sgi->sgconf.admin.control_list_length)
			goto out;

		(entry + u64_val)->time_interval = value->data.uint32_val;
		printf("index %llu ipv is: %u\n", u64_val,
		       (entry + u64_val)->time_interval);
	} else if (!strcmp(nodename, "interval-octet-max")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "admin-control-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		if (u64_val >= sgi->sgconf.admin.control_list_length)
			goto out;

		(entry + u64_val)->octet_max = value->data.uint32_val;
		printf("index %llu ipv is: %u\n", u64_val,
		       (entry + u64_val)->octet_max);
	} else if (!strcmp(nodename, "numerator")) {
		sgi->cycletime.numerator = value->data.uint32_val;
	} else if (!strcmp(nodename, "denominator")) {
		sgi->cycletime.denominator = value->data.uint32_val;
		if (!sgi->cycletime.denominator) {
			snprintf(err_msg, MSG_MAX_LEN,
				 "The value of %s is zero", value->xpath);
			sr_set_error(session, err_msg, value->xpath);

			printf("ERROR: denominator is zero!\n");
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
		sgi->cycletime_f = true;
	} else if (!strcmp(nodename, "seconds")) {
		sgi->basetime.seconds = value->data.uint64_val;
	} else if (!strcmp(nodename, "nanoseconds")) {
		sgi->basetime.nanoseconds = (uint64_t)value->data.uint32_val;
		if (!sgi->basetime.nanoseconds) {
			snprintf(err_msg, MSG_MAX_LEN,
				 "The value of %s is zero", value->xpath);
			sr_set_error(session, err_msg, value->xpath);

			printf("ERROR: nanoseconds is zero!\n");
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
		sgi->basetime_f = true;
	} else if (!strcmp(nodename, "admin-cycle-time-extension")) {
		sgi->sgconf.admin.cycle_time_extension = value->data.int32_val;
	} else if (!strcmp(nodename, "config-change")) {
		sgi->sgconf.config_change = value->data.bool_val;
	} else if (!strcmp(nodename, "gate-closed-due-to-invalid-rx-enable")) {
		sgi->sgconf.block_invalid_rx_enable = value->data.bool_val;
	} else if (!strcmp(nodename, "gate-closed-due-to-invalid-rx")) {
		sgi->sgconf.block_invalid_rx = value->data.bool_val;
	} else if (!strcmp(nodename,
			   "gate-closed-due-octets-exceeded-enable")) {
		sgi->sgconf.block_octets_exceeded_enable = value->data.bool_val;
	} else if (!strcmp(nodename, "")) {
		sgi->sgconf.block_octets_exceeded = value->data.bool_val;
	}

out:
	return rc;
}

int config_sg_per_port(sr_session_ctx_t *session, const char *path, bool abort,
		char *cpname)
{
	int rc = SR_ERR_OK;
	sr_change_iter_t *it;
	sr_xpath_ctx_t xp_ctx = {0};
	sr_change_oper_t oper;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_val_t *values;
	size_t count;
	size_t i;
	size_t j;
	int para = 0;
	char err_msg[MSG_MAX_LEN] = {0};
	struct std_sg_table *sg_table = NULL;
	struct std_sg_table *pre_table = NULL;
	struct std_sg_table *cur_table = NULL;
	char *nodename;
	char *sg_id;
	int table_cnt = 0;
	char xpath[XPATH_MAX_LEN] = {0,};

	printf("%s is called\n", __func__);

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

	/* Count all stream-gate-instance-tables */
	printf("get %lu items in :%s\n", count, path);
	for (i = 0; i < count; i++) {
		nodename = sr_xpath_node_name(values[i].xpath);
		if (!strncmp(nodename, "stream-gate-instance-table", 26)) {
			table_cnt++;
			sr_print_val(&values[i]);
			cur_table = new_sg_table();
			if (!cur_table) {
				snprintf(err_msg, MSG_MAX_LEN,
					 "Create new sg table failed");
				sr_set_error(session, err_msg, path);

				printf("Create new sg table failed\n");
				return SR_ERR_NOMEM;
			}
			sg_id = sr_xpath_key_value(values[i].xpath,
						   "stream-gate-instance-table",
						   "stream-gate-instance-id",
						   &xp_ctx);
			if (!sg_id)
				goto cleanup;
			cur_table->sg_ptr->sg_id = strtoul(sg_id, NULL, 0);
			if (table_cnt == 1) {
				sg_table = cur_table;
				pre_table = cur_table;
			} else {
				pre_table->next = cur_table;
			}
		}
	}

	if (!table_cnt) {
		printf("No stream-gate-instance-table configuration\n");
		return SR_ERR_OK;
	}
	printf("find %d tables\n", table_cnt);

	cur_table = sg_table;
	for (i = 0; i < table_cnt; i++) {
		if (!cur_table) {
			printf("current table in null\n");
			goto cleanup;
		} else {
			printf("current table in ok\n");
		}
		snprintf(xpath, XPATH_MAX_LEN,
			 "%s[name='%s']%s[stream-gate-instance-id='%u']//*",
			 BRIDGE_COMPONENT_XPATH, cpname,
			 SGI_XPATH, cur_table->sg_ptr->sg_id);
		sr_free_values(values, count);
		rc = sr_get_items(session, xpath, &values, &count);
		if (rc != SR_ERR_OK) {
			if (rc != SR_ERR_NOT_FOUND) {
				snprintf(err_msg, MSG_MAX_LEN,
					 "Get items from %s failed", xpath);
				sr_set_error(session, err_msg, xpath);
			}
			printf("ERROR: %s sr_get_items: %s\n", __func__,
			       sr_strerror(rc));

			goto cleanup;
		}
		printf("get %lu items in :%s\n", count, xpath);
		for (j = 0; j < count; j++) {
			if (values[j].type == SR_LIST_T
			    || values[j].type == SR_CONTAINER_PRESENCE_T)
				continue;

			if (!parse_qci_sg(session, &values[j],
					       cur_table->sg_ptr))
				para++;
		}
		printf("parse configuration ok\n");
		if (abort) {
			rc = sr_get_changes_iter(session, path, &it);
			if (rc != SR_ERR_OK) {
				snprintf(err_msg, MSG_MAX_LEN,
					 "Get changes from %s failed", path);
				sr_set_error(session, err_msg, path);

				printf("ERROR: Get changes from %s failed\n",
				       path);
				goto cleanup;
			}
			while (SR_ERR_OK == (rc = sr_get_change_next(session,
							it, &oper, &old_value,
							&new_value))) {
				if (oper == SR_OP_DELETED) {
					if (old_value)
						continue;

					clr_qci_sg(session,
						   old_value,
						   cur_table->sg_ptr);
				}
				parse_qci_sg(session, new_value,
						  cur_table->sg_ptr);
			}
			if (rc == SR_ERR_NOT_FOUND)
				rc = SR_ERR_OK;
		}
		cur_table = cur_table->next;
	}
	if (!para)
		goto cleanup;

	init_tsn_socket();
	cur_table = sg_table;
	while (cur_table != NULL) {
		printf("start set sg via libtsn\n");
		/* set new stream filters configuration */
		rc = tsn_qci_psfp_sgi_set(cpname, cur_table->sg_ptr->sg_handle,
					 cur_table->sg_ptr->enable,
					 &(cur_table->sg_ptr->sgconf));
		if (rc != EXIT_SUCCESS) {
			sprintf(err_msg,
				"failed to set stream filter, %s!",
				strerror(-rc));
			goto cleanup;
		}
		if (cur_table->next == NULL)
			break;
		cur_table = cur_table->next;
	}

cleanup:
	close_tsn_socket();
	free_sg_table(sg_table);
	sr_free_values(values, count);

	return rc;
}

int qci_sg_config(sr_session_ctx_t *session, const char *path, bool abort)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	sr_change_iter_t *it;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_val_t *value;
	sr_change_oper_t oper;
	char *cpname;
	char cpname_bak[IF_NAME_MAX_LEN] = {0,};
	char xpath[XPATH_MAX_LEN] = {0,};
	char err_msg[MSG_MAX_LEN] = {0};

	printf("%s was called\n", __func__);
	rc = sr_get_changes_iter(session, path, &it);
	if (rc != SR_ERR_OK) {
		snprintf(err_msg, MSG_MAX_LEN,
			 "Get changes from %s failed", path);
		sr_set_error(session, err_msg, path);

		printf("ERROR: %s sr_get_changes_iter: %s", __func__,
		       sr_strerror(rc));
		goto cleanup;
	}

	printf("get chages ok\n");
	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
					&oper, &old_value, &new_value))) {
		value = new_value ? new_value : old_value;
		cpname = sr_xpath_key_value(value->xpath, "component",
					    "name", &xp_ctx);
		if (!cpname)
			continue;

		if (strcmp(cpname, cpname_bak)) {
			snprintf(cpname_bak, IF_NAME_MAX_LEN, cpname);
			snprintf(xpath, XPATH_MAX_LEN, "%s[name='%s']%s://*",
				 BRIDGE_COMPONENT_XPATH, cpname,
				 QCISF_XPATH);
			rc = config_sg_per_port(session, xpath, abort,
						      cpname);
			if (rc != SR_ERR_OK)
				break;
		}
	}
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;
cleanup:
	return rc;
}

int qci_sg_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

	printf("%s was called\n", __func__);
	snprintf(xpath, XPATH_MAX_LEN, "%s%s//*", BRIDGE_COMPONENT_XPATH,
		 QCISF_XPATH);
	print_ev_type(event);
	printf("xpath is :\n%s\n", xpath);
	switch (event) {
	case SR_EV_VERIFY:
		rc = qci_sg_config(session, xpath, false);
		break;
	case SR_EV_ENABLED:
		rc = qci_sg_config(session, xpath, false);
		break;
	case SR_EV_APPLY:
		break;
	case SR_EV_ABORT:
		rc = qci_sg_config(session, xpath, true);
		break;
	default:
		break;
	}

	return rc;
}

