/**
 * @file qci_sf.c
 * @author Xiaolin He
 * @brief Implementation of Stream Filter function based on sysrepo
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

struct std_sf_table *new_sf_table(void)
{
	struct std_sf_table *sf_table_ptr;
	struct std_sf *sf_ptr;

	sf_table_ptr = calloc(1, sizeof(struct std_sf_table));
	if (!sf_table_ptr)
		return sf_table_ptr;

	sf_ptr = calloc(1, sizeof(struct std_sf));
	if (!sf_ptr) {
		free(sf_table_ptr);
		return NULL;
	}

	sf_table_ptr->sf_ptr = sf_ptr;
	sf_table_ptr->apply_st = APPLY_NONE;
	sf_table_ptr->next = NULL;
	sf_ptr->sfconf.stream_handle_spec = -1;
	sf_ptr->sfconf.priority_spec = -1;
	sf_ptr->sfconf.stream_filter.flow_meter_instance_id = -1;
	printf("%p is calloced", (void *)sf_table_ptr);
	printf("%p is calloced", (void *)sf_ptr);
	return sf_table_ptr;
}

void free_sf_table(struct std_sf_table *sf_table)
{
	struct std_sf_table *tmp_table = sf_table;
	struct std_sf_table *next_table;

	while (tmp_table) {
		next_table = tmp_table->next;
		printf("%p is freed\n", (void *)tmp_table);
		printf("%p is freed\n", (void *)tmp_table->sf_ptr);
		if (tmp_table->sf_ptr)
			free(tmp_table->sf_ptr);
		free(tmp_table);
		tmp_table = next_table;
	}
}

void clr_qci_sf(sr_session_ctx_t *session, sr_val_t *value,
		struct std_sf *sfi)
{
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename;

	printf("%s was called\n", __func__);
	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		return;

	if (!strcmp(nodename, "stream-filter-enabled")) {
		sfi->enable = false;
	} else if (!strcmp(nodename, "stream-filter-instance-id")) {
		sfi->sf_id = 0;
	} else if (!strcmp(nodename, "wildcard")) {
		sfi->sfconf.stream_handle_spec = -1;
	} else if (!strcmp(nodename, "stream-handle")) {
		sfi->sfconf.stream_handle_spec = -1;
	} else if (!strcmp(nodename, "")) {
		sfi->sfconf.priority_spec = -1;
	} else if (!strcmp(nodename, "stream-gate-ref")) {
		sfi->sfconf.stream_gate_instance_id = 0;
	} else if (!strcmp(nodename, "maximum-sdu-size")) {
		sfi->sfconf.stream_filter.maximum_sdu_size = 0;
	} else if (!strcmp(nodename,
			   "stream-blocked-due-to-oversize-frame-enabled")) {
		sfi->sfconf.block_oversize_enable = 0;
	} else if (!strcmp(nodename, "flow-meter-ref")) {
		sfi->sfconf.stream_filter.flow_meter_instance_id = -1;
	}
}

int parse_qci_sf(sr_session_ctx_t *session, sr_val_t *value,
		struct std_sf *sfi)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	uint32_t u32_val = 0;
	uint64_t u64_val = 0;
	char *nodename;
	char *index;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto out;

	printf("%s was called\n", __func__);
	if (!strcmp(nodename, "stream-filter-enabled")) {
		sfi->enable = value->data.bool_val;
	} else if (!strcmp(nodename, "stream-filter-instance-id")) {
		sfi->sf_id = value->data.uint32_val;
		printf("sf id is: %u\n", sfi->sf_id);
	} else if (!strcmp(nodename, "wildcard")) {
		sfi->sfconf.stream_handle_spec = -1;
		printf("sf id is: %d\n", sfi->sf_id);
	} else if (!strcmp(nodename, "stream-handle")) {
		sfi->sfconf.stream_handle_spec = value->data.int32_val;
		printf("sf id is: %d\n", sfi->sf_id);
	} else if (!strcmp(nodename, "priority-spec")) {
		pri2num(value->data.enum_val, &sfi->sfconf.priority_spec);
		printf("sf pri-spec is: %d\n", sfi->sfconf.priority_spec);
	} else if (!strcmp(nodename, "stream-gate-ref")) {
		sfi->sfconf.stream_gate_instance_id = value->data.uint32_val;
		printf("sf sgref is: %u\n",
		       sfi->sfconf.stream_gate_instance_id);
	} else if (!strcmp(nodename, "maximum-sdu-size")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "filter-specification-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		if (u64_val)
			goto out;
		/* Only use parameters in the first list */
		u32_val = value->data.uint32_val;
		sfi->sfconf.stream_filter.maximum_sdu_size = u32_val;
	} else if (!strcmp(nodename,
			   "stream-blocked-due-to-oversize-frame-enabled")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "filter-specification-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		if (u64_val)
			goto out;
		/* Only use parameters in the first list */
		sfi->sfconf.block_oversize_enable = value->data.bool_val;
	} else if (!strcmp(nodename, "flow-meter-ref")) {
		sr_xpath_recover(&xp_ctx);
		index = sr_xpath_key_value(value->xpath,
					   "filter-specification-list",
					   "index", &xp_ctx);
		u64_val = strtoul(index, NULL, 0);
		if (u64_val)
			goto out;
		u32_val = value->data.uint32_val;
		sfi->sfconf.stream_filter.flow_meter_instance_id = u32_val;
	}

out:
	return rc;
}

int config_sf_per_port(sr_session_ctx_t *session, const char *path, bool abort,
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
	struct std_sf_table *sf_table = NULL;
	struct std_sf_table *pre_table = NULL;
	struct std_sf_table *cur_table = NULL;
	char *nodename;
	char *sf_id;
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

	/* Count all stream-filter-instance-tables */
	printf("get %lu items in :%s\n", count, path);
	for (i = 0; i < count; i++) {
		nodename = sr_xpath_node_name(values[i].xpath);
		if (!strncmp(nodename, "stream-filter-instance-table", 28)) {
			table_cnt++;
			sr_print_val(&values[i]);
			cur_table = new_sf_table();
			if (!cur_table) {
				snprintf(err_msg, MSG_MAX_LEN,
					 "Create new sf table failed");
				sr_set_error(session, err_msg, path);

				printf("Create new sf table failed\n");
				return SR_ERR_NOMEM;
			}
			sf_id = sr_xpath_key_value(values[i].xpath,
						   "stream-filter-instance-table",
						   "stream-filter-instance-id",
						   &xp_ctx);
			if (!sf_id)
				goto cleanup;
			cur_table->sf_ptr->sf_id = strtoul(sf_id, NULL, 0);
			if (table_cnt == 1) {
				sf_table = cur_table;
				pre_table = cur_table;
			} else {
				pre_table->next = cur_table;
			}
		}
	}

	if (!table_cnt) {
		printf("No stream-filter-instance-table configuration\n");
		return SR_ERR_OK;
	}
	printf("find %d tables\n", table_cnt);

	cur_table = sf_table;
	for (i = 0; i < table_cnt; i++) {
		if (!cur_table) {
			printf("current table in null\n");
			goto cleanup;
		} else {
			printf("current table in ok\n");
		}
		snprintf(xpath, XPATH_MAX_LEN,
			 "%s[name='%s']%s[stream-filter-instance-id='%u']//*",
			 BRIDGE_COMPONENT_XPATH, cpname,
			 SFI_XPATH, cur_table->sf_ptr->sf_id);
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

			if (!parse_qci_sf(session, &values[j],
					       cur_table->sf_ptr))
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
					if (!old_value)
						continue;

					clr_qci_sf(session,
						   old_value,
						   cur_table->sf_ptr);
				}
				parse_qci_sf(session, new_value,
						  cur_table->sf_ptr);
			}
			if (rc == SR_ERR_NOT_FOUND)
				rc = SR_ERR_OK;
		}
		cur_table = cur_table->next;
	}
	if (!para)
		goto cleanup;

	init_tsn_socket();
	cur_table = sf_table;
	while (cur_table != NULL) {
		printf("start set sf via libtsn\n");
		/* set new stream filters configuration */
		rc = tsn_qci_psfp_sfi_set(cpname, cur_table->sf_ptr->sf_id,
					 cur_table->sf_ptr->enable,
					 &(cur_table->sf_ptr->sfconf));
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
	free_sf_table(sf_table);
	sr_free_values(values, count);

	return rc;
}

int qci_sf_config(sr_session_ctx_t *session, const char *path, bool abort)
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
			rc = config_sf_per_port(session, xpath, abort,
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

int qci_sf_subtree_change_cb(sr_session_ctx_t *session, const char *path,
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
		rc = qci_sf_config(session, xpath, false);
		break;
	case SR_EV_ENABLED:
		rc = qci_sf_config(session, xpath, false);
		break;
	case SR_EV_APPLY:
		break;
	case SR_EV_ABORT:
		rc = qci_sf_config(session, xpath, true);
		break;
	default:
		break;
	}

	return rc;
}

