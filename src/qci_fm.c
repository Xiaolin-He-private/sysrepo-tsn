/**
 * @file qci_fm.c
 * @author Xiaolin He
 * @brief Implementation of Flow meter function based on sysrepo
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

struct std_fm_table *new_fm_table(void)
{
	struct std_fm_table *fm_table_ptr;
	struct std_fm *fm_ptr;

	fm_table_ptr = calloc(1, sizeof(struct std_fm_table));
	if (!fm_table_ptr)
		return fm_table_ptr;

	fm_ptr = calloc(1, sizeof(struct std_fm));
	if (!fm_ptr) {
		free(fm_table_ptr);
		return NULL;
	}

	fm_table_ptr->fm_ptr = fm_ptr;
	fm_table_ptr->apply_st = APPLY_NONE;
	fm_table_ptr->next = NULL;
	printf("%p is calloced\n", (void *)fm_table_ptr);
	printf("%p is calloced\n", (void *)fm_ptr);
	return fm_table_ptr;
}

void free_fm_table(struct std_fm_table *fm_table)
{
	struct std_fm_table *tmp_table = fm_table;
	struct std_fm_table *next_table;

	while (tmp_table) {
		next_table = tmp_table->next;
		printf("%p is freed\n", (void *)tmp_table);
		printf("%p is freed\n", (void *)tmp_table->fm_ptr);
		if (tmp_table->fm_ptr)
			free(tmp_table->fm_ptr);
		free(tmp_table);
		tmp_table = next_table;
	}
}

void clr_qci_fm(sr_session_ctx_t *session, sr_val_t *value,
		struct std_fm *fmi)
{
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename;

	printf("%s was called\n", __func__);
	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		return;

	if (!strcmp(nodename, "flow-meter-enabled"))
		fmi->enable = false;
	else if (!strcmp(nodename, "committed-information-rate"))
		fmi->fmconf.cir = 0;
	else if (!strcmp(nodename, "committed-burst-size"))
		fmi->fmconf.cbs = 0;
	else if (!strcmp(nodename, "excess-information-rate"))
		fmi->fmconf.eir = 0;
	else if (!strcmp(nodename, "excess-burst-size"))
		fmi->fmconf.ebs = 0;
	else if (!strcmp(nodename, "coupling-flag"))
		fmi->fmconf.cf = false;
	else if (!strcmp(nodename, "color-mode"))
		fmi->fmconf.cm = false;
	else if (!strcmp(nodename, "drop-on-yellow"))
		fmi->fmconf.drop_on_yellow  = false;
	else if (!strcmp(nodename, "mark-all-frames-red-enable"))
		fmi->fmconf.mark_red_enable = false;
}

int parse_qci_fm(sr_session_ctx_t *session, sr_val_t *value,
		struct std_fm *fmi)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename;
	char *num_str;
	char err_msg[MSG_MAX_LEN] = {0};

	printf("%s was called\n", __func__);
	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto out;

	if (!strcmp(nodename, "flow-meter-enabled")) {
		fmi->enable = value->data.bool_val;
		printf("fm enabled is: %d\n", fmi->enable);
	} else if (!strcmp(nodename, "committed-information-rate")) {
		fmi->fmconf.cir = value->data.uint64_val;
		printf("fmi cir is: %u\n", fmi->fmconf.cir);
	} else if (!strcmp(nodename, "committed-burst-size")) {
		fmi->fmconf.cbs = value->data.uint32_val;
		printf("fmi cbs is: %u\n", fmi->fmconf.cbs);
	} else if (!strcmp(nodename, "excess-information-rate")) {
		fmi->fmconf.eir = value->data.uint64_val;
		printf("fmi cir is: %u\n", fmi->fmconf.eir);
	} else if (!strcmp(nodename, "excess-burst-size")) {
		fmi->fmconf.ebs = value->data.uint32_val;
		printf("fmi ebs is: %u\n", fmi->fmconf.ebs);
	} else if (!strcmp(nodename, "coupling-flag")) {
		num_str = value->data.enum_val;
		if (!strcmp(num_str, "zero")) {
			fmi->fmconf.cf = false;
			printf("fmi cf is zero\n");
		} else if (!strcmp(num_str, "one")) {
			fmi->fmconf.cf = true;
			printf("fmi cf is one\n");
		} else {
			snprintf(err_msg, MSG_MAX_LEN, "Invalid '%s'", num_str);
			sr_set_error(session, err_msg, value->xpath);

			printf("ERROR: Invalid '%s' in %s!\n", num_str,
			       value->xpath);
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
	} else if (!strcmp(nodename, "color-mode")) {
		num_str = value->data.enum_val;
		if (!strcmp(num_str, "color-blind")) {
			fmi->fmconf.cm = false;
			printf("fmi cf is zero\n");
		} else if (!strcmp(num_str, "color-aware")) {
			fmi->fmconf.cm = true;
			printf("fmi cf is one\n");
		} else {
			snprintf(err_msg, MSG_MAX_LEN, "Invalid '%s'", num_str);
			sr_set_error(session, err_msg, value->xpath);

			printf("ERROR: Invalid '%s' in %s!\n", num_str,
			       value->xpath);
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
	} else if (!strcmp(nodename, "drop-on-yellow")) {
		fmi->fmconf.drop_on_yellow  = value->data.bool_val;
		printf("fmi drop-on-yellow is %d\n",
		       fmi->fmconf.drop_on_yellow);
	} else if (!strcmp(nodename, "mark-all-frames-red-enable")) {
		fmi->fmconf.mark_red_enable = value->data.bool_val;
		printf("fmi mark_red_enable is %d\n",
		       fmi->fmconf.mark_red_enable);
	}

out:
	return rc;
}

int config_fm_per_port(sr_session_ctx_t *session, const char *path, bool abort,
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
	char err_mfm[MSG_MAX_LEN] = {0};
	struct std_fm_table *fm_table = NULL;
	struct std_fm_table *pre_table = NULL;
	struct std_fm_table *cur_table = NULL;
	char *nodename;
	char *fm_id;
	int table_cnt = 0;
	char xpath[XPATH_MAX_LEN] = {0,};

	printf("%s is called\n", __func__);

	rc = sr_get_items(session, path, &values, &count);
	if (rc != SR_ERR_OK) {
		if (rc != SR_ERR_NOT_FOUND) {
			snprintf(err_mfm, MSG_MAX_LEN,
				 "Get items from %s failed", path);
			sr_set_error(session, err_mfm, path);

			printf("ERROR: %s sr_get_items: %s\n", __func__,
			       sr_strerror(rc));
		}
		return rc;
	}

	/* Count all flow-meter-instance-tables */
	printf("get %lu items in :%s\n", count, path);
	for (i = 0; i < count; i++) {
		nodename = sr_xpath_node_name(values[i].xpath);
		if (!strncmp(nodename, "flow-meter-instance-table", 26)) {
			table_cnt++;
			sr_print_val(&values[i]);
			cur_table = new_fm_table();
			if (!cur_table) {
				snprintf(err_mfm, MSG_MAX_LEN,
					 "Create new fm table failed");
				sr_set_error(session, err_mfm, path);

				printf("Create new fm table failed\n");
				return SR_ERR_NOMEM;
			}
			fm_id = sr_xpath_key_value(values[i].xpath,
						   "flow-meter-instance-table",
						   "flow-meter-instance-id",
						   &xp_ctx);
			if (!fm_id)
				goto cleanup;
			cur_table->fm_ptr->fm_id = strtoul(fm_id, NULL, 0);
			if (table_cnt == 1) {
				fm_table = cur_table;
				pre_table = cur_table;
			} else {
				pre_table->next = cur_table;
			}
		}
	}

	if (!table_cnt) {
		printf("No flow-meter-instance-table configuration\n");
		return SR_ERR_OK;
	}
	printf("find %d tables\n", table_cnt);

	cur_table = fm_table;
	for (i = 0; i < table_cnt; i++) {
		if (!cur_table) {
			printf("current table in null\n");
			goto cleanup;
		} else {
			printf("current table in ok\n");
		}
		snprintf(xpath, XPATH_MAX_LEN,
			 "%s[name='%s']%s[flow-meter-instance-id='%u']//*",
			 BRIDGE_COMPONENT_XPATH, cpname,
			 SGI_XPATH, cur_table->fm_ptr->fm_id);
		sr_free_values(values, count);
		rc = sr_get_items(session, xpath, &values, &count);
		if (rc != SR_ERR_OK) {
			if (rc != SR_ERR_NOT_FOUND) {
				snprintf(err_mfm, MSG_MAX_LEN,
					 "Get items from %s failed", xpath);
				sr_set_error(session, err_mfm, xpath);
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

			if (!parse_qci_fm(session, &values[j],
					       cur_table->fm_ptr))
				para++;
		}
		printf("parse configuration ok\n");
		if (abort) {
			rc = sr_get_changes_iter(session, path, &it);
			if (rc != SR_ERR_OK) {
				snprintf(err_mfm, MSG_MAX_LEN,
					 "Get changes from %s failed", path);
				sr_set_error(session, err_mfm, path);

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

					clr_qci_fm(session,
						   old_value,
						   cur_table->fm_ptr);
				}
				parse_qci_fm(session, new_value,
						  cur_table->fm_ptr);
			}
			if (rc == SR_ERR_NOT_FOUND)
				rc = SR_ERR_OK;
		}
		cur_table = cur_table->next;
	}
	if (!para)
		goto cleanup;

	init_tsn_socket();
	cur_table = fm_table;
	while (cur_table != NULL) {
		printf("start set fm via libtsn\n");
		/* set new flow meter configuration */
		rc = tsn_qci_psfp_fmi_set(cpname, cur_table->fm_ptr->fm_id,
					 cur_table->fm_ptr->enable,
					 &(cur_table->fm_ptr->fmconf));
		if (rc != EXIT_SUCCESS) {
			sprintf(err_mfm,
				"failed to set flow meter, %s!",
				strerror(-rc));
			goto cleanup;
		}
		if (cur_table->next == NULL)
			break;
		cur_table = cur_table->next;
	}

cleanup:
	close_tsn_socket();
	free_fm_table(fm_table);
	sr_free_values(values, count);

	return rc;
}

int qci_fm_config(sr_session_ctx_t *session, const char *path, bool abort)
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
	char err_mfm[MSG_MAX_LEN] = {0};

	printf("%s was called\n", __func__);
	rc = sr_get_changes_iter(session, path, &it);
	if (rc != SR_ERR_OK) {
		snprintf(err_mfm, MSG_MAX_LEN,
			 "Get changes from %s failed", path);
		sr_set_error(session, err_mfm, path);

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
			rc = config_fm_per_port(session, xpath, abort,
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

int qci_fm_subtree_change_cb(sr_session_ctx_t *session, const char *path,
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
		rc = qci_fm_config(session, xpath, false);
		break;
	case SR_EV_ENABLED:
		rc = qci_fm_config(session, xpath, false);
		break;
	case SR_EV_APPLY:
		break;
	case SR_EV_ABORT:
		rc = qci_fm_config(session, xpath, true);
		break;
	default:
		break;
	}

	return rc;
}

