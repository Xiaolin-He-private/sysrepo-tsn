/**
 * @file cb_streamid.c
 * @author Xiaolin He
 * @brief Implementation of Stream Identify function based on sysrepo
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
#include "cb_streamid.h"

struct std_cb_stream_table *new_stream_table(void)
{
	struct std_cb_stream_table *stream_entry_table_ptr;
	struct std_cb_stream *stream_entry_ptr;

	printf("%s is called\n", __func__);
	stream_entry_table_ptr = calloc(1, sizeof(struct std_cb_stream_table));
	if (!stream_entry_table_ptr)
		return NULL;

	stream_entry_ptr = calloc(1, sizeof(struct std_cb_stream));
	if (!stream_entry_ptr) {
		free(stream_entry_table_ptr);
		return NULL;
	}

	stream_entry_table_ptr->stream_ptr = stream_entry_ptr;
	stream_entry_table_ptr->apply_st = APPLY_NONE;
	stream_entry_table_ptr->next = NULL;
	stream_entry_ptr->cbconf.handle = -1;
	return stream_entry_table_ptr;
}

void free_stream_table(struct std_cb_stream_table *stream_table)
{
	struct std_cb_stream_table *tmp_table = stream_table;
	struct std_cb_stream_table *next_table;

	printf("%s is called\n", __func__);
	if (!tmp_table) {
		printf("null table\n");
		return;
	}
	while (tmp_table) {
		next_table = tmp_table->next;
		if (tmp_table->stream_ptr)
			free(tmp_table->stream_ptr);
		free(tmp_table);
		tmp_table = next_table;
	}
}

int parse_vlan_tag(sr_session_ctx_t *session, sr_val_t *value, uint8_t *vlan)
{
	int rc = SR_ERR_OK;
	char err_msg[MSG_MAX_LEN] = {0};
	char *vlan_str = value->data.enum_val;

	printf("%s is called\n", __func__);
	if (!strcmp(vlan_str, "tagged")) {
		printf("tag type is tagged\n");
		*vlan = 1;
	} else if (!strcmp(vlan_str, "priority")) {
		printf("tag type is priority\n");
		*vlan = 2;
	} else if (!strcmp(vlan_str, "all")) {
		printf("tag type is all\n");
		*vlan = 3;
	} else {
		snprintf(err_msg, MSG_MAX_LEN, "Invalid '%s'", vlan_str);
		sr_set_error(session, err_msg, value->xpath);

		printf("ERROR: Invalid '%s' in %s!\n", vlan_str,
		       value->xpath);
		rc = SR_ERR_INVAL_ARG;
	}
	return rc;
}

int parse_mac_address(char *mac_str, uint64_t *mac,
	char *err_msg, char *path)
{
	int rc = SR_ERR_OK;
	char *temp;
	uint64_t ul = 0;
	int i = 0;
	uint64_t byte[6] = {0};

	printf("%s is called\n", __func__);
	if (strlen(mac_str) != 17) {
		rc = SR_ERR_INVAL_ARG;
		sprintf(err_msg, "length of '%s' in path '%s'should be 17!",
			mac_str, path);
		goto out;
	}
	temp = strtok(mac_str, "-");

	ul = strtoul(temp, NULL, 16);
	i = 0;
	byte[i++] = ul;
	while (1) {
		temp = strtok(NULL, "-");
		if (temp != NULL) {
			if (strlen(temp) != 2) {
				rc = SR_ERR_INVAL_ARG;
				sprintf(err_msg,
					"'%s' in '%s' is in wrong format!",
					mac_str, path);
				goto out;
			}
			ul = strtoul(temp, NULL, 16);
			byte[i++] = (uint8_t)ul;
		} else {
			break;
		}
	}
	if (i != 6) {
		rc = SR_ERR_INVAL_ARG;
		sprintf(err_msg, "'%s' in '%s' is in wrong format!",
			mac_str, path);
		goto out;
	}
	for (i = 0, ul = 0; i < 6; i++)
		ul = (ul << 8) + byte[i];

	*mac = ul;
out:
	return rc;
}

void clr_cb_streamid(sr_session_ctx_t *session, sr_val_t *value,
		struct std_cb_stream *stream)
{
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename;

	printf("%s was called\n", __func__);
	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		return;

	if (!strcmp(nodename, "stream-id-enabled")) {
		stream->enable = false;
	} else if (!strcmp(nodename, "stream-handle")) {
		stream->cbconf.handle = 0;
	} else if (!strcmp(nodename, "in-facing-output-port-list")) {
		stream->cbconf.ifac_oport = 0;
	} else if (!strcmp(nodename, "out-facing-output-port-list")) {
		stream->cbconf.ofac_oport = 0;
	} else if (!strcmp(nodename, "in-facing-input-port-list")) {
		stream->cbconf.ifac_iport = 0;
	} else if (!strcmp(nodename, "out-facing-input-port-list")) {
		stream->cbconf.ofac_iport = 0;
	} else if (!strcmp(nodename, "identification-type")) {
		stream->cbconf.type = 0;
	} else if (!strcmp(nodename, "lan-path-id")) {
	} else if (!strcmp(nodename, "dest-address")) {
		if (stream->cbconf.type == STREAMID_IP)
			stream->cbconf.para.iid.dmac = 0;
		else if (stream->cbconf.type == STREAMID_NULL)
			stream->cbconf.para.nid.dmac = 0;
	} else if (!strcmp(nodename, "source-address")) {
		stream->cbconf.para.sid.smac = 0;
	} else if (!strcmp(nodename, "vlan-tagged")) {
		if (stream->cbconf.type == STREAMID_SMAC_VLAN)
			stream->cbconf.para.sid.tagged = 0;
		else if (stream->cbconf.type == STREAMID_NULL)
			stream->cbconf.para.nid.tagged = 0;
	} else if (!strcmp(nodename, "vlan-id")) {
		if (stream->cbconf.type == STREAMID_NULL)
			stream->cbconf.para.nid.vid = 0;
		else if (stream->cbconf.type == STREAMID_SMAC_VLAN)
			stream->cbconf.para.sid.vid = 0;
		else if (stream->cbconf.type == STREAMID_IP)
			stream->cbconf.para.iid.vid = 0;
	} else if (!strcmp(nodename, "down-dest-address")) {
		stream->cbconf.para.did.down_dmac = 0;
	} else if (!strcmp(nodename, "down-vlan-tagged")) {
		if (stream->cbconf.type == STREAMID_DMAC_VLAN)
			stream->cbconf.para.did.down_tagged = 0;
		else if (stream->cbconf.type == STREAMID_IP)
			stream->cbconf.para.iid.tagged = 0;
	} else if (!strcmp(nodename, "down-vlan-id")) {
		stream->cbconf.para.did.down_vid = 0;
	} else if (!strcmp(nodename, "down-priority")) {
		stream->cbconf.para.did.down_prio = 0;
	} else if (!strcmp(nodename, "up-dest-address")) {
		stream->cbconf.para.did.up_dmac = 0;
	} else if (!strcmp(nodename, "up-vlan-tagged")) {
		stream->cbconf.para.did.up_tagged = 0;
	} else if (!strcmp(nodename, "up-vlan-id")) {
		stream->cbconf.para.did.up_vid = 0;
	} else if (!strcmp(nodename, "up-priority")) {
		stream->cbconf.para.did.down_prio = 0;
	} else if (!strcmp(nodename, "ipv4-address")) {
	} else if (!strcmp(nodename, "ipv6-address")) {
	} else if (!strcmp(nodename, "dscp")) {
		stream->cbconf.para.iid.dscp = 0;
	} else if (!strcmp(nodename, "next-protocol")) {
		stream->cbconf.para.iid.npt = 0;
	} else if (!strcmp(nodename, "source-port")) {
		stream->cbconf.para.iid.dscp = 0;
	} else if (!strcmp(nodename, "dest-port")) {
		stream->cbconf.para.iid.dscp = 0;
	}
}

int parse_cb_streamid(sr_session_ctx_t *session, sr_val_t *value,
		struct std_cb_stream *stream)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	uint8_t u8_val = 0;
	uint16_t u16_val = 0;
	uint64_t u64_val = 0;
	char *nodename;
	char *num_str;
	char err_msg[MSG_MAX_LEN] = {0};

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto out;

	printf("%s was called\n", __func__);
	if (!strcmp(nodename, "stream-id-enabled")) {
		stream->enable = value->data.bool_val;
		printf("stream enabled is: %d\n", stream->enable);
	} else if (!strcmp(nodename, "stream-handle")) {
		stream->cbconf.handle = value->data.uint32_val;
	} else if (!strcmp(nodename, "in-facing-output-port-list")) {
		stream->cbconf.ifac_oport = value->data.uint32_val;
	} else if (!strcmp(nodename, "out-facing-output-port-list")) {
		stream->cbconf.ofac_oport = value->data.uint32_val;
	} else if (!strcmp(nodename, "in-facing-input-port-list")) {
		stream->cbconf.ifac_iport = value->data.uint32_val;
	} else if (!strcmp(nodename, "out-facing-input-port-list")) {
		stream->cbconf.ofac_iport = value->data.uint32_val;
	} else if (!strcmp(nodename, "identification-type")) {
		num_str = value->data.enum_val;
		if (!strcmp(num_str, "null")) {
			stream->cbconf.type = STREAMID_NULL;
			printf("id type is null\n");
		} else if (!strcmp(num_str, "source-mac-and-vlan")) {
			stream->cbconf.type = STREAMID_SMAC_VLAN;
			printf("id type is smac\n");
		} else if (!strcmp(num_str, "dest-mac-and-vlan")) {
			stream->cbconf.type = STREAMID_DMAC_VLAN;
			printf("id type is dmac\n");
		} else if (!strcmp(num_str, "ip-octuple")) {
			stream->cbconf.type = STREAMID_IP;
			printf("id type is ip\n");
		} else {
			snprintf(err_msg, MSG_MAX_LEN, "Invalid '%s'", num_str);
			sr_set_error(session, err_msg, value->xpath);

			printf("ERROR: Invalid '%s' in %s!\n", num_str,
			       value->xpath);
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
	} else if (!strcmp(nodename, "lan-path-id")) {
	} else if (!strcmp(nodename, "dest-address")) {
		rc = parse_mac_address(value->data.string_val, &u64_val,
				       err_msg, value->xpath);
		if (rc != SR_ERR_OK) {
			sr_set_error(session, err_msg, value->xpath);
			printf("%s\n", err_msg);
			goto out;
		}
		printf("dest-addr is %lu\n", u64_val);

		if (stream->cbconf.type == STREAMID_IP)
			stream->cbconf.para.iid.dmac = u64_val;
		else if (stream->cbconf.type == STREAMID_NULL)
			stream->cbconf.para.nid.dmac = u64_val;
	} else if (!strcmp(nodename, "source-address")) {
		rc = parse_mac_address(value->data.string_val, &u64_val,
				       err_msg, value->xpath);
		if (rc != SR_ERR_OK) {
			sr_set_error(session, err_msg, value->xpath);
			printf("%s\n", err_msg);
			goto out;
		}
		printf("source-addr is %lu\n", u64_val);
		stream->cbconf.para.sid.smac = u64_val;
	} else if (!strcmp(nodename, "vlan-tagged")) {
		rc = parse_vlan_tag(session, value, &u8_val);
		if (rc != SR_ERR_OK)
			goto out;

		printf("vlan tag is: %u\n", u8_val);
		if (stream->cbconf.type == STREAMID_SMAC_VLAN)
			stream->cbconf.para.sid.tagged = u8_val;
		else if (stream->cbconf.type == STREAMID_NULL)
			stream->cbconf.para.nid.tagged = u8_val;
	} else if (!strcmp(nodename, "vlan-id")) {
		u16_val = value->data.uint16_val;
		printf("vlan id is: %u\n", u16_val);
		if (stream->cbconf.type == STREAMID_NULL)
			stream->cbconf.para.nid.vid = u16_val;
		else if (stream->cbconf.type == STREAMID_SMAC_VLAN)
			stream->cbconf.para.sid.vid = u16_val;
		else if (stream->cbconf.type == STREAMID_IP)
			stream->cbconf.para.iid.vid = u16_val;
	} else if (!strcmp(nodename, "down-dest-address")) {
		rc = parse_mac_address(value->data.string_val, &u64_val,
				       err_msg, value->xpath);
		if (rc != SR_ERR_OK) {
			sr_set_error(session, err_msg, value->xpath);
			printf("%s\n", err_msg);
			goto out;
		}
		printf("down-dest-addr is %lu\n", u64_val);
		stream->cbconf.para.did.down_dmac = u64_val;
	} else if (!strcmp(nodename, "down-vlan-tagged")) {
		rc = parse_vlan_tag(session, value, &u8_val);
		if (rc != SR_ERR_OK)
			goto out;

		printf("down vlan tag is: %u", u8_val);
		if (stream->cbconf.type == STREAMID_DMAC_VLAN)
			stream->cbconf.para.did.down_tagged = u8_val;
		else if (stream->cbconf.type == STREAMID_IP)
			stream->cbconf.para.iid.tagged = u8_val;
	} else if (!strcmp(nodename, "down-vlan-id")) {
		printf("down-vlan id is: %u", value->data.uint16_val);
		stream->cbconf.para.did.down_vid = value->data.uint16_val;
	} else if (!strcmp(nodename, "down-priority")) {
		printf("down-priority is: %u", value->data.uint8_val);
		stream->cbconf.para.did.down_prio = value->data.uint8_val;
	} else if (!strcmp(nodename, "up-dest-address")) {
		rc = parse_mac_address(value->data.string_val, &u64_val,
				       err_msg, value->xpath);
		if (rc != SR_ERR_OK) {
			sr_set_error(session, err_msg, value->xpath);
			printf("%s\n", err_msg);
			goto out;
		}
		printf("up-dest-addr is %lu\n", u64_val);
		stream->cbconf.para.did.up_dmac = u64_val;
	} else if (!strcmp(nodename, "up-vlan-tagged")) {
		rc = parse_vlan_tag(session, value, &u8_val);
		if (rc != SR_ERR_OK)
			goto out;

		printf("up vlan tag is: %u", u8_val);
		stream->cbconf.para.did.up_tagged = u8_val;
	} else if (!strcmp(nodename, "up-vlan-id")) {
		printf("up-vlan id is: %u", value->data.uint16_val);
		stream->cbconf.para.did.up_vid = value->data.uint16_val;
	} else if (!strcmp(nodename, "up-priority")) {
		printf("up-priority is: %u", value->data.uint8_val);
		stream->cbconf.para.did.down_prio = value->data.uint8_val;
	} else if (!strcmp(nodename, "ipv4-address")) {
		struct in_addr i4_addr;

		rc = inet_pton(AF_INET, value->data.string_val, &i4_addr);
		if (rc != 1) {
			printf("Get ipv4 adrress failed\n");
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
	} else if (!strcmp(nodename, "ipv6-address")) {
		struct in6_addr i6_addr;

		rc = inet_pton(AF_INET6, value->data.string_val, &i6_addr);
		if (rc != 1) {
			printf("Get ipv6 adrress failed\n");
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
	} else if (!strcmp(nodename, "dscp")) {
		printf("dscp is: %u", value->data.uint8_val);
		stream->cbconf.para.iid.dscp = value->data.uint8_val;
	} else if (!strcmp(nodename, "next-protocol")) {
		num_str = value->data.enum_val;
		if (!strcmp(num_str, "UDP")) {
			stream->cbconf.para.iid.npt = 0;
			printf("next protocol is UDP\n");
		} else if (!strcmp(num_str, "TCP")) {
			stream->cbconf.para.iid.npt = 1;
			printf("next protocol is TCP\n");
		} else if (!strcmp(num_str, "SCTP")) {
			stream->cbconf.para.iid.npt = 2;
			printf("next protocol is SCTP\n");
		} else if (!strcmp(num_str, "none")) {
			stream->cbconf.para.iid.npt = 3;
			printf("next protocol is none\n");
		}
	} else if (!strcmp(nodename, "source-port")) {
		printf("soruce-port is: %u", value->data.uint16_val);
		stream->cbconf.para.iid.dscp = value->data.uint16_val;
	} else if (!strcmp(nodename, "dest-port")) {
		printf("dest-port is: %u", value->data.uint16_val);
		stream->cbconf.para.iid.dscp = value->data.uint16_val;
	}

out:
	return rc;
}

int config_streamid_per_port(sr_session_ctx_t *session, const char *path,
		bool abort, char *cpname)
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
	struct std_cb_stream_table *stream_table = NULL;
	struct std_cb_stream_table *cur_table;
	struct std_cb_stream_table *pre_table = NULL;
	char *nodename;
	char *index;
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

	/* Count all stream-identity-tables */
	printf("get %lu items in :%s\n", count, path);
	for (i = 0; i < count; i++) {
		nodename = sr_xpath_node_name(values[i].xpath);
		if (!strncmp(nodename, "stream-identity-table", 21)) {
			table_cnt++;

			sr_print_val(&values[i]);
			index = sr_xpath_key_value(values[i].xpath,
						   "stream-identity-table",
						   "index", &xp_ctx);
			if (!index) {
				snprintf(err_msg, MSG_MAX_LEN,
					 "Get index failed");
				sr_set_error(session, err_msg, values[i].xpath);

				printf("ERROR: get index failed from '%s'\n",
				       values[i].xpath);
				rc = SR_ERR_INVAL_ARG;
				goto cleanup;
			}

			cur_table = new_stream_table();
			if (!cur_table) {
				snprintf(err_msg, MSG_MAX_LEN,
					 "Create new stream table failed");
				sr_set_error(session, err_msg, path);

				printf("Create new stream table failed\n");
				return SR_ERR_NOMEM;
			}

			cur_table->stream_ptr->index = strtoul(index, NULL, 0);
			if (!stream_table) {
				stream_table = cur_table;
				pre_table = cur_table;
			} else {
				pre_table->next = cur_table;
			}
		}
	}

	if (!table_cnt) {
		printf("No stream-identity-table configuration\n");
		return SR_ERR_OK;
	}
	printf("find %d tables\n", table_cnt);

	cur_table = stream_table;
	for (i = 0; i < table_cnt; i++) {
		if (!cur_table) {
			printf("current table in null\n");
			goto cleanup;
		} else {
			printf("current table in ok\n");
		}
		snprintf(xpath, XPATH_MAX_LEN,
			 "%s[name='%s']%s[index='%u']//*",
			 BRIDGE_COMPONENT_XPATH, cpname,
			 CB_STREAMID_TABLE_XPATH, cur_table->stream_ptr->index);
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

			rc = !parse_cb_streamid(session, &values[j],
					       cur_table->stream_ptr);
			if (rc != SR_ERR_OK) {
				cur_table->apply_st = APPLY_PARSE_ERR;
				goto cleanup;
			}
		}

		printf("parse configuration success\n");
		cur_table->apply_st = APPLY_PARSE_SUC;

		if (abort && cur_table->apply_st != APPLY_PARSE_ERR) {
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

					clr_cb_streamid(session,
							old_value,
							cur_table->stream_ptr);
				}
				parse_cb_streamid(session, new_value,
						  cur_table->stream_ptr);
			}
			if (rc == SR_ERR_NOT_FOUND)
				rc = SR_ERR_OK;
		}
		cur_table = cur_table->next;
	}
	if (!para)
		goto cleanup;

	init_tsn_socket();
	cur_table = stream_table;
	while (cur_table != NULL) {
		printf("start set cbstreamid via libtsn\n");
		/* set new stream identify configuration */
		if (cur_table->apply_st == APPLY_PARSE_ERR)
			break;

		rc = tsn_cb_streamid_set(cpname, cur_table->stream_ptr->index,
					 cur_table->stream_ptr->enable,
					 &(cur_table->stream_ptr->cbconf));
		if (rc != EXIT_SUCCESS) {
			sprintf(err_msg,
				"failed to set stream identification, %s!",
				strerror(-rc));
			cur_table->apply_st = APPLY_SET_ERR;
			goto cleanup;
		}
		cur_table->apply_st = APPLY_SET_SUC;
		cur_table = cur_table->next;
	}

cleanup:
	close_tsn_socket();
	free_stream_table(stream_table);
	sr_free_values(values, count);

	return rc;
}

int cb_streamid_config(sr_session_ctx_t *session, const char *path, bool abort)
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
			snprintf(xpath, XPATH_MAX_LEN, "%s[name='%s']/%s:*//*",
				 BRIDGE_COMPONENT_XPATH, cpname,
				 CB_STREAMID_MODULE_NAME);
			rc = config_streamid_per_port(session, xpath, abort,
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

int cb_streamid_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

	printf("%s was called\n", __func__);
	snprintf(xpath, XPATH_MAX_LEN, "%s/%s:*//*", BRIDGE_COMPONENT_XPATH,
		 CB_STREAMID_MODULE_NAME);
	print_ev_type(event);
	printf("xpath is :\n%s\n", xpath);
	switch (event) {
	case SR_EV_VERIFY:
		rc = cb_streamid_config(session, xpath, false);
		break;
	case SR_EV_ENABLED:
		rc = cb_streamid_config(session, xpath, false);
		break;
	case SR_EV_APPLY:
		break;
	case SR_EV_ABORT:
		rc = cb_streamid_config(session, xpath, true);
		break;
	default:
		break;
	}

	return rc;
}

