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

struct std_cb_stream_list *stream_head;

struct std_cb_stream_list *new_stream_list_node(char *port, uint32_t index)
{
	struct std_cb_stream_list *stream_list;
	struct std_cb_stream *stream_ptr;

	stream_list = calloc(1, sizeof(struct std_cb_stream_list));
	if (!stream_list)
		return NULL;

	stream_ptr = calloc(1, sizeof(struct std_cb_stream));
	if (!stream_ptr) {
		free(stream_list);
		return NULL;
	}

	stream_list->stream_ptr = stream_ptr;
	stream_list->apply_st = APPLY_NONE;
	snprintf(stream_list->stream_ptr->port, IF_NAME_MAX_LEN, port);
	stream_list->stream_ptr->index = index;
	stream_list->next = NULL;
	stream_list->pre = NULL;
	stream_ptr->cbconf.handle = -1;
	return stream_list;
}

void del_stream_list_node(struct std_cb_stream_list *node)
{
	if (!node)
		return;

	if (node->pre)
		node->pre->next = node->next;
	if (node->stream_ptr)
		free(node->stream_ptr);
	free(node);
}

void free_stream_list(struct std_cb_stream_list *l_head)
{
	if (!l_head)
		return;

	if (l_head->next)
		free_stream_list(l_head->next);

	del_stream_list_node(l_head);
}

struct std_cb_stream_list *find_stream_in_list(struct std_cb_stream_list *list,
		char *port, uint32_t index)
{
	struct std_cb_stream_list *node = list;

	while (node) {
		if (!strncmp(port, node->stream_ptr->port, IF_NAME_MAX_LEN)
		    && (node->stream_ptr->index == index))
			goto out;
		else
			node = node->next;
	}
out:
	return node;
}

void add_stream2list(struct std_cb_stream_list *list,
		struct std_cb_stream_list *node)
{
	struct std_cb_stream_list *last = list;

	if (!list) {
		list = node;
		return;
	}

	while (last->next)
		last = last->next;

	last->next = node;
}

int parse_vlan_tag(sr_session_ctx_t *session, sr_val_t *value, uint8_t *vlan)
{
	int rc = SR_ERR_OK;
	char err_msg[MSG_MAX_LEN] = {0};
	char *vlan_str = value->data.enum_val;

	if (!strcmp(vlan_str, "tagged")) {
		*vlan = 1;
	} else if (!strcmp(vlan_str, "priority")) {
		*vlan = 2;
	} else if (!strcmp(vlan_str, "all")) {
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

/************************************************************************
 *
 * Init value of items in abort callback.
 *
 ************************************************************************/
void clr_cb_streamid(sr_session_ctx_t *session, sr_val_t *value,
		struct std_cb_stream *stream)
{
	sr_xpath_ctx_t xp_ctx = {0};
	char *nodename;

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

/************************************************************************
 *
 * Get items' values from datastore.
 *
 ************************************************************************/
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

	if (!strcmp(nodename, "stream-id-enabled")) {
		stream->enable = value->data.bool_val;
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
		} else if (!strcmp(num_str, "source-mac-and-vlan")) {
			stream->cbconf.type = STREAMID_SMAC_VLAN;
		} else if (!strcmp(num_str, "dest-mac-and-vlan")) {
			stream->cbconf.type = STREAMID_DMAC_VLAN;
		} else if (!strcmp(num_str, "ip-octuple")) {
			stream->cbconf.type = STREAMID_IP;
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
		stream->cbconf.para.sid.smac = u64_val;
	} else if (!strcmp(nodename, "vlan-tagged")) {
		rc = parse_vlan_tag(session, value, &u8_val);
		if (rc != SR_ERR_OK)
			goto out;

		if (stream->cbconf.type == STREAMID_SMAC_VLAN)
			stream->cbconf.para.sid.tagged = u8_val;
		else if (stream->cbconf.type == STREAMID_NULL)
			stream->cbconf.para.nid.tagged = u8_val;
	} else if (!strcmp(nodename, "vlan-id")) {
		u16_val = value->data.uint16_val;
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
		stream->cbconf.para.did.down_dmac = u64_val;
	} else if (!strcmp(nodename, "down-vlan-tagged")) {
		rc = parse_vlan_tag(session, value, &u8_val);
		if (rc != SR_ERR_OK)
			goto out;

		if (stream->cbconf.type == STREAMID_DMAC_VLAN)
			stream->cbconf.para.did.down_tagged = u8_val;
		else if (stream->cbconf.type == STREAMID_IP)
			stream->cbconf.para.iid.tagged = u8_val;
	} else if (!strcmp(nodename, "down-vlan-id")) {
		stream->cbconf.para.did.down_vid = value->data.uint16_val;
	} else if (!strcmp(nodename, "down-priority")) {
		stream->cbconf.para.did.down_prio = value->data.uint8_val;
	} else if (!strcmp(nodename, "up-dest-address")) {
		rc = parse_mac_address(value->data.string_val, &u64_val,
				       err_msg, value->xpath);
		if (rc != SR_ERR_OK) {
			sr_set_error(session, err_msg, value->xpath);
			printf("%s\n", err_msg);
			goto out;
		}
		stream->cbconf.para.did.up_dmac = u64_val;
	} else if (!strcmp(nodename, "up-vlan-tagged")) {
		rc = parse_vlan_tag(session, value, &u8_val);
		if (rc != SR_ERR_OK)
			goto out;

		stream->cbconf.para.did.up_tagged = u8_val;
	} else if (!strcmp(nodename, "up-vlan-id")) {
		stream->cbconf.para.did.up_vid = value->data.uint16_val;
	} else if (!strcmp(nodename, "up-priority")) {
		stream->cbconf.para.did.down_prio = value->data.uint8_val;
	} else if (!strcmp(nodename, "ipv4-address")) {
		struct in_addr i4_addr;

		rc = inet_pton(AF_INET, value->data.string_val, &i4_addr);
		if (rc != 1) {
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
	} else if (!strcmp(nodename, "ipv6-address")) {
		struct in6_addr i6_addr;

		rc = inet_pton(AF_INET6, value->data.string_val, &i6_addr);
		if (rc != 1) {
			rc = SR_ERR_INVAL_ARG;
			goto out;
		}
	} else if (!strcmp(nodename, "dscp")) {
		stream->cbconf.para.iid.dscp = value->data.uint8_val;
	} else if (!strcmp(nodename, "next-protocol")) {
		num_str = value->data.enum_val;
		if (!strcmp(num_str, "UDP"))
			stream->cbconf.para.iid.npt = 0;
		else if (!strcmp(num_str, "TCP"))
			stream->cbconf.para.iid.npt = 1;
		else if (!strcmp(num_str, "SCTP"))
			stream->cbconf.para.iid.npt = 2;
		else if (!strcmp(num_str, "none"))
			stream->cbconf.para.iid.npt = 3;
	} else if (!strcmp(nodename, "source-port")) {
		stream->cbconf.para.iid.dscp = value->data.uint16_val;
	} else if (!strcmp(nodename, "dest-port")) {
		stream->cbconf.para.iid.dscp = value->data.uint16_val;
	}

out:
	return rc;
}

/************************************************************************
 *
 * Process changes in one port and apply them to device.
 *
 ************************************************************************/
int get_streamid_per_port_per_id(sr_session_ctx_t *session, const char *path)
{
	int rc = SR_ERR_OK;
	sr_change_iter_t *it;
	sr_xpath_ctx_t xp_ctx_cp = {0};
	sr_xpath_ctx_t xp_ctx_id = {0};
	sr_change_oper_t oper;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_val_t *value;
	char err_msg[MSG_MAX_LEN] = {0};
	char *cpname;
	char *index;
	uint32_t stream_id = 0;
	struct std_cb_stream_list *cur_node = NULL;
	char index_bak[IF_NAME_MAX_LEN] = "unknown";

	rc = sr_get_changes_iter(session, path, &it);

	if (rc != SR_ERR_OK) {
		snprintf(err_msg, MSG_MAX_LEN,
			 "Get changes from %s failed", path);
		sr_set_error(session, err_msg, path);

		printf("ERROR: %s sr_get_changes_iter: %s", __func__,
		       sr_strerror(rc));
		goto out;
	}

	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
					&oper, &old_value, &new_value))) {
		value = new_value ? new_value : old_value;
		if (!value)
			continue;

		index = sr_xpath_key_value(value->xpath,
					    "stream-identity-table", "index",
					    &xp_ctx_id);

		if ((!index) || !strncmp(index, index_bak, IF_NAME_MAX_LEN))
			continue;

		snprintf(index_bak, IF_NAME_MAX_LEN, index);

		stream_id = strtoul(index, NULL, 0);
		cpname = sr_xpath_key_value(value->xpath, "component",
					    "name", &xp_ctx_cp);
		if (!cpname)
			continue;

		if (!stream_head) {
			stream_head = new_stream_list_node(cpname,
							   stream_id);
			if (!stream_head) {
				snprintf(err_msg, MSG_MAX_LEN, "%s in %s\n",
					 "Create new node failed",
					 value->xpath);
				sr_set_error(session, err_msg, path);
				rc = SR_ERR_NOMEM;
				goto out;
			}
			continue;
		}
		cur_node = find_stream_in_list(stream_head, cpname, stream_id);
		if (!cur_node) {
			cur_node = new_stream_list_node(cpname, stream_id);
			if (!cur_node) {
				snprintf(err_msg, MSG_MAX_LEN, "%s in %s\n",
					 "Create new node failed",
					 value->xpath);
				sr_set_error(session, err_msg, path);
				rc = SR_ERR_NOMEM;
				goto out;
			}

			add_stream2list(stream_head, cur_node);
		}
	}
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

out:
	return rc;
}

int parse_streamid_per_port_per_id(sr_session_ctx_t *session, bool abort)
{
	int rc = SR_ERR_OK;
	sr_change_iter_t *it;
	sr_change_oper_t oper;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_val_t *values;
	size_t count;
	size_t i;
	char err_msg[MSG_MAX_LEN] = {0};
	struct std_cb_stream_list *cur_node = stream_head;
	char xpath[XPATH_MAX_LEN] = {0,};

	while (cur_node) {
		snprintf(xpath, XPATH_MAX_LEN,
			 "%s[name='%s']%s[index='%u']//*",
			 BRIDGE_COMPONENT_XPATH, cur_node->stream_ptr->port,
			 CB_STREAMID_TABLE_XPATH,
			 cur_node->stream_ptr->index);
		if (abort) {
			rc = sr_get_changes_iter(session, xpath, &it);
			if (rc != SR_ERR_OK) {
				snprintf(err_msg, MSG_MAX_LEN,
					 "Get changes from %s failed", xpath);
				sr_set_error(session, err_msg, xpath);

				printf("ERROR: Get changes from %s failed\n",
				       xpath);
				goto out;
			}

next_change:
			rc = sr_get_change_next(session, it, &oper, &old_value,
						&new_value);
			if (rc == SR_ERR_OK) {
				if (oper == SR_OP_DELETED) {
					if (!old_value)
						goto next_change;

					clr_cb_streamid(session, old_value,
							cur_node->stream_ptr);
					goto next_change;
				}
				parse_cb_streamid(session, new_value,
						  cur_node->stream_ptr);
				goto next_change;
			}
			if (rc == SR_ERR_NOT_FOUND)
				rc = SR_ERR_OK;

			cur_node = cur_node->next;
			continue;
		}

		rc = sr_get_items(session, xpath, &values, &count);
		if (rc != SR_ERR_OK) {
			if (rc != SR_ERR_NOT_FOUND) {
				snprintf(err_msg, MSG_MAX_LEN,
					 "Get items from %s failed", xpath);
				sr_set_error(session, err_msg, xpath);
			}
			printf("ERROR: %s sr_get_items: %s\n", __func__,
			       sr_strerror(rc));

			goto out;
		}

		for (i = 0; i < count; i++) {
			if (values[i].type == SR_LIST_T
			    || values[i].type == SR_CONTAINER_PRESENCE_T)
				continue;

			rc = parse_cb_streamid(session, &values[i],
					       cur_node->stream_ptr);
			if (rc != SR_ERR_OK) {
				cur_node->apply_st = APPLY_PARSE_ERR;
				sr_free_values(values, count);
				del_stream_list_node(cur_node);
				goto out;
			}
		}
		sr_free_values(values, count);
		cur_node->apply_st = APPLY_PARSE_SUC;

		cur_node = cur_node->next;
	}

out:
	return rc;
}

int config_streamid(sr_session_ctx_t *session)
{
	int rc = SR_ERR_OK;
	char err_msg[MSG_MAX_LEN] = {0};
	struct std_cb_stream_list *cur_node = stream_head;
	char xpath[XPATH_MAX_LEN] = {0,};

	init_tsn_socket();
	while (cur_node) {
		/* set new flow meter configuration */
		rc = tsn_cb_streamid_set(cur_node->stream_ptr->port,
					 cur_node->stream_ptr->index,
					 cur_node->stream_ptr->enable,
					 &(cur_node->stream_ptr->cbconf));
		if (rc < 0) {
			sprintf(err_msg,
				"failed to set stream-id, %s!",
				strerror(-rc));
			snprintf(xpath, XPATH_MAX_LEN,
				 "%s[name='%s']%s[index='%u']//*",
				 BRIDGE_COMPONENT_XPATH,
				 cur_node->stream_ptr->port,
				 CB_STREAMID_TABLE_XPATH,
				 cur_node->stream_ptr->index);
			sr_set_error(session, err_msg, xpath);
			cur_node->apply_st = APPLY_SET_ERR;
			goto cleanup;
		} else {
			cur_node->apply_st = APPLY_SET_SUC;
		}
		cur_node = cur_node->next;
	}

cleanup:
	close_tsn_socket();

	return rc;
}

int cb_streamid_config(sr_session_ctx_t *session, const char *path, bool abort)
{
	int rc = SR_ERR_OK;

	if (!abort) {
		rc = get_streamid_per_port_per_id(session, path);
		if (rc != SR_ERR_OK)
			goto out;
	}
	if (!stream_head)
		goto out;

	rc = parse_streamid_per_port_per_id(session, abort);
	if (rc != SR_ERR_OK)
		goto out;

	rc = config_streamid(session);
out:
	return rc;
}

/************************************************************************
 *
 * Callback for CB-Stream-Identification configuration.
 *
 ************************************************************************/
int cb_streamid_subtree_change_cb(sr_session_ctx_t *session, const char *path,
		sr_notif_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

	snprintf(xpath, XPATH_MAX_LEN, "%s/%s:*//*", BRIDGE_COMPONENT_XPATH,
		 CB_STREAMID_MODULE_NAME);
	switch (event) {
	case SR_EV_VERIFY:
		rc = cb_streamid_config(session, xpath, false);
		break;
	case SR_EV_ENABLED:
		rc = cb_streamid_config(session, xpath, false);
		break;
	case SR_EV_APPLY:
		free_stream_list(stream_head);
		stream_head = NULL;
		break;
	case SR_EV_ABORT:
		rc = cb_streamid_config(session, xpath, true);
		free_stream_list(stream_head);
		stream_head = NULL;
		break;
	default:
		break;
	}

	return rc;
}
