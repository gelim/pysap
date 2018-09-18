# ===========
# pysap - Python library for crafting SAP's network protocols packets
#
# Copyright (C) 2012-2018 by Martin Gallo, Core Security
#
# The library was designed and developed by Martin Gallo from
# Core Security's CoreLabs team.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# ==============

# External imports
from scapy.layers.inet import TCP
from scapy.packet import Packet, bind_layers
from scapy.fields import (ByteField, ConditionalField, IPField, IntField,
                          StrFixedLenField, SignedShortField, ShortField,
                          ByteEnumKeysField, IntEnumKeysField, SignedIntField,
                          FieldLenField, StrLenField)
# External imports
from scapy.layers.inet6 import IP6Field
# Custom imports
from pysap.SAPNI import SAPNI
from pysap.utils.fields import StrFixedLenPaddedField, IntToStrField


# RFC Request Type values
rfc_req_type_values = {
    0x00: "GW_UNDEF_TYPE",
    0x01: "CHECK_GATEWAY",
    0x02: "GW_CONNECT_GWWP",
    0x03: "GW_NORMAL_CLIENT",
    0x04: "GW_REMOTE_GATEWAY",
    0x05: "STOP_GATEWAY",
    0x06: "GW_LOCAL_R3",
    0x07: "GW_SEND_INTERNAL_ERROR",  # Requires NiLocalCheck
    0x08: "GW_SEND_INFO",
    0x09: "GW_SEND_CMD",
    0x0a: "GW_WORKPROCESS_DIED",  # Requires NiLocalCheck
    0x0b: "GW_REGISTER_TP",
    0x0c: "GW_UNREGISTER_TP",
    0x0d: "GW_CONNECT_DISP",  # Requires NiLocalCheck
    0x0e: "GW_GET_NO_REGISTER_TP",
    0x0f: "GW_SAP_WP_CLIENT",  # Requires NiLocalCheck
    0x10: "GW_CANCEL_REGISTER_TP",
    0x11: "GW_FROM_REMOTE_GATEWAY",
    0x12: "GW_CONTAINER_RECEIVED",
}

rfc_func_type_values = {
    0: "F_NO_REQUEST",
    1: "F_INITIALIZE_CONVERSATION",
    3: "F_ACCEPT_CONVERSATION",
    5: "F_ALLOCATE",
    7: "F_SEND_DATA",
    8: "F_ASEND_DATA",
    9: "F_RECEIVE",
    10: "F_ARECEIVE",
    11: "F_DEALLOCATE",
    13: "F_SET_TP_NAME",
    15: "F_SET_PARTNER_LU_NAME",
    17: "F_SET_SECURITY_PASSWORD",
    19: "F_SET_SECURITY_USER_ID",
    21: "F_SET_SECURITY_TYPE",
    23: "F_SET_CONVERSATION_TYPE",
    25: "F_EXTRACT_TP_NAME",
    27: "F_FLUSH",
    0xc9: "F_SAP_ALLOCATE",
    0xca: "F_SAP_INIT",
    0xcb: "F_SAP_SEND",
    0xcc: "F_ASAP_SEND",
    0xcd: "F_SAP_SYNC",
    0xce: "F_SAP_PING",
    0xcf: "F_SAP_REGTP",
    0xd0: "F_SAP_UNREGTP",
    0xd1: "F_SAP_ACCPTP",
    0xd2: "F_SAP_UNACCPTP",
    0xd3: "F_SAP_CANCTP",
    0xd4: "F_SAP_SET_UID",
    0xd5: "F_SAP_CANCEL",
    0xd6: "F_SAP_CANCELED",
    0xd7: "F_SAP_STOP_STREAMING",
    0xd8: "F_SAP_CONT_STREAMING",
}
"""RFC Request Type values"""

# RFC Monitor Command values
rfc_monitor_cmd_values = {
    0x01: "NOOP",
    0x02: "DELETE_CONN",
    0x03: "CANCEL_CONN",
    0x04: "RST_SINGLE_ERR_CNT",
    0x05: "RST_ALL_ERR_CNT",
    0x06: "INCREASE_TRACE",
    0x07: "DECREASE_TRACE",
    0x08: "READ_SEC_INFO",
    0x09: "REFRESH_SEC_INFO",
    0x0a: "READ_GWSYS_TBL",
    0x0b: "READ_CONN_TBL",
    0x0c: "READ_PROC_TBL",
    0x0d: "READ_CONN_ATTR",
    0x0e: "READ_MEMORY",
    0x0f: "READ_REQ_BLK",
    0x10: "ACT_STATISTIC",
    0x11: "DEACT_STATISTIC",
    0x12: "READ_STATISTIC",
    0x13: "RESET_STATISTIC",
    0x14: "READ_PARAMETER",
    0x19: "DUMP_NIBUFFER",
    0x20: "RESET_NIBUFFER",
    0x21: "ACT_EXTPGM_TRACE",
    0x22: "DEACT_EXTPGM_TRACE",
    0x23: "ACT_CONN_TRACE",
    0x24: "DEACT_CONN_TRACE",
    0x25: "RESET_TRACE",
    0x26: "SUICIDE",
    0x27: "READ_SEC_INFO2",
    0x28: "CANCEL_REG_TP",
    0x29: "DUMP",
    0x2a: "READ_GWSYS_TBL2",
    0x2b: "CHANGE_PARAMETER",
    0x2c: "GET_CONN_PARTNER",
    0x2d: "DELETE_CLIENT",
    0x2e: "DELETE_REMGW",
    0x2f: "DISCONNECT",
    0x30: "ENABLE_RESTART",
    0x31: "DISABLE_RESTART",
    0x32: "NI_TRACE",
    0x33: "CLI_INFO",
    0x34: "GW_INFO",
    0x35: "CONVID_INFO",
    0x36: "GET_NO_REG_TP",
    0x37: "CV_INFO",
    0x38: "SO_KEEPALIVE",
    0x39: "READ_CONN_TBL2",
    0x40: "READ_GWSYS_TBL3",
    0x41: "RELOAD_ACL",
}
"""RFC Monitor Command values"""

appc_protocol_values = {
    0x3: "CPIC",
}

appc_rc_values = {
    0x0: "CM_OK",
    0x1: "CM_ALLOCATE_FAILURE_NO_RETRY",
    0x2: "CM_ALLOCATE_FAILURE_RETRY",
    0x3: "CM_CONVERSATION_TYPE_MISMATCH",
    0x6: "CM_SECURITY_NOT_VALID",
    0x8: "CM_SYNC_LVL_NOT_SUPPORTED_PGM",
    0x9: "CM_TPN_NOT_RECOGNIZED",
    0xa: "CM_TP_NOT_AVAILABLE_NO_RETRY",
    0xb: "CM_TP_NOT_AVAILABLE_RETRY",
    0x11: "CM_DEALLOCATED_ABEND",
    0x12: "CM_DEALLOCATED_NORMAL",
    0x13: "",
    0x15: "CM_PROGRAM_ERROR_NO_TRUNC",
    0x17: "CM_PROGRAM_ERROR_TRUNC",
    0x18: "CM_PROGRAM_PARAMETER_CHECK",
    0x19: "CM_PROGRAM_STATE_CHECK",
    0x14: "CM_PRODUCT_SPECIFIC_ERROR",
    0x1a: "CM_RESOURCE_FAILURE_NO_RETRY",
    0x1b: "CM_RESOURCE_FAILURE_RERTY",
    0x1c: "CM_UNSUCCESSFUL",
    0x24: "CM_SYSTEM_EVENT",
    0x2711: "CM_SAP_TIMEOUT_RETRY",
    0x2712: "CM_CANCEL_REQUEST",
}

sap_rc_values = {
}

# APPC Header versions length:
# 1: 4Ch
# 2/3: 64h
# 4: 8Ah
# 5: 4Eh
# 6: 50h

class SAPRFC(Packet):
    """SAP Remote Function Call packet

    This packet is used for the Remote Function Call (RFC) protocol.
    """
    name = "SAP Remote Function Call"
    fields_desc = [
        ByteField("version", 3),  # If the version is 3, the packet has a size > 88h, versions 1 and 2 are 40h
        ConditionalField(ByteEnumKeysField("req_type", 0, rfc_req_type_values), lambda pkt:pkt.version != 0x06),
        ConditionalField(ByteEnumKeysField("func_type", 0, rfc_func_type_values), lambda pkt:pkt.version == 0x06),

        # Normal client fields (GW_NORMAL_CLIENT)
        ConditionalField(IPField("address", "0.0.0.0"), lambda pkt:pkt.req_type == 0x03),
        ConditionalField(IntField("padd1", 0), lambda pkt:pkt.req_type == 0x03),
        ConditionalField(StrFixedLenPaddedField("service", "", length=10), lambda pkt:pkt.req_type == 0x03),
        ConditionalField(StrFixedLenField("codepage", "1100", length=4), lambda pkt:pkt.req_type == 0x03),
        ConditionalField(StrFixedLenField("padd2", "\x00" * 6, length=6), lambda pkt:pkt.req_type == 0x03),
        ConditionalField(StrFixedLenPaddedField("lu", "", length=8), lambda pkt:pkt.req_type == 0x03),
        ConditionalField(StrFixedLenPaddedField("tp", "", length=8), lambda pkt:pkt.req_type == 0x03),
        ConditionalField(StrFixedLenPaddedField("conversation_id", "", length=8), lambda pkt:pkt.req_type == 0x03),
        ConditionalField(ByteField("appc_header_version", 6), lambda pkt:pkt.req_type == 0x03),
        ConditionalField(ByteField("accept_info", 0xcb), lambda pkt:pkt.req_type == 0x03),
        ConditionalField(SignedShortField("idx", -1), lambda pkt:pkt.req_type == 0x03),
        ConditionalField(IP6Field("address6", "::"), lambda pkt:pkt.req_type == 0x03 and pkt.version == 3),

        ConditionalField(IntField("rc", 0), lambda pkt:pkt.req_type == 0x03),
        ConditionalField(ByteField("echo_data", 0), lambda pkt:pkt.req_type == 0x03),
        ConditionalField(ByteField("filler", 0), lambda pkt:pkt.req_type == 0x03),

        # Monitor Command fields (GW_SEND_CMD)
        ConditionalField(ByteEnumKeysField("cmd", 0, rfc_monitor_cmd_values), lambda pkt:pkt.req_type == 0x09),

        # General padding for non implemented request types
        ConditionalField(StrFixedLenField("padd_v12", "\x00" * 61, length=61), lambda pkt: pkt.version < 3 and pkt.req_type == 0x09),
        ConditionalField(StrFixedLenField("padd_v12", "\x00" * 62, length=62), lambda pkt: pkt.version < 3 and pkt.req_type not in [0x03, 0x09]),
        ConditionalField(StrFixedLenField("padd_v3", "\x00" * 133, length=133), lambda pkt: pkt.version == 3 and pkt.req_type == 0x09),
        ConditionalField(StrFixedLenField("padd_v3", "\x00" * 134, length=134), lambda pkt: pkt.version == 3 and pkt.req_type not in [0x03, 0x09]),

        # APPC layer POC for remote function call
        ConditionalField(ByteEnumKeysField("protocol", 0x3, appc_protocol_values), lambda pkt:pkt.version == 0x6),
        ConditionalField(ByteField("mode", 0x0), lambda pkt:pkt.version == 0x6),
        ConditionalField(ShortField("uid", 0x13), lambda pkt:pkt.version == 0x6),
        ConditionalField(ShortField("gw_id", 0x0), lambda pkt:pkt.version == 0x6),
        ConditionalField(ShortField("err_len", 0x0), lambda pkt:pkt.version == 0x6),
        ConditionalField(ByteField("info2", 0x1), lambda pkt:pkt.version == 0x6), # bitfield
        ConditionalField(ByteField("trace_level", 0x1), lambda pkt:pkt.version == 0x6),
        ConditionalField(IntField("time", 0x0), lambda pkt:pkt.version == 0x6),
        ConditionalField(ByteField("info3", 0x0), lambda pkt:pkt.version == 0x6), # bitfield
        ConditionalField(SignedIntField("timeout", -1), lambda pkt:pkt.version == 0x6),
        ConditionalField(ByteField("info4", 0x0), lambda pkt:pkt.version == 0x6), # bitfield
        ConditionalField(IntField("seq_no", 0x0), lambda pkt:pkt.version == 0x6),
        ConditionalField(FieldLenField("sap_param_len", None, length_of="sap_param", fmt="!H"), lambda pkt:pkt.version == 0x6),
        ConditionalField(ByteField("info", 0x0), lambda pkt:pkt.version == 0x6), # bitfield
        ConditionalField(ShortField("padd_appc", 0x0), lambda pkt:pkt.version == 0x6), # bitfield
        ConditionalField(ByteField("req_type2", 0x0), lambda pkt:pkt.version == 0x6), # bitfield
        ConditionalField(IntEnumKeysField("appc_rc", 0x0, appc_rc_values), lambda pkt:pkt.version == 0x6),
        ConditionalField(IntEnumKeysField("sap_rc", 0x0, sap_rc_values), lambda pkt:pkt.version == 0x6),
        ConditionalField(IntToStrField("conv_id", 0, 8), lambda pkt:pkt.version == 0x6),
        ConditionalField(StrFixedLenField("ncpic_parameters", 0, 28), lambda pkt:pkt.version == 0x6),
        ConditionalField(ShortField("comm_idx", 0x0), lambda pkt:pkt.version == 0x6),
        ConditionalField(ShortField("conn_idx", 0x0), lambda pkt:pkt.version == 0x6),
        ConditionalField(StrLenField("sap_param", "", length_from=lambda pkt:pkt.sap_param_len), lambda pkt:pkt.version == 0x6),
    ]


# Bind SAP NI with the RFC port
bind_layers(TCP, SAPNI, dport=3300)
