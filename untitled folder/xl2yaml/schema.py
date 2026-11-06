"""Single source of truth for the workbook layout and the YAML contract.

Every field below was derived from the module that consumes it (see ``source``).
YAML comments in ``create_vars.yml.example`` were NOT used as a source.

Field classes
-------------
key       Device-name column that scopes a row to a device.
required  Must be filled in. Blank is an error.
explicit  Must be filled in because the module would otherwise apply a default
          that can broaden protection or change enforcement. Blank is an error.
optional  Blank means the key is left out of the YAML; the module/device default
          applies and the report lists it as "left to default".
info      Column copied from the device export that no module consumes.
          Non-blank values are reported as "not converted" (never silently dropped).
check     Formula column used only inside Excel. Ignored by the converter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

TEMPLATE_VERSION = "0.4"

# Row 1 of every sheet is a description of the sheet; headers are on row 2, data starts on row 3.
DESCRIPTION_ROW = 1
HEADER_ROW = 2
FIRST_DATA_ROW = 3

KEY, REQUIRED, EXPLICIT, OPTIONAL, INFO, CHECK = "key", "required", "explicit", "optional", "info", "check"

ENABLED = (("Enabled", "enable"), ("Disabled", "disable"))


@dataclass(frozen=True)
class Field:
    header: str                      # Excel column header (exact)
    key: Optional[str]               # YAML key (None for key/info/check columns)
    kind: str                        # name|text|enum|int|numeric_string|ip|ipv4|mask|yesno|port_group|tcp_flags|ref
    cls: str
    labels: Tuple[Tuple[str, str], ...] = ()   # Excel label -> YAML value
    module_values: Tuple[str, ...] = ()        # values the module accepts in YAML (for YAML-mode checks)
    case_insensitive: bool = False             # module lowercases the value before mapping
    minimum: Optional[int] = None
    maximum: Optional[int] = None
    ref: Optional[str] = None                  # reference type for kind == "ref"
    in_params: bool = False                    # written under ``params:``
    source: str = ""                           # module/function the rule comes from
    note: str = ""                             # help text shown in the template
    width: int = 16

    def label_map(self) -> Dict[str, str]:
        return dict(self.labels)


@dataclass(frozen=True)
class SheetSpec:
    name: str
    role: str                         # data | control | reference | meta
    fields: Tuple[Field, ...] = ()
    toggle: Optional[str] = None      # security_policy_config toggle that governs the sheet
    yaml_key: Optional[str] = None
    tab: str = "003087"
    description: str = ""

    @property
    def headers(self) -> List[str]:
        return [f.header for f in self.fields]

    def field(self, header: str) -> Field:
        for f in self.fields:
            if f.header == header:
                return f
        raise KeyError(header)

    def by_key(self, key: str) -> Field:
        for f in self.fields:
            if f.key == key:
                return f
        raise KeyError(key)


DEVICE = Field("DefensePro Name", None, "name", KEY, note="Must match a row on the Devices sheet.", width=18)

# --------------------------------------------------------------------------- #
# security_policy_config (playbooks/create_full_config.yml)
# --------------------------------------------------------------------------- #
TOGGLES = (
    "create_network_classes",
    "create_cl_profiles",
    "create_out_of_state_profiles",
    "create_bdos_profiles",
    "create_dns_profiles",
    "create_https_profiles",
    "create_traffic_filter_profiles",
    "create_ssl_objects",
    "create_security_policies",
    "apply_policies_after_creation",
)
# Sections the POC converter does not generate. Their toggles must be FALSE.
UNSUPPORTED_TOGGLES = ("create_dns_profiles", "create_https_profiles", "create_ssl_objects")
# Run_Control key that authorizes Phase B. The generated YAML always carries
# apply_policies_after_creation: false (see README, "Two-phase run").
AUTHORIZE_APPLY = "authorize_policy_apply"
RUN_CONTROL_TOGGLES = tuple(t for t in TOGGLES if t != "apply_policies_after_creation")
RUN_CONTROL_SETTINGS = ("environment", "change_ticket", "authorized_by")
ENVIRONMENTS = ("lab", "production")

# Human-readable Run_Control labels (column A) -> internal keys. The workbook shows only the labels.
RUN_CONTROL_LABELS = {
    "create_network_classes": "Create Network Classes",
    "create_cl_profiles": "Create Connection Limit Profiles",
    "create_out_of_state_profiles": "Create Out of State Profiles",
    "create_bdos_profiles": "Create BDoS Profiles",
    "create_dns_profiles": "Create DNS Profiles",
    "create_https_profiles": "Create HTTPS Flood Profiles",
    "create_traffic_filter_profiles": "Create Traffic Filter Profiles",
    "create_ssl_objects": "Create SSL Objects",
    "create_security_policies": "Create Security Policies",
    AUTHORIZE_APPLY: "Authorize Policy Apply",
    "environment": "Environment",
    "change_ticket": "Change Ticket",
    "authorized_by": "Authorized By",
}
RUN_CONTROL_KEYS_BY_LABEL = {v: k for k, v in RUN_CONTROL_LABELS.items()}
YES, NO = "Yes", "No"


def rc_label(key: str) -> str:
    """Human-readable Run_Control label for an internal key (used in messages)."""
    return RUN_CONTROL_LABELS.get(key, key)

# Every top-level key create_full_config.yml reads (written explicitly, even when empty).
YAML_SECTION_ORDER = (
    "dp_ip",
    "netclasses",
    "cl_protections",
    "cl_profiles",
    "oos_profiles",
    "bdos_profiles",
    "create_dns_profiles",
    "create_ssl_objects",
    "create_https_profiles",
    "create_tf_profiles",
    "create_tf_protections",
    "security_policy_config",
    "create_security_policies",
)
SECTION_TOGGLE = {
    "netclasses": "create_network_classes",
    "cl_protections": "create_cl_profiles",
    "cl_profiles": "create_cl_profiles",
    "oos_profiles": "create_out_of_state_profiles",
    "bdos_profiles": "create_bdos_profiles",
    "create_dns_profiles": "create_dns_profiles",
    "create_ssl_objects": "create_ssl_objects",
    "create_https_profiles": "create_https_profiles",
    "create_tf_profiles": "create_traffic_filter_profiles",
    "create_tf_protections": "create_traffic_filter_profiles",
    "create_security_policies": "create_security_policies",
}

# --------------------------------------------------------------------------- #
# External reference types
# --------------------------------------------------------------------------- #
EXT_TYPES = (
    "Network Class",
    "Connection Limit Profile",
    "Connection Limit Protection",
    "Traffic Filter Profile",
    "Out of State Profile",
    "BDoS Profile",
    "Signature Profile",
    "EAAF Profile",
    "Geolocation Profile",
    "SYN Flood Profile",
    "DNS Profile",
    "HTTPS Flood Profile",
)


def _enabled(header, key, cls, source, note="", in_params=False, ci=False, module_values=("enable", "disable")):
    return Field(header, key, "enum", cls, labels=ENABLED, module_values=module_values, case_insensitive=ci,
                 in_params=in_params, source=source, note=note)


# --------------------------------------------------------------------------- #
# Sheets
# --------------------------------------------------------------------------- #
DEVICES = SheetSpec(
    "Devices", "data",
    (
        Field("DefensePro Name", "name", "name", REQUIRED, note="Device name. Used for file names and preflight checks.", width=20),
        Field("DefensePro IP", "ip", "ipv4", REQUIRED, note="Written as dp_ip (exactly one IP per generated file).", width=18),
        Field("Include in this run?", "include", "yesno", REQUIRED, labels=(("Yes", "yes"), ("No", "no")),
              note="Yes = generate create_vars_<device>.yml. This does NOT authorize changes: preflight checks "
                   "the environment allowlist.", width=20),
    ),
    description="PURPOSE: list every DefensePro device this workbook describes. HOW TO FILL: one row per device - its name, management IP and Include in this run? = Yes for the device(s) you want a YAML file for (No = skip). The name must be identical on every other sheet. Yes does not authorize changes: the run still checks the environment allowlist.",
)

_POL = "plugins/modules/create_full_config.py"
POLICIES = SheetSpec(
    "Policies", "data",
    (
        DEVICE,
        Field("Policy Name", "policy_name", "name", REQUIRED, source=_POL, width=22),
        Field("Policy State", "state", "enum", EXPLICIT, labels=ENABLED, case_insensitive=True,
              module_values=("enable", "enabled", "active", "on", "disable", "disabled", "inactive", "off"),
              source=_POL + ": map_security_policy_parameters (unknown value -> enable)"),
        Field("Priority", "priority", "numeric_string", REQUIRED, minimum=1, maximum=1000, source=_POL,
              note="1-1000, lower = higher priority. Not in the device export."),
        Field("Direction", "direction", "enum", EXPLICIT, labels=(("One Way", "oneway"), ("Two Way", "twoway")),
              case_insensitive=True,
              module_values=("oneway", "one_way", "one-way", "twoway", "two_way", "two-way", "bidirectional", "both"),
              source=_POL + ": unknown value -> oneway", note="Not in the device export."),
        Field("Policy Block/Report", "action", "enum", EXPLICIT,
              labels=(("Block and Report", "block_and_report"), ("Report Only", "report_only"), ("Report", "report_only")),
              case_insensitive=True, module_values=("report_only", "report", "block_and_report", "block"),
              source=_POL + ": unknown value -> block_and_report"),
        Field("Policy Packet Reporting", "packet_reporting_status", "enum", EXPLICIT, labels=ENABLED, case_insensitive=True,
              module_values=("enable", "enabled", "on", "disable", "disabled", "off"), source=_POL),
        Field("SRC Network", "src_network", "ref", REQUIRED, ref="Network Class", source=_POL,
              note="'any' or a network class on Network_Classes / External_References."),
        Field("DST Network", "dst_network", "ref", REQUIRED, ref="Network Class", source=_POL),
        Field("Signature Profile", "signature_protection_profile", "ref", OPTIONAL, ref="Signature Profile", source=_POL),
        Field("Out of State Profile", "out_of_state_profile", "ref", OPTIONAL, ref="Out of State Profile", source=_POL),
        Field("EAAF Profile", "ert_attackers_feed_profile", "ref", OPTIONAL, ref="EAAF Profile", source=_POL),
        Field("Geolocation Profile", "geo_feed_profile", "ref", OPTIONAL, ref="Geolocation Profile", source=_POL),
        Field("Connection Limit Profile", "connection_limit_profile", "ref", OPTIONAL, ref="Connection Limit Profile", source=_POL),
        Field("SYN Flood Profile", "syn_protection_profile", "ref", OPTIONAL, ref="SYN Flood Profile", source=_POL),
        Field("Traffic Filter Profile", "traffic_filters_profile", "ref", OPTIONAL, ref="Traffic Filter Profile", source=_POL),
        Field("BDoS Profile", "bdos_profile", "ref", OPTIONAL, ref="BDoS Profile", source=_POL),
        Field("DNS Profile", "dns_flood_profile", "ref", OPTIONAL, ref="DNS Profile", source=_POL),
        Field("HTTPS Flood Profile", "https_flood_profile", "ref", OPTIONAL, ref="HTTPS Flood Profile", source=_POL),
        Field("Reference Check", None, "text", CHECK, width=40),
    ),
    toggle="create_security_policies", yaml_key="create_security_policies",
    description="PURPOSE: the security policies to create and the profiles bound to each one. HOW TO FILL: one row per policy per device. Fill Priority and Direction (not in the device export). Profile columns must name a profile defined on its own sheet in this workbook or declared on External_References; leave blank for no profile. The green Reference Check column shows OK or what is missing - do not edit it.",
)

_NC = "plugins/modules/create_network_class.py"
NETWORK_CLASSES = SheetSpec(
    "Network_Classes", "data",
    (
        DEVICE,
        Field("Network Class", "name", "name", REQUIRED, source=_NC, width=24),
        Field("Group Index", "group_index", "int", REQUIRED, minimum=0, source=_NC + ": index = position in groups[]",
              note="0, 1, 2 ... per class, no gaps. Groups are written in this order, so sorting the sheet is safe."),
        Field("Address", "address", "ip", REQUIRED, source=_NC, width=20),
        Field("Mask", "mask", "mask", REQUIRED, source=_NC,
              note="Prefix length (e.g. 24) or dotted mask (e.g. 255.255.255.0). Written exactly as entered."),
    ),
    toggle="create_network_classes", yaml_key="netclasses",
    description="PURPOSE: network classes (address groups) used as policy source/destination. HOW TO FILL: one row per address group. A class with 3 subnets = 3 rows with the same Network Class name and Group Index 0, 1, 2 (no gaps). Mask = prefix length (24) or dotted mask (255.255.255.0).",
)

_CL = "plugins/modules/create_cl_configuration.py: map_protection_parameters"
CL_PROTECTIONS = SheetSpec(
    "CL_Protections", "data",
    (
        DEVICE,
        Field("Protection Name", "name", "name", REQUIRED, source=_CL, width=24),
        Field("Protection ID", "index", "int", OPTIONAL, minimum=0, source=_CL + " (default 0 = allocated by device)",
              note="Optional. Blank = device allocates the index."),
        Field("Protection Type", "protection_type", "enum", EXPLICIT,
              labels=(("Connections per Second", "cps"), ("Concurrent Connections", "concurrent_connections")),
              module_values=("cps", "concurrent_connections"), source=_CL + " (unknown/blank -> cps)", width=22),
        Field("Protocol", "protocol", "enum", EXPLICIT, labels=(("TCP", "tcp"), ("UDP", "udp")),
              module_values=("tcp", "udp"), source=_CL + " (unknown/blank -> tcp)"),
        Field("App Port Group", "app_port_group", "port_group", EXPLICIT,
              source=_CL + " (blank -> \"\" = ALL PORTS)",
              note="Required. (all ports) writes \"\". Or http, https, dns, ftp, or a port number."),
        Field("Threshold", "threshold", "numeric_string", EXPLICIT, minimum=1, source=_CL + " (blank -> 50)"),
        Field("Tracking Type", "tracking_type", "enum", EXPLICIT,
              labels=(("Source Count", "src_ip"), ("Destination Count", "dst_ip"),
                      ("Source and Destination Count", "src_and_dest_ip"), ("Destination and Port Count", "dst_ip_and_port")),
              module_values=("src_ip", "dst_ip", "src_and_dest_ip", "dst_ip_and_port"),
              source=_CL + " (unknown/blank -> dst_ip)", width=24),
        Field("Action", "action", "enum", EXPLICIT, labels=(("Drop", "drop"), ("Report Only", "report_only")),
              module_values=("drop", "report_only"), source=_CL + " (unknown/blank -> drop)"),
        Field("Packet Reporting", "packet_report", "enum", EXPLICIT, labels=ENABLED, module_values=("enable", "disable"),
              source=_CL + " (unknown/blank -> disable)"),
    ),
    toggle="create_cl_profiles", yaml_key="cl_protections",
    description="PURPOSE: connection-limit protections (the individual rules). HOW TO FILL: one row per protection. Every orange column must be chosen - a blank would let the module apply a default (e.g. App Port Group blank = ALL ports, Action blank = Drop). Link protections to profiles on CL_Profile_Members.",
)

CL_PROFILE_MEMBERS = SheetSpec(
    "CL_Profile_Members", "data",
    (
        DEVICE,
        Field("Profile Name", "name", "name", REQUIRED, source="create_cl_configuration.py: cl_profiles[].name", width=24),
        Field("Protection Name", "protection", "ref", REQUIRED, ref="Connection Limit Protection",
              source="create_cl_configuration.py: cl_profiles[].protections[]", width=24),
    ),
    toggle="create_cl_profiles", yaml_key="cl_profiles",
    description="PURPOSE: groups connection-limit protections into connection-limit profiles. HOW TO FILL: one row per (profile, protection) link - a profile with 3 protections = 3 rows. Protection Name must exist on CL_Protections or be declared on External_References as a Connection Limit Protection.",
)

_TF = "plugins/modules/create_traffic_filter.py"
TF_PROFILES = SheetSpec(
    "TF_Profiles", "data",
    (
        DEVICE,
        Field("Profile Name", "profile_name", "name", REQUIRED, source=_TF, width=24),
        Field("Action", "action", "enum", EXPLICIT,
              labels=(("Block and Report", "block_and_report"), ("Report Only", "report_only")),
              module_values=("report_only", "block_and_report"),
              source=_TF + ": map_profile_parameters (unknown value -> block_and_report)"),
    ),
    toggle="create_traffic_filter_profiles", yaml_key="create_tf_profiles",
    description="PURPOSE: traffic-filter profiles (the containers for traffic-filter rules). HOW TO FILL: one row per profile with its Action. Add the rules of each profile on TF_Rules.",
)

TCP_FLAG_KEYS = (("SYN", "tcp_syn"), ("ACK", "tcp_ack"), ("RST", "tcp_rst"),
                 ("SYN-ACK", "tcp_synack"), ("FIN-ACK", "tcp_finack"), ("PSH-ACK", "tcp_pshack"))
TF_RULES = SheetSpec(
    "TF_Rules", "data",
    (
        DEVICE,
        Field("Profile Name", "profile_name", "ref", REQUIRED, ref="Traffic Filter Profile", source=_TF, width=22),
        Field("Rule Name", "protection_name", "name", REQUIRED, source=_TF, width=24),
        Field("Protection ID", None, "int", INFO, note="From the export. create_traffic_filter.py has no index parameter; not converted."),
        Field("Status", "status", "enum", EXPLICIT, labels=ENABLED, module_values=("enable", "disable"),
              source=_TF + " (blank -> enable)", note="Not in the device export."),
        Field("Match Criteria", "match_criteria", "enum", EXPLICIT, labels=(("Match", "match"), ("Not Match", "not-match")),
              module_values=("match", "not-match"), source=_TF + " (blank -> match)", note="Not in the device export."),
        Field("Protocol", "protocol", "enum", EXPLICIT,
              labels=(("Any Supported Protocol", "any"), ("TCP", "tcp"), ("UDP", "udp"), ("ICMP", "icmp"),
                      ("IGMP", "igmp"), ("SCTP", "sctp"), ("ICMPv6", "icmpv6"), ("GRE", "gre"), ("IP-in-IP", "ipinip")),
              module_values=("any", "tcp", "udp", "icmp", "igmp", "sctp", "icmpv6", "gre", "ipinip"),
              source=_TF + " (unknown -> any)", width=22),
        Field("TCP Flags", "tcp_flags", "tcp_flags", EXPLICIT, source=_TF + " (each flag blank -> enable)",
              note="Required when Protocol is TCP or Any: (all flags) or a comma list of SYN, ACK, RST, SYN-ACK, "
                   "FIN-ACK, PSH-ACK. Leave blank for other protocols.", width=20),
        Field("Threshold Unit", "threshold_unit", "enum", EXPLICIT, labels=(("PPS", "pps"), ("Kbps", "kbps")),
              module_values=("pps", "kbps"), source=_TF + " (blank -> pps)"),
        Field("Threshold (PPS)", "threshold_pps", "numeric_string", OPTIONAL, minimum=0, source=_TF + " (blank -> 10000)",
              note="Required when Threshold Unit = PPS."),
        Field("Threshold (Kbps)", "threshold_kbps", "numeric_string", OPTIONAL, minimum=0, source=_TF + " (blank -> 0)",
              note="Required when Threshold Unit = Kbps."),
        Field("Tracking Mode", "attack_tracking_type", "enum", EXPLICIT,
              labels=(("All", "all"), ("Per Source", "per_source"), ("Per Destination", "per_destination"),
                      ("Per Source and Destination", "per_source_and_destination"),
                      ("Track Returning Traffic", "track_returning_traffic")),
              module_values=("all", "per_source", "per_destination", "per_source_and_destination", "track_returning_traffic"),
              source=_TF + " (unknown -> all)", width=22),
        Field("Packet Reporting", "packet_report", "enum", EXPLICIT, labels=ENABLED, module_values=("enable", "disable"),
              source=_TF + " (blank -> enable)"),
    ),
    toggle="create_traffic_filter_profiles", yaml_key="create_tf_protections",
    description="PURPOSE: traffic-filter rules inside the profiles on TF_Profiles. HOW TO FILL: one row per rule. Profile Name must exist on TF_Profiles. Fill every orange column; TCP Flags is required for Protocol TCP or Any (choose (all flags) or e.g. SYN,ACK) and must be blank for other protocols. Fill the threshold that matches Threshold Unit.",
)

_OOS = "plugins/modules/create_oos_profile.py: map_oos_profile_parameters"
OOS_PROFILES = SheetSpec(
    "OOS_Profiles", "data",
    (
        DEVICE,
        Field("Profile Name", "name", "name", REQUIRED, source=_OOS, width=22),
        Field("Action", "action", "enum", EXPLICIT, labels=(("Block and Report", "block_and_report"), ("Report Only", "report_only")),
              module_values=("report_only", "block_and_report"), case_insensitive=True, in_params=True,
              source=_OOS + " (blank -> device default)"),
        Field("Activation Threshold", "act_threshold", "int", OPTIONAL, minimum=0, in_params=True, source=_OOS),
        Field("Termination Threshold", "term_threshold", "int", OPTIONAL, minimum=0, in_params=True, source=_OOS),
        _enabled("SYN-ACK Allow", "syn_ack_allow", OPTIONAL, _OOS, in_params=True, ci=True),
        _enabled("Packet Reporting", "packet_report", OPTIONAL, _OOS, in_params=True, ci=True),
        Field("Risk", "risk", "enum", OPTIONAL, labels=(("Info", "info"), ("Low", "low"), ("Medium", "medium"), ("High", "high")),
              module_values=("info", "low", "medium", "high"), case_insensitive=True, in_params=True, source=_OOS),
        _enabled("Idle State", "idle_state", OPTIONAL, _OOS, in_params=True, ci=True),
        Field("Idle State Bandwidth Threshold", "idle_state_bandwidth_threshold", "int", OPTIONAL, minimum=0, in_params=True, source=_OOS),
        Field("Idle State Timer", "idle_state_timer", "int", OPTIONAL, minimum=0, in_params=True, source=_OOS),
    ),
    toggle="create_out_of_state_profiles", yaml_key="oos_profiles",
    description="PURPOSE: out-of-state (TCP state) protection profiles. HOW TO FILL: one row per profile. Profile Name and Action are required; blue columns are optional - blank keeps the device default (listed in the validation report).",
)

_BD = "plugins/modules/create_bdos_profile.py: map_netflood_profile_parameters"


def _bd_enabled(header, key):
    return _enabled(header, key, OPTIONAL, _BD, in_params=True, ci=True)


def _bd_quota(header, key):
    return Field(header, key, "int", OPTIONAL, minimum=0, maximum=100, in_params=True, source=_BD)


BDOS_PROFILES = SheetSpec(
    "BDoS_Profiles", "data",
    (
        DEVICE,
        Field("Profile Name", "name", "name", REQUIRED, source=_BD, width=22),
        Field("Action", "action", "enum", EXPLICIT, labels=(("Block and Report", "block_&_report"), ("Report Only", "report_only")),
              module_values=("report_only", "block_&_report"), case_insensitive=True, in_params=True,
              source=_BD + " (blank -> device default)"),
        Field("Inbound Traffic (kbps)", "inbound_traffic", "int", EXPLICIT, minimum=1, maximum=1342177280, in_params=True,
              source=_BD, note="Export column 'BDOS Profile Bandwidth'."),
        Field("Outbound Traffic (kbps)", "outbound_traffic", "int", EXPLICIT, minimum=1, maximum=1342177280, in_params=True,
              source=_BD, note="Not in the device export."),
        _bd_enabled("SYN Flood", "syn_flood"),
        _bd_enabled("UDP Flood", "udp_flood"),
        _bd_enabled("IGMP Flood", "igmp_flood"),
        _bd_enabled("ICMP Flood", "icmp_flood"),
        _bd_enabled("TCP ACK-FIN Flood", "tcp_ack_fin_flood"),
        _bd_enabled("TCP RST Flood", "tcp_rst_flood"),
        _bd_enabled("TCP PSH-ACK Flood", "tcp_psh_ack_flood"),
        _bd_enabled("TCP SYN-ACK Flood", "tcp_syn_ack_flood"),
        _bd_enabled("TCP Frag Flood", "tcp_frag_flood"),
        _bd_enabled("UDP Frag Flood", "udp_frag_flood"),
        _bd_quota("TCP In Quota %", "tcp_in_quota"),
        _bd_quota("UDP In Quota %", "udp_in_quota"),
        _bd_quota("ICMP In Quota %", "icmp_in_quota"),
        _bd_quota("IGMP In Quota %", "igmp_in_quota"),
        _bd_quota("TCP Out Quota %", "tcp_out_quota"),
        _bd_quota("UDP Out Quota %", "udp_out_quota"),
        _bd_quota("ICMP Out Quota %", "icmp_out_quota"),
        _bd_quota("IGMP Out Quota %", "igmp_out_quota"),
        _bd_enabled("Transparent Optimization", "transparent_optimization"),
        _bd_enabled("Packet Reporting", "packet_report"),
        _bd_enabled("Burst-Attack Protection", "burst_attack"),
        Field("Max Interval Between Bursts (min)", "maximum_interval_between_bursts", "int", OPTIONAL, minimum=1, maximum=336,
              in_params=True, source=_BD),
        Field("Learning Suppression", "learning_suppression_threshold", "int", OPTIONAL, minimum=0, maximum=50,
              in_params=True, source=_BD),
        Field("Footprint Strictness", "footprint_strictness", "enum", OPTIONAL,
              labels=(("Low", "low"), ("Medium", "medium"), ("High", "high")), module_values=("low", "medium", "high"),
              case_insensitive=True, in_params=True, source=_BD),
        Field("UDP Packet Rate Sensitivity", "udp_packet_rate_detection_sensitivity", "enum", OPTIONAL,
              labels=(("Ignore", "ignore"), ("Low", "low"), ("Medium", "medium"), ("High", "high")),
              module_values=("ignore", "low", "medium", "high"), case_insensitive=True, in_params=True, source=_BD),
        Field("BDoS Rate Limit", "bdos_rate_limit", "enum", OPTIONAL,
              labels=(("Disable", "disable"), ("Normal Edge", "normal_edge"), ("Suspect Edge", "suspect_edge"),
                      ("User Defined", "user_defined")),
              module_values=("disable", "normal_edge", "suspect_edge", "user_defined"), case_insensitive=True,
              in_params=True, source=_BD),
        Field("User Defined Rate Limit", "user_defined_rate_limit", "int", OPTIONAL, minimum=0, maximum=400000000,
              in_params=True, source=_BD, note="Required when BDoS Rate Limit = User Defined."),
        Field("User Defined Rate Limit Unit", "user_defined_rate_limit_unit", "enum", OPTIONAL,
              labels=(("Kbps", "kbps"), ("Mbps", "mbps"), ("Gbps", "gbps")), module_values=("kbps", "mbps", "gbps"),
              case_insensitive=True, in_params=True, source=_BD, note="Required when BDoS Rate Limit = User Defined."),
        _bd_enabled("Adv UDP Detection", "adv_udp_detection"),
    ),
    toggle="create_bdos_profiles", yaml_key="bdos_profiles",
    description="PURPOSE: BDoS (behavioral DoS) profiles. HOW TO FILL: one row per profile. Profile Name, Action, Inbound and Outbound Traffic are required; blue columns are optional - blank keeps the device default. User Defined Rate Limit and its Unit are required when BDoS Rate Limit = User Defined.",
)

EXTERNAL_REFERENCES = SheetSpec(
    "External_References", "data",
    (
        DEVICE,
        Field("Type", "type", "enum", REQUIRED, labels=tuple((t, t) for t in EXT_TYPES), width=24),
        Field("Name", "name", "name", REQUIRED, width=24),
        Field("Reason", "reason", "text", OPTIONAL, width=50),
    ),
    tab="C55A11",
    description="PURPOSE: declares objects that ALREADY EXIST on the device and that this workbook only refers to by name - nothing is created from this sheet. WHY IT IS NEEDED: policies can bind profiles this tool cannot create (Signature, EAAF, Geolocation, SYN Flood, DNS, HTTPS Flood) or objects created earlier. Every name used on Policies / CL_Profile_Members / TF_Rules must be defined on its sheet OR declared here, otherwise validation stops - this catches typos before the device rejects the policy halfway through a run. HOW TO FILL: one row per existing object - device, Type, exact Name as on the device, and a Reason. Declared names are reported as UNVERIFIED. Leave empty if every referenced object is created by this workbook.",
)

RUN_CONTROL = SheetSpec("Run_Control", "control", tab="C55A11",
                        description="PURPOSE: controls what the run does - which sections are created, the target environment and the approval to apply policies. HOW TO FILL: set every Create ... row to Yes or No (DNS, HTTPS Flood and SSL must stay No). Keep Authorize Policy Apply = No until the change is approved; Yes (or Environment = production) requires Change Ticket and Authorized By. Only edit the yellow Value column. The check at the bottom must show OK.")

DATA_SHEETS = (DEVICES, POLICIES, NETWORK_CLASSES, CL_PROTECTIONS, CL_PROFILE_MEMBERS, TF_PROFILES, TF_RULES,
               OOS_PROFILES, BDOS_PROFILES, EXTERNAL_REFERENCES)
REFERENCE_SHEETS = ("DNS_Profiles", "SYN_Profiles", "SYN_Protections")   # kept from the export, never converted
REFERENCE_SHEET_DESCRIPTION = ("PURPOSE: information copied from the device export for reference only. NOTHING on this "
                               "sheet is converted or sent to the device. HOW TO USE: read only - to use one of these "
                               "profiles in a policy, declare it on External_References.")
VALUE_MAP_DESCRIPTION = ("PURPOSE: shows, for every dropdown column, which YAML value each Excel choice writes. HOW TO "
                         "USE: read only - use it to check what a choice means for the Ansible modules.")
META_SHEETS = ("README", "Value_Map", "_Lists", "_Meta")
SHEET_ORDER = ("README", "Devices", "Run_Control", "Policies", "Network_Classes", "CL_Protections",
               "CL_Profile_Members", "TF_Profiles", "TF_Rules", "OOS_Profiles", "BDoS_Profiles",
               "External_References") + REFERENCE_SHEETS + ("Value_Map", "_Lists", "_Meta")
SHEETS: Dict[str, SheetSpec] = {s.name: s for s in DATA_SHEETS}
SHEETS["Run_Control"] = RUN_CONTROL

# Where each reference type can be defined inside the workbook (sheet, key field, governing toggle)
INTERNAL_REF_SOURCES = {
    "Network Class": ("Network_Classes", "name", "create_network_classes"),
    "Connection Limit Profile": ("CL_Profile_Members", "name", "create_cl_profiles"),
    "Connection Limit Protection": ("CL_Protections", "name", "create_cl_profiles"),
    "Traffic Filter Profile": ("TF_Profiles", "profile_name", "create_traffic_filter_profiles"),
    "Out of State Profile": ("OOS_Profiles", "name", "create_out_of_state_profiles"),
    "BDoS Profile": ("BDoS_Profiles", "name", "create_bdos_profiles"),
}

# Port groups accepted for app_port_group (custom port numbers are also accepted)
PORT_GROUPS = ("http", "https", "dns", "ftp")
ALL_PORTS_TOKEN = "(all ports)"
ALL_FLAGS_TOKEN = "(all flags)"
