# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Automotive CTF-like environment with segmented in-vehicle networks.

Bus topology (intended attack graph):
- External attacker (AttackerLaptop)
  -> Wireless entry: IVI (WIFI/BT/HTTPS) -> IVI[user=media] shell
  -> Cellular entry: Telematics (CELL/HTTPS) -> Telematics[user=root] shell
  -> Physical entry: OBD (USB) -> DCAN credential

- Pivot to GTW (Gateway):
  - via IVI[user=media] using ETH_MGMT + gtw_admin_token
  - OR via OBD using DCAN + dcan_access
  - OR via Telematics[user=root] using OTA + ota_update_token (token obtained from OTA.Server)

- GTW then leaks bus access creds:
  - bcan_access / ccan_access / lin_access

- Own buses:
  - connect_and_infect(GTW -> BCAN, "BCAN", bcan_access)
  - connect_and_infect(GTW -> CCAN, "CCAN", ccan_access)
  - connect_and_infect(GTW -> LIN,  "LIN",  lin_access)

- Impact-only attacks are LOCAL on bus nodes (not remote on ECUs).
- Full compromise chain: owned bus node -> connect_and_infect(bus -> ECU, *_DIAG, bus_access) -> ECU becomes owned -> LOCAL post-compromise dumps.
"""

from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID, VulnerabilityInfo
from typing import Dict, Iterator, cast, Tuple

# ---- Ports / Services
PORT_WIFI = "WIFI"
PORT_BT = "BT"
PORT_CELL = "CELL"
PORT_USB = "USB"
PORT_HTTPS = "HTTPS"
PORT_SHELL = "SHELL"

PORT_ETH_MGMT = "ETH_MGMT"   # IVI -> GTW management plane
PORT_OTA = "OTA"             # Telematics -> GTW OTA/update channel

PORT_BCAN = "BCAN"           # Body CAN
PORT_CCAN = "CCAN"           # Chassis CAN
PORT_DCAN = "DCAN"           # Diagnostic CAN (OBD)
PORT_LIN  = "LIN"            # LIN

PORT_BCAN_DIAG = "BCAN_DIAG"
PORT_CCAN_DIAG = "CCAN_DIAG"
PORT_LIN_DIAG  = "LIN_DIAG"

def allow(*ports: str):
    return [m.FirewallRule(p, m.RulePermission.ALLOW) for p in ports]

# ---- Nodes
nodes = {
    # -------------------------------------------------------------------------
    # External attacker foothold
    # -------------------------------------------------------------------------
    "AttackerLaptop": m.NodeInfo(
        services=[],
        firewall=m.FirewallConfiguration(
            incoming=allow(PORT_HTTPS, PORT_WIFI, PORT_BT, PORT_CELL, PORT_USB, PORT_SHELL),
            # 현실성: 외부 공격자는 내부 버스/관리 포트로 직접 못 나간다고 가정
            outgoing=allow(PORT_HTTPS, PORT_WIFI, PORT_BT, PORT_CELL, PORT_USB, PORT_SHELL),
        ),
        value=0,
        properties=["Attacker", "Laptop", "Tools"],
        vulnerabilities=dict(
            ScanWirelessVicinity=m.VulnerabilityInfo(
                description="Discover nearby endpoints (IVI/Telematics) and presence of OBD port.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["IVI", "Telematics", "OBD"]),
                reward_string="Discovered IVI, Telematics, and the OBD interface.",
                cost=1.0,
            ),
            AcquireOBDDongle=m.VulnerabilityInfo(
                description="Acquire OBD dongle (physical) enabling USB access to OBD node.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="OBD", port=PORT_USB, credential="obd_dongle_token")
                ]),
                reward_string="Acquired OBD dongle token.",
                cost=1.0,
            ),
        ),
        agent_installed=True,
        reimagable=False,
    ),

    # -------------------------------------------------------------------------
    # IVI entry (wireless)
    # -------------------------------------------------------------------------
    "IVI": m.NodeInfo(
        services=[m.ListeningService(PORT_WIFI), m.ListeningService(PORT_BT), m.ListeningService(PORT_HTTPS)],
        firewall=m.FirewallConfiguration(
            incoming=allow(PORT_WIFI, PORT_BT, PORT_HTTPS),
            # IVI는 GW 관리/진단(DCAN) 방향만 의미 있게 통신 가능
            outgoing=allow(PORT_ETH_MGMT, PORT_DCAN),
        ),
        value=80,
        properties=["IVI", "Android", "WebView"],
        vulnerabilities=dict(
            ExploitWebViewRCE=m.VulnerabilityInfo(
                description="Exploit IVI WebView to obtain a media shell credential.",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="IVI[user=media]", port=PORT_SHELL, credential="ivi_media_shell")
                ]),
                rates=m.Rates(successRate=1.0, probingDetectionRate=0.0, exploitDetectionRate=0.0),
                reward_string="WebView exploit: obtained IVI media shell credential.",
                cost=2.0,
            ),
            ReadInfotainmentData=m.VulnerabilityInfo(
                description="Collect infotainment data (impact-only).",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="Collected infotainment data.",
                cost=1.0,
            ),
        ),
    ),

    "IVI[user=media]": m.NodeInfo(
        services=[m.ListeningService(PORT_SHELL, allowedCredentials=["ivi_media_shell"])],
        firewall=m.FirewallConfiguration(
            incoming=allow(PORT_SHELL),
            outgoing=allow(PORT_ETH_MGMT, PORT_DCAN),  # IVI media도 GW/진단 방향만
        ),
        value=60,
        properties=["IVI", "PostExploitation"],
        owned_string="FLAG: IVI media shell obtained.",
        vulnerabilities=dict(
            DiscoverGatewayNode=m.VulnerabilityInfo(
                description="Discover GTW from routing / proxy configuration.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["GTW"]),
                reward_string="Discovered GTW from IVI routing metadata.",
                cost=0.5,
            ),
            DumpGatewayAdminToken=m.VulnerabilityInfo(
                description="Dump GTW admin token used for ETH_MGMT access.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="GTW", port=PORT_ETH_MGMT, credential="gtw_admin_token")
                ]),
                reward_string="Dumped gtw_admin_token.",
                cost=1.0,
            ),
            ExtractOTASessionToken=m.VulnerabilityInfo(
                description="Extract cached OTA session token (for OTA.Server HTTPS).",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="OTA.Server", port=PORT_HTTPS, credential="ota_session_token")
                ]),
                reward_string="Extracted ota_session_token.",
                cost=1.0,
            ),
        ),
    ),

    # -------------------------------------------------------------------------
    # OBD -> DCAN
    # -------------------------------------------------------------------------
    "OBD": m.NodeInfo(
        services=[m.ListeningService(PORT_USB, allowedCredentials=["obd_dongle_token"])],
        firewall=m.FirewallConfiguration(
            incoming=allow(PORT_USB),
            outgoing=allow(PORT_DCAN),
        ),
        value=40,
        properties=["OBD", "Physical"],
        owned_string="FLAG: OBD access established.",
        vulnerabilities=dict(
            EnableDCANAccess=m.VulnerabilityInfo(
                description="Enable diagnostic CAN access and obtain dcan_access credential.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="DCAN", port=PORT_DCAN, credential="dcan_access"),
                    m.CachedCredential(node="GTW",  port=PORT_DCAN, credential="dcan_access"),
                ]),
                reward_string="Enabled DCAN access (dcan_access).",
                cost=1.0,
            )
        ),
    ),

    "DCAN": m.NodeInfo(
        services=[m.ListeningService(PORT_DCAN, allowedCredentials=["dcan_access"])],
        firewall=m.FirewallConfiguration(
            incoming=allow(PORT_DCAN),
            outgoing=allow(PORT_DCAN),
        ),
        value=10,
        properties=["Bus", "DCAN"],
        owned_string="DCAN node owned (diagnostic bus access).",
    ),

    # -------------------------------------------------------------------------
    # Telematics + OTA backend (cellular path)
    # -------------------------------------------------------------------------
    "Telematics": m.NodeInfo(
        services=[m.ListeningService(PORT_CELL), m.ListeningService(PORT_HTTPS)],
        firewall=m.FirewallConfiguration(
            incoming=allow(PORT_CELL, PORT_HTTPS),
            outgoing=allow(PORT_HTTPS, PORT_SHELL),
        ),
        value=50,
        properties=["Telematics", "RemoteService"],
        vulnerabilities=dict(
            ExploitTelematicsRCE=m.VulnerabilityInfo(
                description="Exploit Telematics unit to get a root shell credential.",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="Telematics[user=root]", port=PORT_SHELL, credential="tcu_root_shell")
                ]),
                rates=m.Rates(successRate=1.0, probingDetectionRate=0.0, exploitDetectionRate=0.0),
                reward_string="Telematics RCE: obtained tcu_root_shell.",
                cost=2.0,
            ),
            DiscoverOTAServer=m.VulnerabilityInfo(
                description="Discover OTA backend endpoint.",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId(["OTA.Server"]),
                rates=m.Rates(successRate=1.0, probingDetectionRate=0.0, exploitDetectionRate=0.0),
                reward_string="Discovered OTA.Server endpoint.",
                cost=1.0,
            ),
            AbuseRemoteControlAPI=m.VulnerabilityInfo(
                description="Abuse weak API to obtain OTA session token.",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="OTA.Server", port=PORT_HTTPS, credential="ota_session_token")
                ]),
                rates=m.Rates(successRate=1.0, probingDetectionRate=0.0, exploitDetectionRate=0.0),
                reward_string="Obtained ota_session_token via telematics.",
                cost=2.0,
            ),
        ),
    ),

    "Telematics[user=root]": m.NodeInfo(
        services=[m.ListeningService(PORT_SHELL, allowedCredentials=["tcu_root_shell"])],
        firewall=m.FirewallConfiguration(
            incoming=allow(PORT_SHELL),
            # Telematics는 OTA/HTTPS만 (내부에서 GTW OTA 채널로 접근 가능)
            outgoing=allow(PORT_HTTPS, PORT_OTA),
        ),
        value=60,
        properties=["Telematics", "PostExploitation"],
        owned_string="FLAG: Telematics root shell obtained.",
        vulnerabilities=dict(
            # (선택) 여기서 IVI/WIFI 키를 덤프해서 IVI 공격을 쉽게 만들 수도 있음
            DumpVehicleBackendConfig=m.VulnerabilityInfo(
                description="Dump backend config / endpoints (impact-only).",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="Dumped Telematics backend config.",
                cost=1.0,
            )
        ),
    ),

    "OTA.Server": m.NodeInfo(
        services=[m.ListeningService(PORT_HTTPS, allowedCredentials=["ota_session_token"])],
        firewall=m.FirewallConfiguration(
            incoming=allow(PORT_HTTPS),
            outgoing=allow(PORT_HTTPS),
        ),
        value=40,
        properties=["OTA", "Backend"],
        vulnerabilities=dict(
            StealFirmwareArtifacts=m.VulnerabilityInfo(
                description="Steal firmware artifacts (impact-only).",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="Collected firmware artifacts.",
                cost=1.0,
            ),
            DownloadUpdateBundle=m.VulnerabilityInfo(
                description="Download update bundle and extract ota_update_token for GTW OTA port.",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="GTW", port=PORT_OTA, credential="ota_update_token")
                ]),
                rates=m.Rates(successRate=1.0),
                reward_string="Obtained ota_update_token.",
                cost=1.0,
            ),
        ),
    ),

    # -------------------------------------------------------------------------
    # GTW bridges buses: DCAN <-> BCAN/CCAN/LIN
    # -------------------------------------------------------------------------
    "GTW": m.NodeInfo(
        services=[
            m.ListeningService(PORT_ETH_MGMT, allowedCredentials=["gtw_admin_token"]),
            m.ListeningService(PORT_DCAN, allowedCredentials=["dcan_access"]),
            m.ListeningService(PORT_OTA, allowedCredentials=["ota_update_token"]),
        ],
        firewall=m.FirewallConfiguration(
            incoming=allow(PORT_ETH_MGMT, PORT_DCAN, PORT_OTA),
            # GTW는 버스 세그먼트로만 나갈 수 있음 (외부/무선로 직접 X)
            outgoing=allow(PORT_BCAN, PORT_CCAN, PORT_LIN, PORT_DCAN),
        ),
        value=120,
        properties=["Gateway", "Bridge"],
        owned_string="FLAG: GTW compromised.",
        vulnerabilities=dict(
            LeakBusTopology=m.VulnerabilityInfo(
                description="Reveal bus segments connected to GTW.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["BCAN", "CCAN", "LIN", "DCAN"]),
                reward_string="Discovered bus topology (BCAN/CCAN/LIN/DCAN).",
                cost=0.5,
            ),
            EnumerateECUs=m.VulnerabilityInfo(
                description="Enumerate ECUs behind each bus.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["BCM", "DoorLockECU", "ESP", "VCU", "ADAS", "IMU", "BMS", "Airbag"]),
                reward_string="Enumerated ECUs on BCAN/CCAN/LIN.",
                cost=1.0,
            ),
            DumpBusAccessCreds=m.VulnerabilityInfo(
                description="Dump internal bus access credentials (simplified; no SecOC).",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedCredentials(credentials=[
                    m.CachedCredential(node="BCAN", port=PORT_BCAN, credential="bcan_access"),
                    m.CachedCredential(node="CCAN", port=PORT_CCAN, credential="ccan_access"),
                    m.CachedCredential(node="LIN",  port=PORT_LIN,  credential="lin_access"),
                ]),
                reward_string="Dumped bus access creds: bcan_access / ccan_access / lin_access.",
                cost=1.0,
            ),
        ),
    ),

    # -------------------------------------------------------------------------
    # Bus segment nodes: impact-only attacks are LOCAL here
    # -------------------------------------------------------------------------
    "BCAN": m.NodeInfo(
        services=[m.ListeningService(PORT_BCAN, allowedCredentials=["bcan_access"])],
        firewall=m.FirewallConfiguration(
            incoming=allow(PORT_BCAN),
            outgoing=allow(PORT_BCAN_DIAG),
        ),
        value=10,
        properties=["Bus", "BCAN"],
        owned_string="BCAN access established.",
        vulnerabilities=dict(
            ImpactUnlockDoors=m.VulnerabilityInfo(
                description="Impact-only: replay/spoof frames to unlock doors on Body CAN.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="FLAG: doors unlocked via BCAN (impact-only).",
                cost=1.0,
            ),
            ImpactDoorActuation=m.VulnerabilityInfo(
                description="Impact-only: actuate door lock via Body CAN.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="FLAG: door actuation triggered via BCAN (impact-only).",
                cost=1.0,
            ),
        ),
    ),

    "CCAN": m.NodeInfo(
        services=[m.ListeningService(PORT_CCAN, allowedCredentials=["ccan_access"])],
        firewall=m.FirewallConfiguration(
            incoming=allow(PORT_CCAN),
            outgoing=allow(PORT_CCAN_DIAG),
        ),
        value=10,
        properties=["Bus", "CCAN"],
        owned_string="CCAN access established.",
        vulnerabilities=dict(
            ImpactBrakeSpoof=m.VulnerabilityInfo(
                description="Impact-only: spoof brake/stability frames (safety impact).",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="FLAG: brake/stability spoofed via CCAN (impact-only).",
                cost=2.0,
            ),
            ImpactDriveModeChange=m.VulnerabilityInfo(
                description="Impact-only: modify a drive mode parameter.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="FLAG: powertrain parameter modified via CCAN (impact-only).",
                cost=2.0,
            ),
            ImpactSpoofADAS=m.VulnerabilityInfo(
                description="Impact-only: spoof ADAS inputs/alerts.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="FLAG: ADAS inputs spoofed via CCAN (impact-only).",
                cost=2.0,
            ),
            ImpactReadIMU=m.VulnerabilityInfo(
                description="Impact-only: read/eavesdrop IMU-related frames (privacy).",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="FLAG: IMU stream collected via CCAN (impact-only).",
                cost=1.0,
            ),
            ImpactModifyBatteryTelemetry=m.VulnerabilityInfo(
                description="Impact-only: modify BMS telemetry via CCAN.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="FLAG: BMS telemetry modified via CCAN (impact-only).",
                cost=2.0,
            ),
        ),
    ),

    "LIN": m.NodeInfo(
        services=[m.ListeningService(PORT_LIN, allowedCredentials=["lin_access"])],
        firewall=m.FirewallConfiguration(
            incoming=allow(PORT_LIN),
            outgoing=allow(PORT_LIN_DIAG),
        ),
        value=10,
        properties=["Bus", "LIN"],
        owned_string="LIN access established.",
        vulnerabilities=dict(
            ImpactTamperAirbagStatus=m.VulnerabilityInfo(
                description="Impact-only: tamper airbag status signals over LIN (simplified).",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="FLAG: airbag status tampered via LIN (impact-only).",
                cost=3.0,
            )
        ),
    ),

    # -------------------------------------------------------------------------
    # ECUs: no CAN/LIN impact REMOTE vulns here.
    # Compromise path is via *_DIAG port (connect_and_infect from owned bus node).
    # -------------------------------------------------------------------------
    "BCM": m.NodeInfo(
        services=[m.ListeningService(PORT_BCAN_DIAG, allowedCredentials=["bcan_access"])],
        firewall=m.FirewallConfiguration(incoming=allow(PORT_BCAN_DIAG), outgoing=[]),
        value=80,
        properties=["ECU", "Body", "BCAN"],
        owned_string="BCM owned (diagnostic session established).",
        vulnerabilities=dict(
            DumpBCMConfig=m.VulnerabilityInfo(
                description="Post-compromise local: dump BCM configuration/keys.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="Dumped BCM config (post-compromise).",
                cost=1.0,
            ),
        ),
    ),

    "DoorLockECU": m.NodeInfo(
        services=[m.ListeningService(PORT_BCAN_DIAG, allowedCredentials=["bcan_access"])],
        firewall=m.FirewallConfiguration(incoming=allow(PORT_BCAN_DIAG), outgoing=[]),
        value=50,
        properties=["ECU", "Body", "BCAN"],
        owned_string="DoorLockECU owned (diagnostic session established).",
        vulnerabilities=dict(
            DumpDoorLockFirmware=m.VulnerabilityInfo(
                description="Post-compromise local: dump firmware image.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="Dumped DoorLock ECU firmware (post-compromise).",
                cost=1.0,
            ),
        ),
    ),

    "ESP": m.NodeInfo(
        services=[m.ListeningService(PORT_CCAN_DIAG, allowedCredentials=["ccan_access"])],
        firewall=m.FirewallConfiguration(incoming=allow(PORT_CCAN_DIAG), outgoing=[]),
        value=120,
        properties=["ECU", "Chassis", "CCAN"],
        owned_string="ESP owned (diagnostic session established).",
        vulnerabilities=dict(
            DumpESPParams=m.VulnerabilityInfo(
                description="Post-compromise local: dump calibration/parameters.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="Dumped ESP parameters (post-compromise).",
                cost=1.0,
            ),
        ),
    ),

    "VCU": m.NodeInfo(
        services=[m.ListeningService(PORT_CCAN_DIAG, allowedCredentials=["ccan_access"])],
        firewall=m.FirewallConfiguration(incoming=allow(PORT_CCAN_DIAG), outgoing=[]),
        value=100,
        properties=["ECU", "Powertrain", "CCAN"],
        owned_string="VCU owned (diagnostic session established).",
        vulnerabilities=dict(
            DumpVCUState=m.VulnerabilityInfo(
                description="Post-compromise local: dump internal state.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="Dumped VCU state (post-compromise).",
                cost=1.0,
            ),
        ),
    ),

    "ADAS": m.NodeInfo(
        services=[m.ListeningService(PORT_CCAN_DIAG, allowedCredentials=["ccan_access"])],
        firewall=m.FirewallConfiguration(incoming=allow(PORT_CCAN_DIAG), outgoing=[]),
        value=70,
        properties=["ECU", "ADAS", "CCAN"],
        owned_string="ADAS owned (diagnostic session established).",
        vulnerabilities=dict(
            DumpADASModel=m.VulnerabilityInfo(
                description="Post-compromise local: dump ADAS model/config.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="Dumped ADAS config/model (post-compromise).",
                cost=1.0,
            ),
        ),
    ),

    "IMU": m.NodeInfo(
        services=[m.ListeningService(PORT_CCAN_DIAG, allowedCredentials=["ccan_access"])],
        firewall=m.FirewallConfiguration(incoming=allow(PORT_CCAN_DIAG), outgoing=[]),
        value=40,
        properties=["ECU", "Sensor", "CCAN"],
        owned_string="IMU owned (diagnostic session established).",
        vulnerabilities=dict(
            DumpIMUOffsets=m.VulnerabilityInfo(
                description="Post-compromise local: dump sensor calibration.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="Dumped IMU calibration (post-compromise).",
                cost=1.0,
            ),
        ),
    ),

    "BMS": m.NodeInfo(
        services=[m.ListeningService(PORT_CCAN_DIAG, allowedCredentials=["ccan_access"])],
        firewall=m.FirewallConfiguration(incoming=allow(PORT_CCAN_DIAG), outgoing=[]),
        value=90,
        properties=["ECU", "Energy", "CCAN"],
        owned_string="BMS owned (diagnostic session established).",
        vulnerabilities=dict(
            DumpBMSProfile=m.VulnerabilityInfo(
                description="Post-compromise local: dump battery profile/params.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="Dumped BMS profile (post-compromise).",
                cost=1.0,
            ),
        ),
    ),

    "Airbag": m.NodeInfo(
        services=[m.ListeningService(PORT_LIN_DIAG, allowedCredentials=["lin_access"])],
        firewall=m.FirewallConfiguration(incoming=allow(PORT_LIN_DIAG), outgoing=[]),
        value=110,
        properties=["ECU", "Safety", "LIN"],
        owned_string="Airbag ECU owned (diagnostic session established).",
        vulnerabilities=dict(
            DumpCrashLogs=m.VulnerabilityInfo(
                description="Post-compromise local: dump crash logs / diagnostics.",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.CustomerData(),
                rates=m.Rates(successRate=1.0),
                reward_string="Dumped airbag crash logs (post-compromise).",
                cost=1.0,
            ),
        ),
    ),
}

global_vulnerability_library: Dict[VulnerabilityID, VulnerabilityInfo] = dict([])

ENV_IDENTIFIERS = m.infer_constants_from_nodes(
    cast(Iterator[Tuple[NodeID, NodeInfo]], list(nodes.items())),
    global_vulnerability_library,
)

def new_environment() -> m.Environment:
    return m.Environment(
        network=m.create_network(nodes),
        vulnerability_library=global_vulnerability_library,
        identifiers=ENV_IDENTIFIERS,
    )
