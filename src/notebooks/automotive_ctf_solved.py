# ---
# jupyter:
#   jupytext:
#     formats: py:percent
#     text_representation:
#       extension: .py
#       format_name: percent
#       format_version: '1.3'
#       jupytext_version: 1.16.4
#   kernelspec:
#     display_name: cybersim
#     language: python
#     name: cybersim
# ---

# %%
import sys, logging
import cyberbattle.simulation.model as model
import cyberbattle.simulation.commandcontrol as commandcontrol
import cyberbattle.samples.toyctf.automotive_ctf as auto_ctf

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(levelname)s: %(message)s")


# %% [markdown]
# ## 1. 환경 생성 및 전체 토폴로지 확인

# %%
env = auto_ctf.new_environment()
env.plot_environment_graph()

# %%
c2 = commandcontrol.CommandControl(env)
dbg = commandcontrol.EnvironmentDebugging(c2)

# 시작 상태: AttackerLaptop만 보이는지 확인
dbg.plot_discovered_network()
c2.print_all_attacks()

# %% [markdown]
# ## 2. Plotly 결과를 PNG로 자동 저장 (선택 사항)

# %%
from pathlib import Path
import plotly.io as pio
import plotly.offline as poff
import plotly.graph_objects as go

plots_dir = "notebooks/output/automotive_ctf_solved/plots"
plot_prefix = "automotivectf"

PLOTS_DIR = Path(plots_dir)
PLOTS_DIR.mkdir(parents=True, exist_ok=True)

_plot_idx = 0

def _next_name(name=None):
    global _plot_idx
    _plot_idx += 1
    return name or f"{plot_prefix}-{_plot_idx:03d}"

def save_png(fig, name=None):
    out = PLOTS_DIR / f"{_next_name(name)}.png"
    try:
        fig.write_image(out, format="png", scale=2)
    except Exception as e:
        raise RuntimeError(
            "PNG 저장을 위해 plotly의 이미지 엔진(kaleido)이 필요합니다.\n"
            "예:  pip install -U kaleido"
        ) from e

# pio.show / Figure.show / offline.iplot / offline.plot 후킹
_orig_pio_show = pio.show

def _pio_show(fig, *args, **kwargs):
    save_png(fig)
    return _orig_pio_show(fig, *args, **kwargs)

pio.show = _pio_show

_orig_fig_show = go.Figure.show

def _fig_show(self, *args, **kwargs):
    save_png(self)
    return _orig_fig_show(self, *args, **kwargs)

go.Figure.show = _fig_show

_orig_iplot = poff.iplot

def _iplot(fig, *args, **kwargs):
    save_png(fig)
    return _orig_iplot(fig, *args, **kwargs)

poff.iplot = _iplot

_orig_plot = poff.plot

def _plot(fig, *args, **kwargs):
    save_png(fig)
    kwargs = dict(kwargs)
    kwargs.pop("filename", None)
    kwargs.setdefault("auto_open", False)
    kwargs.setdefault("output_type", "div")
    return _orig_plot(fig, *args, **kwargs)

poff.plot = _plot
# %% [markdown]
# ## 3. AttackerLaptop에서 1차 정찰
# - WiFi 스캔 → IVI 발견
# - Cellular 스캔 → Telematics 발견
# - 물리 점검 → OBD 발견
# - OBD 동글 획득 → USB 접근용 credential 획득

# %%
# 3-1) 무선 / 셀룰러 / 물리 스캔
c2.run_attack("AttackerLaptop", "ScanWIFINetworks")
c2.run_attack("AttackerLaptop", "ScanCellularEndpoints")
c2.run_attack("AttackerLaptop", "InspectVehiclePhysical")

# 3-2) OBD 동글 획득
c2.run_attack("AttackerLaptop", "AcquireOBDDongle")

dbg.plot_discovered_network()
c2.print_all_attacks()

# %% [markdown]
# ## 4. 무선 경로: IVI → IVI[user=media] → GTW 피벗

# %%
# 4-1) IVI WebView RCE로 media shell credential 획득
c2.run_remote_attack("AttackerLaptop", "IVI", "ExploitWebViewRCE")

# (옵션) IVI 데이터 단순 수집
c2.run_remote_attack("AttackerLaptop", "IVI", "ReadInfotainmentData")

dbg.plot_discovered_network()

# %%
# 4-2) AttackerLaptop → IVI[user=media] 쉘 접속
ivi_media_shell_owned = c2.connect_and_infect(
    "AttackerLaptop",
    "IVI[user=media]",
    auto_ctf.PORT_SHELL,
    "ivi_media_shell",
)
print("IVI[user=media] owned:", ivi_media_shell_owned)
dbg.plot_discovered_network()

# %%
# 4-3) IVI[user=media]에서 GTW 정보 및 토큰 획득
c2.run_attack("IVI[user=media]", "DiscoverGatewayNode")      # GTW 노드 발견
c2.run_attack("IVI[user=media]", "DumpGatewayAdminToken")    # gtw_admin_token
c2.run_attack("IVI[user=media]", "ExtractOTASessionToken")   # ota_session_token

dbg.plot_discovered_network()
c2.print_all_attacks()

# %%
# 4-4) IVI[user=media] → GTW (ETH_MGMT)로 피벗
gtw_via_eth = c2.connect_and_infect(
    "IVI[user=media]",
    "GTW",
    auto_ctf.PORT_ETH_MGMT,
    "gtw_admin_token",
)
print("GTW via ETH_MGMT owned:", gtw_via_eth)
dbg.plot_discovered_network()

# %% [markdown]
# ## 5. 물리 경로: OBD → DCAN → GTW 피벗

# %%
# 5-1) AttackerLaptop → OBD (USB + obd_dongle_token)
obd_owned = c2.connect_and_infect(
    "AttackerLaptop",
    "OBD",
    auto_ctf.PORT_USB,
    "obd_dongle_token",
)
print("OBD owned:", obd_owned)
dbg.plot_discovered_network()

# %%
# 5-2) OBD에서 DCAN access 활성화 (dcan_access credential)
c2.run_attack("OBD", "EnableDCANAccess")
dbg.plot_discovered_network()

# %%
# 5-3) OBD → DCAN (dcan_access 사용)
dcan_owned = c2.connect_and_infect(
    "OBD",
    "DCAN",
    auto_ctf.PORT_DCAN,
    "dcan_access",
)
print("DCAN owned:", dcan_owned)
dbg.plot_discovered_network()

# %%
# 5-4) DCAN에서 GTW 존재 탐지 + GTW DCAN 포트로 credential 재사용
c2.run_attack("DCAN", "DiscoverGatewayFromDiagnostics")   # GTW 노드 존재 확인
c2.run_attack("DCAN", "ProvisionGatewayDCANAccess")       # GTW.DCAN에 dcan_access 사용 가능

dbg.plot_discovered_network()

# %%
# 5-5) DCAN → GTW (DCAN + dcan_access) 피벗 (이미 owned여도 OK)
gtw_via_dcan = c2.connect_and_infect(
    "DCAN",
    "GTW",
    auto_ctf.PORT_DCAN,
    "dcan_access",
)
print("GTW via DCAN owned:", gtw_via_dcan)
dbg.plot_discovered_network()

# %% [markdown]
# ## 6. 셀룰러 경로: Telematics → OTA.Server → GTW (OTA)

# %%
# 6-1) Telematics RCE / OTA 서버 탐색 / OTA 세션 토큰 획득
c2.run_remote_attack("AttackerLaptop", "Telematics", "ExploitTelematicsRCE")
c2.run_remote_attack("AttackerLaptop", "Telematics", "DiscoverOTAServer")
c2.run_remote_attack("AttackerLaptop", "Telematics", "AbuseRemoteControlAPI")

dbg.plot_discovered_network()
c2.print_all_attacks()

# %%
# 6-2) AttackerLaptop → Telematics[root shell]
tcu_root_owned = c2.connect_and_infect(
    "AttackerLaptop",
    "Telematics[user=root]",
    auto_ctf.PORT_SHELL,
    "tcu_root_shell",
)
print("Telematics[user=root] owned:", tcu_root_owned)
dbg.plot_discovered_network()

# %%
# 6-3) Telematics 포스트 익스플로잇: 백엔드 설정 덤프 (impact-only)
c2.run_attack("Telematics[user=root]", "DumpVehicleBackendConfig")

# %%
# 6-4) AttackerLaptop → OTA.Server (HTTPS + ota_session_token)
ota_server_owned = c2.connect_and_infect(
    "AttackerLaptop",
    "OTA.Server",
    auto_ctf.PORT_HTTPS,
    "ota_session_token",
)
print("OTA.Server owned:", ota_server_owned)
dbg.plot_discovered_network()

# %%
# 6-5) OTA 서버에서 펌웨어 아티팩트 탈취 + GTW OTA 토큰 획득
c2.run_remote_attack("AttackerLaptop", "OTA.Server", "StealFirmwareArtifacts")
c2.run_remote_attack("AttackerLaptop", "OTA.Server", "DownloadUpdateBundle")  # ota_update_token → GTW.OTA

dbg.plot_discovered_network()

# %%
# 6-6) Telematics[root] → GTW (OTA 채널 + ota_update_token)
gtw_via_ota = c2.connect_and_infect(
    "Telematics[user=root]",
    "GTW",
    auto_ctf.PORT_OTA,
    "ota_update_token",
)
print("GTW via OTA owned:", gtw_via_ota)
dbg.plot_discovered_network()

# %% [markdown]
# ## 7. GTW에서 Bus 토폴로지 및 ECU 열람 + Bus 접근 Credential 덤프

# %%
# 7-1) Bus 토폴로지 / ECU 목록 / Bus access cred 덤프
c2.run_attack("GTW", "LeakBusTopology")     # BCAN/CCAN/LIN/DCAN 노출
c2.run_attack("GTW", "EnumerateECUs")      # BCM, DoorLockECU, ESP, VCU, ADAS, IMU, BMS, Airbag, TestBenchECU
c2.run_attack("GTW", "DumpBusAccessCreds") # bcan_access / ccan_access / lin_access

dbg.plot_discovered_network()
c2.print_all_attacks()

# %% [markdown]
# ## 8. GTW → Bus 피벗 (BCAN / CCAN / LIN)

# %%
# 8-1) GTW → BCAN / CCAN / LIN 접속
bcan_owned = c2.connect_and_infect("GTW", "BCAN", auto_ctf.PORT_BCAN, "bcan_access")
ccan_owned = c2.connect_and_infect("GTW", "CCAN", auto_ctf.PORT_CCAN, "ccan_access")
lin_owned = c2.connect_and_infect("GTW", "LIN", auto_ctf.PORT_LIN, "lin_access")

print("BCAN owned:", bcan_owned)
print("CCAN owned:", ccan_owned)
print("LIN owned:", lin_owned)
dbg.plot_discovered_network()

# %% [markdown]
# ## 9. Bus 레벨 Impact 공격 (문 열기, 브레이크 스푸핑, 에어백 상태 조작 등)

# %%
# 9-1) BCAN impact / decoy
c2.run_attack("BCAN", "ImpactUnlockDoors")
c2.run_attack("BCAN", "ImpactDoorActuation")
c2.run_attack("BCAN", "PollAmbientTemperature")  # 데코이

# 9-2) CCAN impact / decoy
c2.run_attack("CCAN", "ImpactBrakeSpoof")
c2.run_attack("CCAN", "ImpactDriveModeChange")
c2.run_attack("CCAN", "ImpactSpoofADAS")
c2.run_attack("CCAN", "ImpactReadIMU")
c2.run_attack("CCAN", "ImpactModifyBatteryTelemetry")
c2.run_attack("CCAN", "PollDebugCounters")  # 데코이

# 9-3) LIN impact / decoy
c2.run_attack("LIN", "ImpactTamperAirbagStatus")
c2.run_attack("LIN", "ReadInteriorLightingStatus")  # 데코이

dbg.plot_discovered_network()

# %% [markdown]
# ## 10. ECU 레벨 피벗 및 Post-compromise 덤프
# - BCAN_DIAG: BCM, DoorLockECU
# - CCAN_DIAG: ESP, VCU, ADAS, IMU, BMS, TestBenchECU
# - LIN_DIAG: Airbag

# %%
# 10-1) BCAN → Body ECUs
c2.connect_and_infect("BCAN", "BCM", auto_ctf.PORT_BCAN_DIAG, "bcan_access")
c2.connect_and_infect("BCAN", "DoorLockECU", auto_ctf.PORT_BCAN_DIAG, "bcan_access")

# 10-2) CCAN → Chassis/Powertrain/ADAS/센서/BMS/TestBench ECUs
for ecu in ["ESP", "VCU", "ADAS", "IMU", "BMS", "TestBenchECU"]:
    c2.connect_and_infect("CCAN", ecu, auto_ctf.PORT_CCAN_DIAG, "ccan_access")

# 10-3) LIN → 안전 ECU (Airbag)
c2.connect_and_infect("LIN", "Airbag", auto_ctf.PORT_LIN_DIAG, "lin_access")

dbg.plot_discovered_network()

# %%
# 10-4) 각 ECU에서 post-compromise 덤프 (CustomerData 플래그들)
c2.run_attack("BCM", "DumpBCMConfig")
c2.run_attack("DoorLockECU", "DumpDoorLockFirmware")

c2.run_attack("ESP", "DumpESPParams")
c2.run_attack("VCU", "DumpVCUState")
c2.run_attack("ADAS", "DumpADASModel")
c2.run_attack("IMU", "DumpIMUOffsets")
c2.run_attack("BMS", "DumpBMSProfile")

c2.run_attack("Airbag", "DumpCrashLogs")

# TestBenchECU는 저가치 데코이
c2.run_attack("TestBenchECU", "DumpTestLogs")

dbg.plot_discovered_network()
c2.print_all_attacks()