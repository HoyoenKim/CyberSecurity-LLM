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

# %% [markdown]
# pyright: reportUnusedExpression=false

# %% [markdown]
# # Automotive CTF - Solved manually (step-by-step)
# - Telematics -> (discover OTA, leak token)
# - IVI -> IVI[user=media] -> GTW (ETH_MGMT)
# - OBD -> GTW (DCAN)
# - GTW -> BCAN/CCAN/LIN -> ECU DIAG -> ECU LOCAL (post-compromise)

# %%
import sys, logging
import cyberbattle.simulation.model as model
import cyberbattle.simulation.commandcontrol as commandcontrol
import cyberbattle.samples.toyctf.automotive_ctf as autoctf

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(levelname)s: %(message)s")

# %%
# (선택) plotly png 저장 훅(너가 toyctf에서 쓰던 코드 그대로 유지해도 됨)
plots_dir = "notebooks/output/automotive_ctf_solved/plots"
plot_prefix = "automotive_ctf"

from pathlib import Path
import plotly.io as pio
import plotly.offline as poff
import plotly.graph_objects as go

PLOTS_DIR = Path(plots_dir)
PLOTS_DIR.mkdir(parents=True, exist_ok=True)

_plot_idx = 0
def _next_name(name=None):
    global _plot_idx
    _plot_idx += 1
    return name or f"{plot_prefix}-{_plot_idx:03d}"

def save_png(fig, name=None):
    out = PLOTS_DIR / f"{_next_name(name)}.png"
    fig.write_image(out, format="png", scale=2)

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

_orig_plot = poff.plot
def _plot(fig, *args, **kwargs):
    save_png(fig)
    kwargs = dict(kwargs)
    kwargs.pop("filename", None)
    kwargs.setdefault("auto_open", False)
    kwargs.setdefault("output_type", "div")
    return _orig_plot(fig, *args, **kwargs)
poff.plot = _plot

# %%
# --- env init
network = model.create_network(autoctf.nodes)
env = model.Environment(network=network, vulnerability_library=dict([]), identifiers=autoctf.ENV_IDENTIFIERS)
env.plot_environment_graph()

c2 = commandcontrol.CommandControl(env)
dbg = commandcontrol.EnvironmentDebugging(c2)

# %%
# --- helpers: "한 스텝 실행 -> 즉시 상태 출력"
def show_state(title: str):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)
    dbg.plot_discovered_network()
    c2.print_all_attacks()

def step_local(node: str, vuln: str, title: str = ""):
    if title:
        print(f"\n[STEP] {title}")
    out = c2.run_attack(node, vuln)
    print(f"[OK] LOCAL  {node} :: {vuln} -> {type(out).__name__}")
    show_state(f"After LOCAL {node}::{vuln}")
    return out

def step_remote(src: str, dst: str, vuln: str, title: str = ""):
    if title:
        print(f"\n[STEP] {title}")
    out = c2.run_remote_attack(src, dst, vuln)
    print(f"[OK] REMOTE {src} -> {dst} :: {vuln} -> {type(out).__name__}")
    show_state(f"After REMOTE {src}->{dst}::{vuln}")
    return out

def step_connect(src: str, dst: str, port: str, cred: str, title: str = ""):
    if title:
        print(f"\n[STEP] {title}")
    ok = bool(c2.connect_and_infect(src, dst, port, cred))
    print(f"[{'OK' if ok else 'FAIL'}] CONNECT {src} -> {dst} ({port}, {cred})")
    show_state(f"After CONNECT {src}->{dst}({port},{cred})")
    return ok

# %%
# 0) start
show_state("Start state")

# %%
# 1) Discovery / physical token
step_local("AttackerLaptop", "ScanWirelessVicinity", "무선 주변 + OBD 존재 발견")
step_local("AttackerLaptop", "AcquireOBDDongle", "OBD 동글 토큰 획득")

# %%
# 2) Telematics -> discover OTA + leak session token (원격 경로)
step_remote("AttackerLaptop", "Telematics", "DiscoverOTAServer", "Telematics로 OTA.Server 엔드포인트 발견")
step_remote("AttackerLaptop", "Telematics", "AbuseRemoteControlAPI", "Telematics로 ota_session_token 획득")

# %%
# 3) OTA.Server -> firmware artifacts + update token
step_remote("AttackerLaptop", "OTA.Server", "StealFirmwareArtifacts", "OTA 서버에서 펌웨어/아티팩트 접근(impact)")
step_remote("AttackerLaptop", "OTA.Server", "DownloadUpdateBundle", "OTA 업데이트 번들로 ota_update_token 획득")

# %%
# 4) IVI compromise -> IVI[user=media] shell credential
step_remote("AttackerLaptop", "IVI", "ExploitWebViewRCE", "IVI WebView RCE로 media shell credential 획득")
step_remote("AttackerLaptop", "IVI", "ReadInfotainmentData", "IVI 데이터 접근(impact)")

# %%
# 5) Connect to IVI[user=media] (SHELL) and dump GTW admin token
step_connect("AttackerLaptop", "IVI[user=media]", "SHELL", "ivi_media_shell", "IVI[user=media]로 쉘 접속/감염")
step_local("IVI[user=media]", "DiscoverGatewayNode", "IVI에서 GTW 발견")
step_local("IVI[user=media]", "DumpGatewayAdminToken", "IVI에서 gtw_admin_token 덤프")
step_local("IVI[user=media]", "ExtractOTASessionToken", "IVI에서 ota_session_token 추가 덤프(선택)")

# %%
# 6) GTW compromise paths (둘 다 '하나씩' 실행)
# (A) ETH_MGMT via IVI media
step_connect("IVI[user=media]", "GTW", "ETH_MGMT", "gtw_admin_token", "ETH_MGMT로 GTW 감염(IVI 경로)")

# (B) DCAN via OBD
step_connect("AttackerLaptop", "OBD", "USB", "obd_dongle_token", "OBD USB 연결/감염")
step_local("OBD", "EnableDCANAccess", "OBD에서 DCAN access(진단) 활성화")
step_connect("OBD", "GTW", "DCAN", "dcan_access", "DCAN으로 GTW 감염(OBD 경로)")

# (C) OTA path (Telematics/OTA)
# 필요하면 Telematics root 노드가 있는 환경에서만 유효
if "Telematics[user=root]" in autoctf.nodes:
    step_remote("AttackerLaptop", "Telematics", "ExploitTelematicsRCE", "Telematics RCE로 root shell cred 획득")
    step_connect("AttackerLaptop", "Telematics[user=root]", "SHELL", "tcu_root_shell", "Telematics[user=root] 접속/감염")
    step_local("Telematics[user=root]", "DumpVehicleBackendConfig", "Telematics backend 설정 덤프(선택)")
    step_connect("Telematics[user=root]", "GTW", "OTA", "ota_update_token", "OTA 포트로 GTW 감염(OTA 경로)")

# %%
# 7) GTW owned 이후: topology + ECU enumerate + bus creds
step_local("GTW", "LeakBusTopology", "GTW에서 버스 토폴로지 노출(BCAN/CCAN/LIN/DCAN)")
step_local("GTW", "EnumerateECUs", "GTW에서 ECU 나열(발견)")
step_local("GTW", "DumpBusAccessCreds", "GTW에서 BCAN/CCAN/LIN access creds 덤프")

# %%
# 8) Own bus segments (meaningful compromise chain)
step_connect("GTW", "BCAN", "BCAN", "bcan_access", "BCAN 세그먼트 장악")
step_connect("GTW", "CCAN", "CCAN", "ccan_access", "CCAN 세그먼트 장악")
step_connect("GTW", "LIN",  "LIN",  "lin_access",  "LIN 세그먼트 장악")

# %%
# 9) Impact-only attacks should be launched from BUS nodes (현실성)
# (BCAN impact)
step_local("BCAN", "ImpactUnlockDoors", "BCAN에서 도어 언락 영향 공격(impact)")

# (CCAN impact)
step_local("CCAN", "ImpactBrakeSpoof", "CCAN에서 브레이크/ESP 영향 공격(impact)")
step_local("CCAN", "ImpactBatteryTelemetry", "CCAN에서 BMS 텔레메트리 변조(impact)")

# (LIN impact)
step_local("LIN", "ImpactAirbagStatusTamper", "LIN에서 에어백 상태 변조(impact)")

# %%
# 10) Own ECUs via DIAG services (BUS -> ECU_DIAG)
# Body CAN ECUs
step_connect("BCAN", "BCM", "BCAN_DIAG", "bcan_access", "BCAN->BCM DIAG로 ECU 장악")
step_connect("BCAN", "DoorLockECU", "BCAN_DIAG", "bcan_access", "BCAN->DoorLock DIAG로 ECU 장악")

# Chassis CAN ECUs
step_connect("CCAN", "ESP",  "CCAN_DIAG", "ccan_access", "CCAN->ESP DIAG로 ECU 장악")
step_connect("CCAN", "VCU",  "CCAN_DIAG", "ccan_access", "CCAN->VCU DIAG로 ECU 장악")
step_connect("CCAN", "ADAS", "CCAN_DIAG", "ccan_access", "CCAN->ADAS DIAG로 ECU 장악")
step_connect("CCAN", "IMU",  "CCAN_DIAG", "ccan_access", "CCAN->IMU DIAG로 ECU 장악")
step_connect("CCAN", "BMS",  "CCAN_DIAG", "ccan_access", "CCAN->BMS DIAG로 ECU 장악")

# LIN ECU
step_connect("LIN", "Airbag", "LIN_DIAG", "lin_access", "LIN->Airbag DIAG로 ECU 장악")

# %%
# 11) ECU post-compromise LOCAL actions (owned 된 ECU만)
# (각 ECU에 LOCAL 공격이 정의돼 있어야 함)
for ecu, local_list in [
    ("BCM", ["DumpBCMConfig"]),
    ("DoorLockECU", ["DumpDoorLockFirmware"]),
    ("ESP", ["DumpESPParams"]),
    ("VCU", ["DumpVCUState"]),
    ("ADAS", ["DumpADASModel"]),
    ("IMU", ["DumpIMUOffsets"]),
    ("BMS", ["DumpBMSProfile"]),
    ("Airbag", ["DumpCrashLogs"]),
]:
    for v in local_list:
        if ecu in autoctf.nodes and autoctf.nodes[ecu].vulnerabilities and v in autoctf.nodes[ecu].vulnerabilities:
            step_local(ecu, v, f"{ecu} post-compromise local: {v}")

# %%
show_state("FINAL STATE")
