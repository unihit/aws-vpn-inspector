import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from vpn_models import VpnDiagnosticResult, ConnectivityTests
from diagnostic_engine import DiagnosticEngine

app = FastAPI(title="AWS Site-to-Site VPN Connectivity Inspector", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

current_dir = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(current_dir, "templates"))
engine = DiagnosticEngine()

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """엔지니어용 대시보드 메인 화면"""
    return templates.TemplateResponse(request, "dashboard.html", {})

@app.get("/api/scenario/{name}", response_model=VpnDiagnosticResult)
async def get_scenario(name: str):
    """사전 정의된 장애/정상 시나리오 반환 (Mock)"""
    return engine.generate_scenario_result(name)

@app.get("/api/aws/profiles")
async def get_profiles():
    """머신에 설정된 AWS CLI 프로필 목록"""
    return {"profiles": engine.list_available_profiles()}

@app.get("/api/aws/identity")
async def get_identity(profile: str = "default", region: str = "ap-northeast-2"):
    """선택한 프로필의 STS GetCallerIdentity 인증 상태 반환"""
    return engine.get_caller_identity(profile_name=profile, region_name=region)

@app.get("/api/aws/vpns")
async def get_vpns(profile: str = "default", region: str = "ap-northeast-2"):
    """선택한 프로필 및 리전의 Site-to-Site VPN 목록 자동 탐색"""
    return {"vpns": engine.list_account_vpns(profile_name=profile, region_name=region)}

@app.get("/api/aws/instances")
async def get_instances(profile: str = "default", region: str = "ap-northeast-2"):
    """선택한 프로필 및 리전에서 실행 중인 EC2 (Bastion 후보) 목록"""
    return {"instances": engine.list_running_instances(profile_name=profile, region=region)}

@app.post("/api/diagnose", response_model=VpnDiagnosticResult)
async def run_live_diagnosis(
    target_ip: str = "10.0.1.15",
    vpn_id: str = None,
    profile_name: str = "default",
    region: str = "ap-northeast-2",
    bastion_instance_id: str = None
):
    """지정된 AWS Profile 및 Bastion EC2를 출발지로 온프레미스 대상 사설 IP 실측 진단"""
    # 1. AWS VPN 텔레메트리 조회
    if vpn_id and vpn_id.strip():
        vpn_info, tunnels, aws_logs, errors = engine.query_aws_vpn(vpn_id.strip(), profile_name, region)
    else:
        vpn_info, tunnels, aws_logs, errors = engine.query_aws_vpn("vpn-demo", profile_name, region)
        if errors or not tunnels:
            tunnels = [
                engine.generate_scenario_result("normal").tunnels[0],
                engine.generate_scenario_result("normal").tunnels[1]
            ]
            errors = []

    # 2. 실측 프로브 실행 (Bastion SSM 원격 또는 로컬)
    probe_location = "on-premises"
    probe_source_ip = "127.0.0.1"

    if bastion_instance_id and bastion_instance_id.strip():
        # [방법론 1]: AWS SSM을 통해 Bastion에서 온프레미스로 실측 실행!
        probe_location = f"AWS Bastion ({bastion_instance_id})"
        icmp_res, tcp_checks, mtu_res, probe_logs = engine.run_ssm_probe_on_bastion(
            instance_id=bastion_instance_id.strip(),
            target_ip=target_ip,
            profile_name=profile_name,
            region=region
        )
    else:
        # Bastion 미지정 시 로컬 실측
        probe_location = "local host"
        icmp_res = engine.run_icmp_ping(target_ip, count=4)
        tcp_checks = [
            engine.run_tcp_check(target_ip, 22, "SSH Admin", required=False),
            engine.run_tcp_check(target_ip, 80, "HTTP Web", required=False),
            engine.run_tcp_check(target_ip, 443, "HTTPS Web", required=False)
        ]
        mtu_res = engine.run_mtu_test(target_ip, threshold=1400)
        probe_logs = [
            {"time": "Live", "source": "ICMP", "level": icmp_res.status, "message": f"Ping to {target_ip}: {icmp_res.packet_loss_pct}% loss, avg {icmp_res.rtt_avg_ms}ms"},
            {"time": "Live", "source": "MTU", "level": mtu_res.status, "message": f"Observed non-fragmented MTU: {mtu_res.max_successful_packet_size} Bytes."}
        ]

    # 3. 종합 판정
    connectivity = ConnectivityTests(
        icmp_ping=icmp_res,
        tcp_health_checks=tcp_checks,
        mtu_test=mtu_res
    )
    overall_status, recommendations = engine.evaluate_overall_status(tunnels, connectivity)
    logs = aws_logs + probe_logs

    from vpn_models import ProbeInfo
    return VpnDiagnosticResult(
        overall_status=overall_status,
        probe=ProbeInfo(location=probe_location, source_ip=probe_source_ip),
        vpn_info=vpn_info,
        tunnels=tunnels,
        connectivity_tests=connectivity,
        recommendations=recommendations,
        errors=errors,
        logs=logs
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
