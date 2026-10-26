from datetime import datetime, timezone
from typing import List, Optional, Literal
from pydantic import BaseModel, Field

StatusType = Literal["PASS", "WARNING", "FAIL", "SKIPPED", "ERROR"]
OverallStatusType = Literal["NORMAL", "WARNING", "CRITICAL"]
TunnelStatusType = Literal["UP", "DOWN"]
RoutingType = Literal["STATIC", "BGP"]
TcpResultType = Literal["SUCCESS", "TIMEOUT", "REFUSED"]

class ProbeInfo(BaseModel):
    location: str = "on-premises"
    source_ip: Optional[str] = "127.0.0.1"

class VpnInfo(BaseModel):
    vpn_connection_id: str
    customer_gateway_ip: Optional[str] = None
    vgw_or_tgw_id: Optional[str] = None
    routing_type: Optional[RoutingType] = "BGP"

class TunnelInfo(BaseModel):
    tunnel_inside_ip: Optional[str] = None
    outside_ip: str
    status: TunnelStatusType
    accepted_route_count: Optional[int] = 0
    status_message: Optional[str] = None

class IcmpPingTest(BaseModel):
    target_ip: str
    packets_sent: int = 5
    packets_received: int = 5
    packet_loss_pct: Optional[float] = 0.0
    rtt_avg_ms: Optional[float] = 12.0
    status: StatusType = "PASS"

class TcpCheck(BaseModel):
    target_ip: str
    port: int
    service_name: str
    required: bool = True
    result: Optional[TcpResultType] = "SUCCESS"
    latency_ms: Optional[float] = 15.0

class MtuTest(BaseModel):
    target_ip: str
    max_successful_packet_size: Optional[int] = 1420
    threshold: int = 1400
    is_fragmented: Optional[bool] = None
    status: StatusType = "PASS"

class ConnectivityTests(BaseModel):
    icmp_ping: IcmpPingTest
    tcp_health_checks: List[TcpCheck] = []
    mtu_test: MtuTest

class Recommendation(BaseModel):
    priority: Literal["P0", "P1", "P2"] = "P1"
    code: str
    title: str
    action: str
    evidence_paths: List[str] = []

class DiagnosticError(BaseModel):
    path: str
    code: str
    message: str

class VpnDiagnosticResult(BaseModel):
    schema_version: str = "1.0"
    diagnosis_id: str = Field(default_factory=lambda: f"diag-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}")
    collected_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    probe: ProbeInfo = Field(default_factory=ProbeInfo)
    overall_status: OverallStatusType = "NORMAL"
    vpn_info: VpnInfo
    tunnels: List[TunnelInfo] = []
    connectivity_tests: ConnectivityTests
    recommendations: List[Recommendation] = []
    errors: List[DiagnosticError] = []
    logs: List[dict] = []
