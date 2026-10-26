import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpn_models import VpnDiagnosticResult
from diagnostic_engine import DiagnosticEngine
from fastapi.testclient import TestClient
from main import app

def test_engine():
    print("1. Testing DiagnosticEngine scenario generation...")
    engine = DiagnosticEngine()
    for scen in ["normal", "warning", "critical"]:
        res = engine.generate_scenario_result(scen)
        assert isinstance(res, VpnDiagnosticResult)
        print(f"   [OK] Scenario '{scen}' generated. Status: {res.overall_status}, Tunnels: {len(res.tunnels)}")

def test_fastapi_endpoints():
    print("2. Testing FastAPI endpoints...")
    client = TestClient(app)

    # 1. Dashboard HTML
    resp_home = client.get("/")
    assert resp_home.status_code == 200
    assert "AWS Site-to-Site VPN Inspector" in resp_home.text
    print("   [OK] GET / returned 200 and rendered dashboard HTML.")

    # 2. Scenario API
    resp_scen = client.get("/api/scenario/warning")
    assert resp_scen.status_code == 200
    data = resp_scen.json()
    assert data["overall_status"] == "WARNING"
    assert len(data["tunnels"]) == 2
    assert len(data["recommendations"]) > 0
    print(f"   [OK] GET /api/scenario/warning returned valid JSON. Recs: {len(data['recommendations'])}")

    # 3. Live diagnose API
    resp_diag = client.post("/api/diagnose")
    assert resp_diag.status_code == 200
    diag_data = resp_diag.json()
    assert "connectivity_tests" in diag_data
    print(f"   [OK] POST /api/diagnose executed. Overall: {diag_data['overall_status']}")

    print("\n>>> ALL TESTS PASSED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    test_engine()
    test_fastapi_endpoints()
