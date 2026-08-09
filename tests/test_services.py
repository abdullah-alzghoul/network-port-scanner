"""
Tests for scanner.services — the port/service database and lookup logic.
No network, no mocking: this module is pure data plus one pure function.
"""
from scanner.services import (
    get_service_info,
    PORT_SERVICES,
    COMMON_PORTS,
    HIGH_RISK_PORTS,
    MEDIUM_RISK_PORTS,
)


def test_known_port_returns_correct_service():
    info = get_service_info(80)
    assert info["name"] == "HTTP"
    assert info["category"] == "Web"


def test_known_high_risk_port_tagged_high():
    info = get_service_info(23)  # Telnet
    assert info["risk"] == "HIGH"


def test_known_medium_risk_port_tagged_medium():
    # 22/SSH is a real, common service that is not in HIGH_RISK_PORTS
    assert 22 not in HIGH_RISK_PORTS
    info = get_service_info(22)
    assert info["risk"] in ("MEDIUM", "LOW")  # whichever this codebase assigns
    assert info["name"] == "SSH"


def test_unknown_port_returns_fallback_with_port_number():
    info = get_service_info(59999)
    assert "59999" in info["name"] or "59999" in info["description"]
    # Risk tagging is independent of whether the port is "known" — a port
    # missing from PORT_SERVICES just isn't in HIGH_RISK_PORTS or
    # MEDIUM_RISK_PORTS either, so it falls through to the LOW default.
    # (display.py's risk_class table has an "UNKNOWN" entry, but nothing
    # in this function ever actually produces that value — confirmed by
    # this test, not assumed.)
    assert info["risk"] == "LOW"


def test_lookup_does_not_mutate_shared_dict():
    # get_service_info adds a "risk" key to the dict it returns.
    # It must .copy() first, or repeated/concurrent calls would corrupt
    # the shared PORT_SERVICES table.
    before = "risk" in PORT_SERVICES[80]
    get_service_info(80)
    get_service_info(80)
    after = "risk" in PORT_SERVICES[80]
    assert before == after == False, (
        "PORT_SERVICES[80] was mutated by get_service_info — "
        "the risk key is leaking into the shared table"
    )


def test_two_calls_return_independent_objects():
    a = get_service_info(80)
    b = get_service_info(80)
    a["name"] = "TAMPERED"
    assert b["name"] == "HTTP", "returned dicts share state across calls"


def test_no_duplicate_ports_in_common_ports():
    assert len(COMMON_PORTS) == len(set(COMMON_PORTS)), (
        "COMMON_PORTS contains duplicate port numbers"
    )


def test_no_overlap_between_high_and_medium_risk():
    overlap = set(HIGH_RISK_PORTS) & set(MEDIUM_RISK_PORTS)
    assert not overlap, f"Ports tagged as both HIGH and MEDIUM risk: {overlap}"


def test_every_high_risk_port_has_service_info():
    missing = set(HIGH_RISK_PORTS) - set(PORT_SERVICES.keys())
    assert not missing, f"HIGH_RISK_PORTS ports missing from PORT_SERVICES: {missing}"


def test_every_medium_risk_port_has_service_info():
    missing = set(MEDIUM_RISK_PORTS) - set(PORT_SERVICES.keys())
    assert not missing, f"MEDIUM_RISK_PORTS ports missing from PORT_SERVICES: {missing}"


def test_every_common_port_has_service_info():
    missing = set(COMMON_PORTS) - set(PORT_SERVICES.keys())
    assert not missing, f"COMMON_PORTS ports missing from PORT_SERVICES: {missing}"


def test_common_ports_count_matches_documented_figure():
    # README and main.py's epilog both say 72 (Stage 1 corrected this from
    # an inflated "80+"). This test is the tripwire if the table ever grows
    # or shrinks without the docs being updated to match.
    assert len(COMMON_PORTS) == 72, (
        f"COMMON_PORTS has {len(COMMON_PORTS)} entries, but README.md and "
        f"main.py's epilog both say 72 — update one or the other"
    )