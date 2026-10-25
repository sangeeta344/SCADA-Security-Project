"""Feature Extractor for SCADA Network Traffic.

Converts observed network connection metadata into the exact 40-feature schema
required by the trained TON_IoT Random Forest intrusion detection pipeline.

IMPORTANT MODEL DOMAIN LIMITATION:
The intrusion detection model was trained on the TON_IoT dataset, which consists
primarily of IT/IoT protocols (HTTP, DNS, SSL, etc.) and contains NO Modbus TCP
traffic (destination port 502/5020). Predictions made on Modbus connections are
strictly experimental and out-of-domain.
"""

from typing import Dict, Any, Tuple
import pandas as pd
import numpy as np

# Exact 40 features expected by scada_attack_model.joblib
EXPECTED_FEATURES = [
    "src_port", "dst_port", "proto", "service", "duration", "src_bytes",
    "dst_bytes", "conn_state", "missed_bytes", "src_pkts", "src_ip_bytes",
    "dst_pkts", "dst_ip_bytes", "dns_query", "dns_qclass", "dns_qtype",
    "dns_rcode", "dns_AA", "dns_RD", "dns_RA", "dns_rejected",
    "ssl_version", "ssl_cipher", "ssl_resumed", "ssl_established",
    "ssl_subject", "ssl_issuer", "http_trans_depth", "http_method",
    "http_uri", "http_version", "http_request_body_len",
    "http_response_body_len", "http_status_code", "http_user_agent",
    "http_orig_mime_types", "http_resp_mime_types", "weird_name",
    "weird_addl", "weird_notice"
]

NUMERIC_FEATURES = [
    "src_port", "dst_port", "duration", "src_bytes", "dst_bytes",
    "missed_bytes", "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes",
    "dns_qclass", "dns_qtype", "dns_rcode", "http_request_body_len",
    "http_response_body_len", "http_status_code"
]

CATEGORICAL_FEATURES = [
    "proto", "service", "conn_state", "dns_query", "dns_AA", "dns_RD",
    "dns_RA", "dns_rejected", "ssl_version", "ssl_cipher", "ssl_resumed",
    "ssl_established", "ssl_subject", "ssl_issuer", "http_trans_depth",
    "http_method", "http_uri", "http_version", "http_user_agent",
    "http_orig_mime_types", "http_resp_mime_types", "weird_name",
    "weird_addl", "weird_notice"
]

# Industrial SCADA/ICS ports historically absent from TON_IoT training data
KNOWN_SCADA_PORTS = {502, 5020, 102, 44818, 20000}


def _safe_int(val: Any, default: int = 0) -> int:
    """Safely convert value to integer, handling strings, nulls, and floats."""
    try:
        if val is None or val == "" or val == "-":
            return default
        return int(float(val))
    except (ValueError, TypeError):
        return default


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Safely convert value to float, handling strings and nulls."""
    try:
        if val is None or val == "" or val == "-":
            return default
        return float(val)
    except (ValueError, TypeError):
        return default


def assess_feature_compatibility(connection: Dict[str, Any]) -> Tuple[bool, str]:
    """Assess whether an observed connection is within the model's trained feature domain.

    Returns:
        (is_compatible, diagnostic_message):
            is_compatible: True if the connection aligns with the TON_IoT training domain.
            diagnostic_message: Detailed explanation of domain alignment or blocker.
    """
    dst_port = _safe_int(connection.get("dst_port", 0))
    src_port = _safe_int(connection.get("src_port", 0))
    service = str(connection.get("service", "-")).lower().strip()
    proto = str(connection.get("proto", "tcp")).lower().strip()

    if dst_port in KNOWN_SCADA_PORTS or src_port in KNOWN_SCADA_PORTS:
        target_port = dst_port if dst_port in KNOWN_SCADA_PORTS else src_port
        return False, (
            f"Port {target_port} is a dedicated SCADA/ICS port. "
            "Modbus/SCADA ports were never present in the TON_IoT training data. "
            "Live model classification is blocked to avoid systematic false alarms."
        )

    if service in ["modbus", "dnp3", "s7", "enip", "opcua"]:
        return False, (
            f"Service '{service}' is an industrial SCADA protocol absent from TON_IoT training data. "
            "Live model classification is blocked to prevent out-of-domain errors."
        )

    if proto not in ["tcp", "udp", "icmp"]:
        return False, f"Protocol '{proto}' is unsupported by the model preprocessor."

    return True, "Connection matches standard IT/IoT training domain."


def build_feature_vector(connection: Dict[str, Any]) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Convert an observed connection dictionary into a validated 40-feature DataFrame.

    Args:
        connection: Dictionary with connection attributes (e.g. src_port, dst_port,
                    proto, duration, src_bytes, dst_bytes, conn_state, etc.)

    Returns:
        (df_features, metadata):
            df_features: 1-row DataFrame containing the 40 expected features
            metadata: Domain status, timestamp, IP endpoints, and compatibility flags
    """
    row: Dict[str, Any] = {}

    # 1. Transport and Connection Metrics (Genuinely Observed)
    row["src_port"] = _safe_int(connection.get("src_port", 0))
    row["dst_port"] = _safe_int(connection.get("dst_port", 0))
    row["proto"] = str(connection.get("proto", "tcp")).lower().strip()
    row["service"] = str(connection.get("service", "-")).strip()
    row["duration"] = _safe_float(connection.get("duration", 0.0))
    row["src_bytes"] = _safe_int(connection.get("src_bytes", 0))
    row["dst_bytes"] = _safe_int(connection.get("dst_bytes", 0))
    row["conn_state"] = str(connection.get("conn_state", "SF")).strip()
    row["missed_bytes"] = _safe_int(connection.get("missed_bytes", 0))
    row["src_pkts"] = _safe_int(connection.get("src_pkts", 1))
    row["src_ip_bytes"] = _safe_int(connection.get("src_ip_bytes", row["src_bytes"] + 40))
    row["dst_pkts"] = _safe_int(connection.get("dst_pkts", 1))
    row["dst_ip_bytes"] = _safe_int(connection.get("dst_ip_bytes", row["dst_bytes"] + 40))

    # 2. DNS Metrics (Default to '-' or 0 when not applicable)
    row["dns_query"] = str(connection.get("dns_query", "-")).strip()
    row["dns_qclass"] = _safe_int(connection.get("dns_qclass", 0))
    row["dns_qtype"] = _safe_int(connection.get("dns_qtype", 0))
    row["dns_rcode"] = _safe_int(connection.get("dns_rcode", 0))
    row["dns_AA"] = str(connection.get("dns_AA", "-")).strip()
    row["dns_RD"] = str(connection.get("dns_RD", "-")).strip()
    row["dns_RA"] = str(connection.get("dns_RA", "-")).strip()
    row["dns_rejected"] = str(connection.get("dns_rejected", "-")).strip()

    # 3. SSL / TLS Metrics (Default to '-' when not applicable)
    row["ssl_version"] = str(connection.get("ssl_version", "-")).strip()
    row["ssl_cipher"] = str(connection.get("ssl_cipher", "-")).strip()
    row["ssl_resumed"] = str(connection.get("ssl_resumed", "-")).strip()
    row["ssl_established"] = str(connection.get("ssl_established", "-")).strip()
    row["ssl_subject"] = str(connection.get("ssl_subject", "-")).strip()
    row["ssl_issuer"] = str(connection.get("ssl_issuer", "-")).strip()

    # 4. HTTP Metrics (Default to '-' or 0 when not applicable)
    row["http_trans_depth"] = str(connection.get("http_trans_depth", "-")).strip()
    row["http_method"] = str(connection.get("http_method", "-")).strip()
    row["http_uri"] = str(connection.get("http_uri", "-")).strip()
    row["http_version"] = str(connection.get("http_version", "-")).strip()
    row["http_request_body_len"] = _safe_int(connection.get("http_request_body_len", 0))
    row["http_response_body_len"] = _safe_int(connection.get("http_response_body_len", 0))
    row["http_status_code"] = _safe_int(connection.get("http_status_code", 0))
    row["http_user_agent"] = str(connection.get("http_user_agent", "-")).strip()
    row["http_orig_mime_types"] = str(connection.get("http_orig_mime_types", "-")).strip()
    row["http_resp_mime_types"] = str(connection.get("http_resp_mime_types", "-")).strip()

    # 5. Zeek Weird Notices (Default to '-' when not applicable)
    row["weird_name"] = str(connection.get("weird_name", "-")).strip()
    row["weird_addl"] = str(connection.get("weird_addl", "-")).strip()
    row["weird_notice"] = str(connection.get("weird_notice", "-")).strip()

    # Construct DataFrame in exact feature order
    df = pd.DataFrame([row], columns=EXPECTED_FEATURES)

    # Domain compatibility assessment
    is_compatible, diagnostic_message = assess_feature_compatibility(connection)

    metadata = {
        "timestamp": connection.get("timestamp", ""),
        "src_ip": connection.get("src_ip", "127.0.0.1"),
        "dst_ip": connection.get("dst_ip", "127.0.0.1"),
        "src_port": row["src_port"],
        "dst_port": row["dst_port"],
        "proto": row["proto"],
        "is_compatible": is_compatible,
        "is_out_of_domain": not is_compatible,
        "domain_note": diagnostic_message,
    }

    return df, metadata


def validate_feature_dataframe(df: pd.DataFrame) -> bool:
    """Validate that a DataFrame has all 40 required features."""
    if df is None or not isinstance(df, pd.DataFrame):
        return False
    return list(df.columns) == EXPECTED_FEATURES
