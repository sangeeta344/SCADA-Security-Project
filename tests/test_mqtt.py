"""Unit tests for MQTT publisher and subscriber components."""

import json
from unittest.mock import MagicMock
import pytest
from config.protocol_config import MQTTTopics
from protocols.mqtt_publisher import MQTTPublisher
from protocols.mqtt_subscriber import MQTTSubscriber


def test_mqtt_topic_structure():
    """Verify standard SCADA MQTT topic structure."""
    assert MQTTTopics.RTU_TELEMETRY == "scada/rtu1/telemetry"
    assert MQTTTopics.SECURITY_ALERTS == "scada/security/alerts"
    assert MQTTTopics.QUANTUM_STATUS == "scada/quantum/status"


def test_publisher_disconnected_broker():
    """Verify publisher never pretends messages are delivered when broker is offline."""
    pub = MQTTPublisher(host="127.0.0.1", port=59999)
    assert pub.is_connected is False

    # Attempting to publish while offline must return False
    payload = {"device_id": "RTU_01", "temp": 28.5}
    success = pub.publish_json(MQTTTopics.RTU_TELEMETRY, payload)
    assert success is False
    assert "disconnected" in pub.last_error.lower()


def test_subscriber_message_validation():
    """Verify subscriber validates incoming JSON and handles malformed payloads safely."""
    sub = MQTTSubscriber(host="127.0.0.1", port=59999)

    received_payloads = []
    def sample_handler(topic, payload):
        received_payloads.append((topic, payload))

    sub.register_handler("scada/rtu1/telemetry", sample_handler)

    # 1. Valid JSON payload simulation
    mock_msg = MagicMock()
    mock_msg.topic = "scada/rtu1/telemetry"
    mock_msg.payload = json.dumps({"sensor": "TEMP_01", "value": 28.5}).encode("utf-8")

    sub._on_message(None, None, mock_msg)
    assert len(received_payloads) == 1
    assert received_payloads[0][1]["sensor"] == "TEMP_01"
    assert sub.message_queue.qsize() == 1

    # 2. Malformed non-JSON payload simulation
    bad_msg = MagicMock()
    bad_msg.topic = "scada/rtu1/telemetry"
    bad_msg.payload = b"MALFORMED_NON_JSON_CORRUPT_BYTES"

    # Must not raise an exception or dispatch callback
    sub._on_message(None, None, bad_msg)
    assert len(received_payloads) == 1  # Unchanged
