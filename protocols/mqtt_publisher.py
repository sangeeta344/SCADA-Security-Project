"""MQTT Publisher using Paho MQTT with reliable delivery status reporting."""

import json
from typing import Dict, Any, Optional
import paho.mqtt.client as mqtt

from config.settings import settings
from config.logging_config import logger


class MQTTPublisher:
    """Publishes SCADA telemetry and alert messages over MQTT."""

    def __init__(
        self,
        client_id: str = "scada_publisher",
        host: Optional[str] = None,
        port: Optional[int] = None,
        keepalive: Optional[int] = None,
    ):
        self.client_id = client_id
        self.host = host or settings.MQTT_HOST
        self.port = port or settings.MQTT_PORT
        self.keepalive = keepalive or settings.MQTT_KEEPALIVE
        self.is_connected = False
        self.last_error: Optional[str] = None

        # Paho MQTT 2.x callback API version handling
        try:
            self.client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id=self.client_id,
            )
        except AttributeError:
            self.client = mqtt.Client(client_id=self.client_id)

        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            self.is_connected = True
            self.last_error = None
            logger.info("MQTT Publisher connected to %s:%d", self.host, self.port)
        else:
            self.is_connected = False
            self.last_error = f"Connection failed with code {rc}"
            logger.warning("MQTT Publisher connection failed code=%s", rc)

    def _on_disconnect(self, client, userdata, disconnect_flags_or_rc, reason_code=None, properties=None):
        self.is_connected = False
        logger.info("MQTT Publisher disconnected")

    def connect(self, timeout: float = 0.5) -> bool:
        """Attempt broker connection with fast pre-check."""
        import socket
        try:
            with socket.create_connection((self.host, self.port), timeout=0.2):
                pass
        except (OSError, ConnectionRefusedError) as e:
            self.is_connected = False
            self.last_error = f"Broker unavailable on {self.host}:{self.port} ({e})"
            return False

        try:
            self.client.connect_async(self.host, port=self.port, keepalive=self.keepalive)
            self.client.loop_start()
            # Give short window to confirm connection
            import time
            start = time.time()
            while time.time() - start < timeout:
                if self.is_connected:
                    return True
                time.sleep(0.1)
            # If not connected in timeout, record status
            if not self.is_connected:
                self.last_error = f"Connection timeout to {self.host}:{self.port}"
            return self.is_connected
        except Exception as e:
            self.is_connected = False
            self.last_error = str(e)
            logger.warning("MQTT broker unavailable on %s:%d (%s)", self.host, self.port, e)
            return False

    def publish_json(self, topic: str, payload: Dict[str, Any], qos: int = 1) -> bool:
        """Publish JSON payload if connected. Never pretend success if broker unavailable."""
        if not self.is_connected:
            self.last_error = f"Cannot publish: Broker disconnected on {self.host}:{self.port}"
            return False

        try:
            payload_str = json.dumps(payload)
            info = self.client.publish(topic, payload_str, qos=qos)
            return info.rc == mqtt.MQTT_ERR_SUCCESS
        except Exception as e:
            self.last_error = str(e)
            logger.warning("MQTT publish failed to %s: %s", topic, e)
            return False

    def disconnect(self) -> None:
        """Disconnect and stop background loop cleanly."""
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            pass
        self.is_connected = False
