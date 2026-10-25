"""MQTT Subscriber with message validation, callback dispatch, and bounded queue."""

import json
from queue import Queue, Full
from typing import Dict, Any, Optional, Callable, List
import paho.mqtt.client as mqtt

from config.settings import settings
from config.protocol_config import MQTTTopics
from config.logging_config import logger


class MQTTSubscriber:
    """Subscribes to SCADA telemetry topics, validates payloads, and buffers messages."""

    def __init__(
        self,
        client_id: str = "scada_subscriber",
        host: Optional[str] = None,
        port: Optional[int] = None,
        max_queue_size: int = 500,
    ):
        self.client_id = client_id
        self.host = host or settings.MQTT_HOST
        self.port = port or settings.MQTT_PORT
        self.is_connected = False
        self.message_queue: Queue = Queue(maxsize=max_queue_size)
        self.topic_handlers: Dict[str, List[Callable[[str, Dict[str, Any]], None]]] = {}
        self.last_error: Optional[str] = None

        try:
            self.client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id=self.client_id,
            )
        except AttributeError:
            self.client = mqtt.Client(client_id=self.client_id)

        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            self.is_connected = True
            self.last_error = None
            logger.info("MQTT Subscriber connected to %s:%d", self.host, self.port)
            # Resubscribe to configured topics
            for topic in MQTTTopics.ALL_TOPICS:
                self.client.subscribe(topic)
        else:
            self.is_connected = False
            self.last_error = f"Connection failed code {rc}"

    def _on_disconnect(self, client, userdata, disconnect_flags_or_rc, reason_code=None, properties=None):
        self.is_connected = False

    def _on_message(self, client, userdata, msg):
        """Validate and dispatch incoming MQTT message."""
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            if not isinstance(payload, dict):
                logger.warning("Rejected non-dict MQTT payload on %s", msg.topic)
                return

            # Push to bounded queue
            try:
                self.message_queue.put_nowait({"topic": msg.topic, "payload": payload})
            except Full:
                # Discard oldest to keep queue bounded
                try:
                    self.message_queue.get_nowait()
                    self.message_queue.put_nowait({"topic": msg.topic, "payload": payload})
                except Exception:
                    pass

            # Dispatch registered callbacks
            handlers = self.topic_handlers.get(msg.topic, [])
            for h in handlers:
                try:
                    h(msg.topic, payload)
                except Exception as e:
                    logger.error("Error in handler for %s: %s", msg.topic, e)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning("Malformed MQTT payload received on %s: %s", msg.topic, e)

    def register_handler(self, topic: str, handler: Callable[[str, Dict[str, Any]], None]) -> None:
        """Register a callback for a specific topic."""
        if topic not in self.topic_handlers:
            self.topic_handlers[topic] = []
        self.topic_handlers[topic].append(handler)

    def connect(self, timeout: float = 0.5) -> bool:
        """Start connection loop with fast pre-check."""
        import socket
        try:
            with socket.create_connection((self.host, self.port), timeout=0.2):
                pass
        except (OSError, ConnectionRefusedError) as e:
            self.is_connected = False
            self.last_error = f"Broker unavailable on {self.host}:{self.port} ({e})"
            return False

        try:
            self.client.connect_async(self.host, port=self.port, keepalive=settings.MQTT_KEEPALIVE)
            self.client.loop_start()
            import time
            start = time.time()
            while time.time() - start < timeout:
                if self.is_connected:
                    return True
                time.sleep(0.1)
            if not self.is_connected:
                self.last_error = f"Connection timeout to {self.host}:{self.port}"
            return self.is_connected
        except Exception as e:
            self.is_connected = False
            self.last_error = str(e)
            return False

    def disconnect(self) -> None:
        try:
            self.client.loop_stop()
            self.client.disconnect()
        except Exception:
            pass
        self.is_connected = False
