"""Protocol adapter providing unified interface for Modbus TCP and MQTT with graceful fallback."""

from typing import Dict, Any, Optional, List
from datetime import datetime

from config.settings import settings
from config.protocol_config import ModbusRegisterMap, MQTTTopics
from protocols.modbus_server import ModbusServer
from protocols.modbus_client import ModbusClient
from protocols.mqtt_publisher import MQTTPublisher
from protocols.mqtt_subscriber import MQTTSubscriber
from database.repository import Repository, repo as default_repo
from config.logging_config import logger


class ProtocolAdapter:
    """Coordinates Modbus TCP and MQTT protocols with automatic fallback and diagnostics."""

    def __init__(self, repository: Optional[Repository] = None):
        self.repo = repository or default_repo
        self.modbus_server = ModbusServer()
        self.modbus_client = ModbusClient()
        self.mqtt_pub = MQTTPublisher()
        self.mqtt_sub = MQTTSubscriber()

        self.modbus_active = False
        self.mqtt_active = False

    def start_services(self, start_modbus: bool = True, start_mqtt: bool = True) -> Dict[str, Any]:
        """Attempt to start real protocol services, reporting exact status."""
        status = {"modbus_tcp": False, "mqtt": False, "details": {}}

        if start_modbus:
            try:
                server_ok = self.modbus_server.start()
                if server_ok:
                    client_ok = self.modbus_client.connect()
                    self.modbus_active = client_ok
                    status["modbus_tcp"] = client_ok
                    status["details"]["modbus"] = "Connected to local Modbus TCP server"
                else:
                    self.modbus_active = False
                    status["details"]["modbus"] = "Modbus server could not bind to port (permission or port in use)"
            except Exception as e:
                self.modbus_active = False
                status["details"]["modbus"] = str(e)

        if start_mqtt:
            try:
                pub_ok = self.mqtt_pub.connect()
                sub_ok = self.mqtt_sub.connect()
                self.mqtt_active = pub_ok and sub_ok
                status["mqtt"] = self.mqtt_active
                if self.mqtt_active:
                    status["details"]["mqtt"] = f"Connected to broker at {settings.MQTT_HOST}:{settings.MQTT_PORT}"
                else:
                    status["details"]["mqtt"] = f"Broker unavailable on {settings.MQTT_HOST}:{settings.MQTT_PORT}"
            except Exception as e:
                self.mqtt_active = False
                status["details"]["mqtt"] = str(e)

        # Update database device statuses
        try:
            self.repo.update_device_status(
                "RTU_01", "ONLINE" if self.modbus_active else "SIMULATED"
            )
            self.repo.update_device_status(
                "MQTT_BROKER", "ONLINE" if self.mqtt_active else "OFFLINE"
            )
        except Exception:
            pass

        return status

    def transfer_telemetry(self, sensor_data: Dict[str, Any], actuator_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Transfer telemetry via live Modbus & MQTT if available, or in-memory simulation."""
        actuator_data = actuator_data or {}
        # 1. Update Modbus registers on server
        regs = [0] * ModbusRegisterMap.TOTAL_REGISTERS
        regs[0] = ModbusRegisterMap.encode_value(ModbusRegisterMap.REG_TEMPERATURE, float(sensor_data.get("temperature_c", 28.0)))
        regs[1] = ModbusRegisterMap.encode_value(ModbusRegisterMap.REG_PRESSURE, float(sensor_data.get("pressure_bar", 2.5)))
        regs[2] = ModbusRegisterMap.encode_value(ModbusRegisterMap.REG_WATER_LEVEL, float(sensor_data.get("water_level_mm", 900.0)))
        regs[3] = ModbusRegisterMap.encode_value(ModbusRegisterMap.REG_FLOW_RATE, float(sensor_data.get("flow_rate_lpm", 35.0)))
        regs[4] = actuator_data.get("pump_state_int", 1)
        regs[5] = actuator_data.get("valve_state_int", 0)
        status_map = {"NORMAL": 1, "WARNING": 2, "ALARM": 3, "ATTACK": 4}
        regs[6] = status_map.get(sensor_data.get("operating_status", "NORMAL").upper(), 1)

        self.modbus_server.update_registers(regs)

        # 2. If client is connected, read from client; otherwise read from memory
        read_regs = None
        if self.modbus_active and self.modbus_client.is_connected:
            read_regs = self.modbus_client.read_holding_registers(0, ModbusRegisterMap.TOTAL_REGISTERS)

        if not read_regs:
            read_regs = list(self.modbus_server.register_data.values)

        # 3. Publish to MQTT if broker is active
        payload = {
            "device_id": "RTU_01",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "readings": sensor_data,
            "actuators": actuator_data,
        }
        if self.mqtt_active and self.mqtt_pub.is_connected:
            self.mqtt_pub.publish_json(MQTTTopics.RTU_TELEMETRY, payload)

        return {
            "modbus_registers": read_regs,
            "mqtt_published": bool(self.mqtt_active and self.mqtt_pub.is_connected),
            "payload": payload,
        }

    def stop_services(self) -> None:
        """Stop all protocol servers and client loops."""
        self.modbus_client.close()
        self.modbus_server.stop()
        self.mqtt_pub.disconnect()
        self.mqtt_sub.disconnect()
        self.modbus_active = False
        self.mqtt_active = False
