"""Modbus TCP Client implementation using PyModbus 3.x."""

from typing import List, Optional, Dict, Any
from pymodbus.client import ModbusTcpClient

from config.settings import settings
from config.protocol_config import ModbusRegisterMap
from config.logging_config import logger


class ModbusClient:
    """Industrial Modbus TCP Client representing the MTU poller."""

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None, timeout: float = 3.0):
        self.host = host or settings.MODBUS_HOST
        self.port = port or settings.MODBUS_PORT
        self.timeout = timeout
        self.client: Optional[ModbusTcpClient] = None
        self.is_connected = False

    def connect(self) -> bool:
        """Establish connection to Modbus server with fast pre-check."""
        import socket
        try:
            with socket.create_connection((self.host, self.port), timeout=min(0.5, self.timeout)):
                pass
        except (OSError, ConnectionRefusedError) as e:
            self.is_connected = False
            return False

        try:
            self.client = ModbusTcpClient(self.host, port=self.port, timeout=self.timeout)
            self.is_connected = bool(self.client.connect())
            if self.is_connected:
                logger.info("Modbus client connected to %s:%d", self.host, self.port)
            else:
                logger.warning("Modbus client failed to connect to %s:%d", self.host, self.port)
            return self.is_connected
        except Exception as e:
            logger.warning("Modbus connection error to %s:%d: %s", self.host, self.port, e)
            self.is_connected = False
            return False

    def read_holding_registers(
        self, address: int = 0, count: int = ModbusRegisterMap.TOTAL_REGISTERS, slave: int = 1
    ) -> Optional[List[int]]:
        """Read contiguous block of holding registers."""
        if not self.is_connected or not self.client:
            if not self.connect():
                return None

        try:
            # Handle PyModbus 3.x parameter name (device_id vs slave)
            try:
                result = self.client.read_holding_registers(address=address, count=count, device_id=slave)
            except TypeError:
                result = self.client.read_holding_registers(address=address, count=count, slave=slave)

            if result.isError():
                logger.warning("Modbus read error at addr %d count %d: %s", address, count, result)
                return None
            return list(result.registers)
        except Exception as e:
            logger.warning("Modbus read exception: %s", e)
            self.is_connected = False
            return None

    def write_register(self, address: int, value: int, slave: int = 1) -> bool:
        """Write single holding register value."""
        if not self.is_connected or not self.client:
            if not self.connect():
                return False

        try:
            try:
                result = self.client.write_register(address=address, value=value, device_id=slave)
            except TypeError:
                result = self.client.write_register(address=address, value=value, slave=slave)
            return not result.isError()
        except Exception as e:
            logger.warning("Modbus write exception: %s", e)
            return False

    def write_registers(self, address: int, values: List[int], slave: int = 1) -> bool:
        """Write multiple holding register values."""
        if not self.is_connected or not self.client:
            if not self.connect():
                return False

        try:
            try:
                result = self.client.write_registers(address=address, values=values, device_id=slave)
            except TypeError:
                result = self.client.write_registers(address=address, values=values, slave=slave)
            return not result.isError()
        except Exception as e:
            logger.warning("Modbus write_registers exception: %s", e)
            return False

    def close(self) -> None:
        """Close connection cleanly."""
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
        self.is_connected = False
