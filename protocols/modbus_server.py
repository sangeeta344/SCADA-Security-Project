"""Modbus TCP Server implementation using PyModbus 3.x."""

import asyncio
import threading
import time
from typing import List, Optional
from pymodbus.server import StartAsyncTcpServer, ServerAsyncStop
from pymodbus.simulator import SimData, SimDevice, DataType

from config.settings import settings
from config.protocol_config import ModbusRegisterMap
from config.logging_config import logger


class ModbusServer:
    """Industrial Modbus TCP Server representing the RTU."""

    def __init__(self, host: Optional[str] = None, port: Optional[int] = None, slave_id: Optional[int] = None):
        self.host = host or settings.MODBUS_HOST
        self.port = port or settings.MODBUS_PORT
        self.slave_id = slave_id or settings.MODBUS_SLAVE_ID
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # 7 holding registers initialized to 0
        self.register_data = SimData(
            address=0,
            count=ModbusRegisterMap.TOTAL_REGISTERS,
            values=[0] * ModbusRegisterMap.TOTAL_REGISTERS,
            datatype=DataType.REGISTERS,
        )

        self.device = SimDevice(
            id=self.slave_id,
            simdata=[self.register_data],
            action=self._action_callback,
        )

    async def _action_callback(self, fc, start_addr, addr, count, current_regs, set_values):
        """Dynamic callback invoked by PyModbus server on register reads and writes."""
        if set_values:
            for idx, val in enumerate(set_values):
                target_idx = start_addr + idx
                if 0 <= target_idx < len(self.register_data.values):
                    self.register_data.values[target_idx] = int(val) & 0xFFFF
            return None
        return self.register_data.values[start_addr : start_addr + count]

    def update_registers(self, values: List[int]) -> None:
        """Update holding registers exposed to connected clients."""
        for i, val in enumerate(values[:ModbusRegisterMap.TOTAL_REGISTERS]):
            self.register_data.values[i] = int(val) & 0xFFFF

    def get_register(self, address: int) -> int:
        """Get holding register value by address."""
        if 0 <= address < len(self.register_data.values):
            return self.register_data.values[address]
        raise ValueError(f"Invalid register address {address}")

    def set_register(self, address: int, value: int) -> None:
        """Write holding register value by address."""
        if 0 <= address < len(self.register_data.values):
            self.register_data.values[address] = int(value) & 0xFFFF
        else:
            raise ValueError(f"Invalid register address {address}")

    def _run_server(self) -> None:
        """Internal server event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            logger.info("Starting Modbus TCP server on %s:%d (Slave %d)", self.host, self.port, self.slave_id)
            self.is_running = True
            self._loop.run_until_complete(
                StartAsyncTcpServer(
                    context=[self.device],
                    address=(self.host, self.port),
                )
            )
        except Exception as e:
            logger.warning("Modbus TCP server stopped or failed to bind on %s:%d: %s", self.host, self.port, e)
        finally:
            self.is_running = False

    def start(self, wait_secs: float = 0.5) -> bool:
        """Start server in background daemon thread."""
        if self.is_running:
            return True

        self._thread = threading.Thread(target=self._run_server, daemon=True, name="ModbusServerThread")
        self._thread.start()
        time.sleep(wait_secs)
        return self.is_running

    def stop(self) -> None:
        """Stop Modbus TCP server gracefully."""
        if not self.is_running:
            return

        try:
            if self._loop and self._loop.is_running():
                future = asyncio.run_coroutine_threadsafe(ServerAsyncStop(), self._loop)
                future.result(timeout=2.0)
        except Exception as e:
            logger.warning("Error stopping Modbus server: %s", e)
        finally:
            self.is_running = False
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=1.0)
            logger.info("Modbus TCP server stopped.")
