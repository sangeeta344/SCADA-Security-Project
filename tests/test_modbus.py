"""Unit and integration tests for Modbus TCP protocol communication."""

import pytest
from config.protocol_config import ModbusRegisterMap
from protocols.modbus_server import ModbusServer
from protocols.modbus_client import ModbusClient


def test_modbus_register_map_scaling():
    """Verify register encoding and decoding precision."""
    temp_encoded = ModbusRegisterMap.encode_value(ModbusRegisterMap.REG_TEMPERATURE, 29.45)
    assert temp_encoded == 2945
    temp_decoded = ModbusRegisterMap.decode_value(ModbusRegisterMap.REG_TEMPERATURE, 2945)
    assert temp_decoded == 29.45

    press_encoded = ModbusRegisterMap.encode_value(ModbusRegisterMap.REG_PRESSURE, 2.654)
    assert press_encoded == 2654
    press_decoded = ModbusRegisterMap.decode_value(ModbusRegisterMap.REG_PRESSURE, 2654)
    assert press_decoded == 2.654


def test_modbus_server_datastore():
    """Verify ModbusServer datastore initialization and value updating."""
    server = ModbusServer(port=5020)
    assert len(server.register_data.values) == ModbusRegisterMap.TOTAL_REGISTERS

    test_vals = [2850, 2500, 9100, 3500, 1, 0, 1]
    server.update_registers(test_vals)

    assert server.get_register(ModbusRegisterMap.REG_TEMPERATURE) == 2850
    assert server.get_register(ModbusRegisterMap.REG_PUMP_STATE) == 1

    server.set_register(ModbusRegisterMap.REG_VALVE_STATE, 1)
    assert server.get_register(ModbusRegisterMap.REG_VALVE_STATE) == 1

    with pytest.raises(ValueError):
        server.get_register(99)


def test_modbus_client_offline_handling():
    """Verify ModbusClient gracefully reports offline status without crashing."""
    # Use non-existent port
    client = ModbusClient(host="127.0.0.1", port=59999, timeout=0.2)
    connected = client.connect()
    assert connected is False
    assert client.is_connected is False

    read_result = client.read_holding_registers(0, 4)
    assert read_result is None

    write_result = client.write_register(0, 100)
    assert write_result is False
