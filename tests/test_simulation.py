"""Unit tests for industrial system simulation (sensors, actuators, PLC, RTU, MTU)."""

import pytest
from simulation.sensor_simulator import Sensor, SensorSimulator
from simulation.actuator_simulator import Pump, Valve, ActuatorSimulator
from simulation.industrial_process import IndustrialProcess
from simulation.plc_simulator import PLCSimulator
from simulation.rtu_simulator import RTUSimulator
from simulation.mtu_simulator import MTUSimulator


def test_sensor_bounded_readings():
    """Verify sensor generates values within designated boundaries and respects seed."""
    s1 = Sensor("TEMP_TEST", "Test Temperature", "°C", 10.0, 50.0, 25.0, seed=123)
    s2 = Sensor("TEMP_TEST", "Test Temperature", "°C", 10.0, 50.0, 25.0, seed=123)

    r1 = [s1.read() for _ in range(10)]
    r2 = [s2.read() for _ in range(10)]

    assert r1 == r2, "Deterministic seed must produce reproducible readings"
    for val in r1:
        assert 10.0 <= val <= 50.0, f"Value {val} out of bounds"


def test_actuator_state_transitions():
    """Verify pump and valve state changes."""
    pump = Pump()
    assert pump.is_running is True
    pump.set_state(False)
    assert pump.is_running is False
    assert pump.to_dict()["state"] == "OFF"

    valve = Valve()
    assert valve.is_open is False
    valve.set_state(True)
    assert valve.is_open is True
    assert valve.to_dict()["state"] == "OPEN"


def test_plc_safety_ladder_logic():
    """Verify PLC triggers safety cutoffs when thresholds are violated."""
    actuators = ActuatorSimulator()
    plc = PLCSimulator(actuators)

    # 1. Normal conditions
    normal_res = plc.execute_logic({"water_level_mm": 900.0, "temperature_c": 28.0, "pressure_bar": 2.5})
    assert "NORMAL" in normal_res["rule_fired"]

    # 2. High water level (> 980mm) -> Overflow protection (Pump OFF, Valve OPEN)
    overflow_res = plc.execute_logic({"water_level_mm": 1050.0, "temperature_c": 28.0, "pressure_bar": 2.5})
    assert actuators.pump.is_running is False
    assert actuators.valve.is_open is True
    assert "OVERFLOW_PREVENTION" in overflow_res["rule_fired"]

    # 3. Low water level (< 820mm) -> Dry run protection (Pump ON, Valve CLOSE)
    low_res = plc.execute_logic({"water_level_mm": 750.0, "temperature_c": 28.0, "pressure_bar": 2.5})
    assert actuators.pump.is_running is True
    assert actuators.valve.is_open is False
    assert "LOW_LEVEL" in low_res["rule_fired"]


def test_rtu_modbus_register_encoding():
    """Verify RTU scales engineering floats into 16-bit unsigned registers."""
    rtu = RTUSimulator()
    telemetry = {
        "temperature_c": 28.11,
        "pressure_bar": 2.603,
        "water_level_mm": 931.4,
        "flow_rate_lpm": 34.04,
        "operating_status": "NORMAL",
    }
    regs = rtu.update_from_telemetry(telemetry)
    assert len(regs) == 7
    assert regs[0] == 2811  # 28.11 * 100
    assert regs[1] == 2603  # 2.603 * 1000
    assert regs[2] == 9314  # 931.4 * 10
    assert regs[3] == 3404  # 34.04 * 100
    assert regs[6] == 1     # NORMAL status code


def test_mtu_decoding():
    """Verify MTU decodes registers back into exact physical float values."""
    mtu = MTUSimulator()
    registers = [2811, 2603, 9314, 3404, 1, 0, 1]
    decoded = mtu.decode_modbus_registers(registers)
    assert decoded["temperature_c"] == 28.11
    assert decoded["pressure_bar"] == 2.603
    assert decoded["water_level_mm"] == 931.4
    assert decoded["flow_rate_lpm"] == 34.04
    assert decoded["pump_state"] == "ON"
    assert decoded["valve_state"] == "CLOSED"
    assert decoded["operating_status"] == "NORMAL"
