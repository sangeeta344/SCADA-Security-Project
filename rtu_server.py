
import asyncio
import csv
import random
from pathlib import Path

from pymodbus.server import StartAsyncTcpServer
from pymodbus.simulator import SimData, SimDevice, DataType


# CSV dataset path
CSV_PATH = (
    Path(__file__).parent
    / "datasets"
    / "scada_sensor_dataset_200_rows.csv"
)

# Load sensor readings
with open(CSV_PATH, "r", newline="", encoding="utf-8") as file:
    sensor_rows = list(csv.DictReader(file))

if not sensor_rows:
    raise ValueError("The CSV dataset contains no readings.")

# Store the currently selected row number
selected_row_number = None


async def update_sensor_registers(
    function_code,
    start_address,
    address,
    count,
    current_registers,
    set_values,
):
    """Select a random CSV row and update the RTU registers."""
    global selected_row_number

    # Only respond to read-holding-register requests
    if function_code != 3 or set_values is not None:
        return

    # Select a random row (row numbers shown from 1 to 200)
    selected_row_number = random.randrange(len(sensor_rows))
    row = sensor_rows[selected_row_number]

    # Convert sensor values to Modbus integers
    sensor_values = [
        round(float(row["temperature_c"]) * 10),
        round(float(row["pressure_bar"]) * 10),
        round(float(row["water_level_mm"])),
        round(float(row["flow_rate_lpm"])),
    ]

    # Update registers 0, 1, 2 and 3
    for i, value in enumerate(sensor_values):
        index = i - start_address

        if 0 <= index < len(current_registers):
            current_registers[index] = value

    print(
        f"Random CSV row {selected_row_number + 1}: "
        f"Temperature={sensor_values[0] / 10:.1f} C, "
        f"Pressure={sensor_values[1] / 10:.1f} bar, "
        f"Water level={sensor_values[2]} mm, "
        f"Flow rate={sensor_values[3]} L/min"
    )


# Four holding registers
register_data = SimData(
    address=0,
    count=4,
    values=[250, 75, 1200, 450],
    datatype=DataType.REGISTERS,
)

# Configure RTU device
rtu_device = SimDevice(
    id=1,
    simdata=[register_data],
    action=update_sensor_registers,
)


async def main():
    print("=" * 45)
    print("SCADA RTU - MODBUS TCP SERVER")
    print("=" * 45)
    print(f"Dataset rows: {len(sensor_rows)}")
    print("Address: 127.0.0.1")
    print("Port: 5020")
    print("Mode: Random CSV row selection")
    print("Waiting for MTU requests...")
    print("=" * 45)

    await StartAsyncTcpServer(
        context=[rtu_device],
        address=("127.0.0.1", 5020),
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nRTU server stopped.")
