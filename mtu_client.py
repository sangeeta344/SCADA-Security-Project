
import asyncio
from pymodbus.client import AsyncModbusTcpClient


async def main():
    client = AsyncModbusTcpClient(
        host="127.0.0.1",
        port=5020
    )

    try:
        await client.connect()

        if not client.connected:
            print("Could not connect to RTU.")
            return

        print("Connected to RTU successfully!")
        print("Monitoring sensor data every 2 seconds.")
        print("Press Ctrl+C to stop.\n")

        while True:
            response = await client.read_holding_registers(
                address=0,
                count=4,
                device_id=1,
            )

            if response.isError():
                print("Error reading registers:", response)
            else:
                values = response.registers

                print("--- MTU: Sensor Readings ---")
                print(f"Temperature : {values[0] / 10:.1f} °C")
                print(f"Pressure    : {values[1] / 10:.1f} bar")
                print(f"Water Level : {values[2]} mm")
                print(f"Flow Rate   : {values[3]} L/min")
                print("-" * 30)

            await asyncio.sleep(2)

    finally:
        client.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nMTU monitoring stopped.")
