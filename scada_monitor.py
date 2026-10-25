
import asyncio
from pymodbus.client import AsyncModbusTcpClient


async def read_sensor_data():
    """Read the four sensor registers from the RTU."""

    client = AsyncModbusTcpClient(
        host="127.0.0.1",
        port=5020,
        timeout=3,
    )

    try:
        await client.connect()

        if not client.connected:
            return {
                "connected": False,
                "error": "Could not connect to RTU at 127.0.0.1:5020",
            }

        response = await client.read_holding_registers(
            address=0,
            count=4,
            device_id=1,
        )

        if response.isError():
            return {
                "connected": False,
                "error": f"Modbus read failed: {response}",
            }

        values = response.registers

        return {
            "connected": True,
            "temperature": values[0] / 10,
            "pressure": values[1] / 10,
            "water_level": values[2],
            "flow_rate": values[3],
        }

    except Exception as error:
        return {
            "connected": False,
            "error": str(error),
        }

    finally:
        client.close()


if __name__ == "__main__":
    result = asyncio.run(read_sensor_data())
    print(result)
