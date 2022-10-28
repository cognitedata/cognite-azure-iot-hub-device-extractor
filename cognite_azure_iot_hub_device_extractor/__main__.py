from cognite.extractorutils import Extractor

from cognite_azure_iot_hub_device_extractor import __version__
from cognite_azure_iot_hub_device_extractor.config import Config
from cognite_azure_iot_hub_device_extractor.extractor import run_extractor


def main() -> None:
    with Extractor(
        name="cognite_azure_iot_hub_device_extractor",
        description="Pull device information from IoT Hub and creates assets and time series to reflect the current status of IoT Hub",
        config_class=Config,
        run_handle=run_extractor,
        version=__version__,
    ) as extractor:
        extractor.run()


if __name__ == "__main__":
    main()
