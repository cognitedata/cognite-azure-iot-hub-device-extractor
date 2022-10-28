from dataclasses import dataclass

from cognite.extractorutils.configtools import BaseConfig, StateStoreConfig


@dataclass
class IotHubConfig:
    connection_string: str
    update_interval: int = 60


@dataclass
class ExtractorConfig:
    data_set_external_id: str = None
    state_store: StateStoreConfig = StateStoreConfig()


@dataclass
class Config(BaseConfig):
    iothub: IotHubConfig = IotHubConfig

    extractor: ExtractorConfig = ExtractorConfig()
