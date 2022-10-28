FROM python:3.10-slim-buster
RUN python -m pip install --upgrade pip
WORKDIR /cognite
COPY requirements.txt /cognite/requirements.txt
RUN python -m pip install --force-reinstall -r /cognite/requirements.txt

COPY config.yaml config.yaml
ADD cognite_azure_iot_hub_device_extractor ./cognite_azure_iot_hub_device_extractor

ENTRYPOINT [ "python", "-m", "cognite_azure_iot_hub_device_extractor.__main__", "config.yaml" ]
