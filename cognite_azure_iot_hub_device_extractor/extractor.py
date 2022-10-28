import base64
import hashlib
import hmac
import json
import logging
import time
import urllib
from datetime import datetime, timezone
from threading import Event

import requests
from cognite.client import CogniteClient
from cognite.client.data_classes import Asset, Label, Relationship, TimeSeries
from cognite.client.exceptions import CogniteNotFoundError
from cognite.extractorutils.statestore import AbstractStateStore

from cognite_azure_iot_hub_device_extractor.config import Config

logger = logging.getLogger(__name__)


class IotHubClient:
    def __init__(self, iothub_connection_string):
        self.iothub_connection_string = iothub_connection_string
        cs = dict(map(lambda x: x.split("=", 1), iothub_connection_string.split(";")))
        self.iothub_namespace = cs["HostName"].split(".")[0]
        self.sas_token = self._get_sas_token(cs["HostName"], cs["SharedAccessKeyName"], cs["SharedAccessKey"])

    def _get_sas_token(self, resource_uri, sas_name, sas_value):
        sas = base64.b64decode(sas_value.encode("utf-8"))
        expiry = str(int(time.time() + 10000))
        string_to_sign = (resource_uri + "\n" + expiry).encode("utf-8")
        signed_hmac_sha256 = hmac.HMAC(sas, string_to_sign, hashlib.sha256)
        signature = urllib.parse.quote(base64.b64encode(signed_hmac_sha256.digest()))
        return "SharedAccessSignature sr={}&sig={}&se={}&skn={}".format(resource_uri, signature, expiry, sas_name)

    def post(self, path, query={}):
        # logger.info(path)
        # REST API see doc: https://docs.microsoft.com/en-us/rest/api/iothub
        headers = {"Authorization": self.sas_token, "Content-Type": "application/json;charset=utf-8"}
        payload = {"query": query}
        uri = f"https://{self.iothub_namespace}.azure-devices.net{path}"
        return requests.post(uri, data=json.dumps(payload), headers=headers).json()

    def get(self, path):
        # logger.info(path)
        # REST API see doc: https://docs.microsoft.com/en-us/rest/api/iothub
        headers = {"Authorization": self.sas_token, "Content-Type": "application/json;charset=utf-8"}
        uri = f"https://{self.iothub_namespace}.azure-devices.net{path}"
        return requests.get(uri, headers=headers).json()


def create_device_asset(device, iothub_namespace, data_set_id):
    asset = Asset(external_id=device["deviceScope"], name=device["deviceId"], data_set_id=data_set_id)
    rels = []
    metadata = {}
    for k in device:
        if type(device[k]) == str:
            metadata[k] = device[k]
    asset.metadata = metadata

    if "parentScopes" in device:
        if len(device["parentScopes"]) > 0:  # only one parent relationship in hierarchy
            asset.parent_external_id = device["parentScopes"][0]

            for parent in device["parentScopes"]:
                xid = f"{device['deviceScope'].replace('ms-azure-iot-edge://','')}_p_{parent.replace('ms-azure-iot-edge://','')}"
                rels.append(
                    Relationship(
                        external_id=xid,
                        target_external_id=device["deviceScope"],
                        source_external_id=parent,
                        target_type="asset",
                        source_type="asset",
                        confidence=1.0,
                        data_set_id=data_set_id,
                        labels=[Label(external_id="isParentOf")],
                    )
                )
        else:
            asset.parent_external_id = iothub_namespace
            rels.append(
                Relationship(
                    external_id=f"{iothub_namespace}_{device['deviceScope'].replace('ms-azure-iot-edge://','')}",
                    target_external_id=device["deviceScope"],
                    source_external_id=iothub_namespace,
                    target_type="asset",
                    source_type="asset",
                    confidence=1.0,
                    data_set_id=data_set_id,
                    labels=[Label(external_id="isParentOf")],
                )
            )
    else:
        asset.parent_external_id = iothub_namespace
        rels.append(
            Relationship(
                external_id=f"{iothub_namespace}_{device['deviceScope'].replace('ms-azure-iot-edge://','')}",
                target_external_id=device["deviceScope"],
                source_external_id=iothub_namespace,
                target_type="asset",
                source_type="asset",
                confidence=1.0,
                data_set_id=data_set_id,
                labels=[Label(external_id="isParentOf")],
            )
        )

    return asset, rels


def update_device_timeseries(asset, device, data_set_id):
    timeseries = {}
    datapoints = []

    if (
        "connectionState" in device
        and "connectionStateUpdatedTime" in device
        and not device["connectionStateUpdatedTime"] == "0001-01-01T00:00:00Z"
    ):
        ext_id = f"{asset.external_id}_connectionState"
        dt = device["connectionStateUpdatedTime"][:26] + "Z"
        timestamp = datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        value = 1 if device["connectionState"] == "Connected" else 0
        datapoints.append({"externalId": ext_id, "datapoints": [(timestamp, value)]})

        timeseries[ext_id] = TimeSeries(external_id=ext_id, name="connectionState", data_set_id=data_set_id)

    return datapoints, timeseries


def create_module_asset(module, desired, reported, parent_asset, data_set_id):

    xid = f"{parent_asset.external_id}_{module}"
    asset = Asset(external_id=xid, name=module, data_set_id=data_set_id, parent_external_id=parent_asset.external_id)

    rels = []
    metadata = {}

    if desired:
        metadata["image"] = desired["settings"]["image"]
        if "createOptions" in desired["settings"]:
            metadata["createOptions"] = desired["settings"]["createOptions"]

        if "env" in desired:
            for key in desired["env"]:
                if (
                    not "secret" in key.lower()
                    and not "key" in key.lower()
                    and not "pass" in key.lower()
                    and not "connection_string" in key.lower()
                ):
                    metadata[key] = desired["env"][key]["value"]
                else:
                    metadata[key] = "<hidden>"
    if reported:
        metadata["exitCode"] = reported["exitCode"]
        metadata["statusDescription"] = reported["statusDescription"]
        metadata["lastStartTimeUtc"] = reported["lastStartTimeUtc"]
        metadata["lastExitTimeUtc"] = reported["lastExitTimeUtc"]
        metadata["restartCount"] = reported["restartCount"]
        metadata["lastRestartTimeUtc"] = reported["lastRestartTimeUtc"]
        metadata["runtimeStatus"] = reported["runtimeStatus"]
        metadata["version"] = reported["version"]
        metadata["status"] = reported["status"]
        metadata["restartPolicy"] = reported["restartPolicy"]
        metadata["imagePullPolicy"] = reported["imagePullPolicy"]

    asset.metadata = metadata

    rel_xid = f"{xid.replace('ms-azure-iot-edge://','')}_p_{parent_asset.name}"
    rel = Relationship(
        external_id=rel_xid,
        source_external_id=xid,
        target_external_id=parent_asset.external_id,
        target_type="asset",
        source_type="asset",
        confidence=1.0,
        data_set_id=data_set_id,
        labels=[Label(external_id="running_on")],
    )

    return asset, rel


def update_assets(client, assets, parent_external_id):
    logger.info(parent_external_id)

    filtered = [asset for asset in assets if asset.parent_external_id in parent_external_id]

    for asset in filtered:
        exist = client.assets.retrieve(external_id=asset.external_id)
        if exist:
            logger.info(f"Update {asset.name}")
            client.assets.update(asset)
        else:
            logger.info(f"create {asset.name}")
            client.assets.create(asset)

    xid = [asset.external_id for asset in filtered]
    if len(xid) > 0:
        update_assets(client, assets, xid)


def update_relationships(client, rels):
    xid = [rel.external_id for rel in rels]

    logger.info(xid)
    missing = []

    try:
        client.relationships.retrieve_multiple(external_ids=xid)
    except CogniteNotFoundError as e:
        missing = [r["externalId"] for r in e.not_found]

    update = [rel for rel in rels if not rel.external_id in missing]
    create = [rel for rel in rels if rel.external_id in missing]

    client.relationships.update(update)
    client.relationships.create(create)


def run_extractor(client: CogniteClient, states: AbstractStateStore, config: Config, stop_event: Event) -> None:

    iothub_client = IotHubClient(config.iothub.connection_string)
    root_asset = client.assets.retrieve(external_id=iothub_client.iothub_namespace)
    if not root_asset:
        client.assets.create(
            Asset(external_id=iothub_client.iothub_namespace, name="IotHub Edge", data_set_id=data_set_id)
        )

    data_set_id = (
        client.data_sets.retrieve(external_id=config.cognite.data_set_external_id).id
        if config.cognite.data_set_external_id
        else None
    )

    starttime = time.time()
    while True:

        query = "SELECT deviceId from devices WHERE capabilities.iotEdge = true"
        devices = iothub_client.post("/devices/query?api-version=2020-09-30", query)

        assets = []
        relationships = []
        if "Message" in devices:
            logger.error(f"Message: {devices['Message']}")
            logger.error(f"Exception: {devices['ExceptionMessage']}")
            return

        logger.debug(devices)
        for device in devices:
            deviceId = device["deviceId"]
            path = f"/devices/{deviceId}?api-version=2020-09-30"
            d = iothub_client.get(path)
            if "connectionState" in d:
                logger.info(f"{deviceId}: {d['connectionState']}")
            else:
                logger.info(d)

            asset, rels = create_device_asset(d, iothub_client.iothub_namespace, data_set_id)
            datapoints, timeseries = update_device_timeseries(asset, d, data_set_id)

            if len(datapoints) > 0:
                try:
                    client.datapoints.insert_multiple(datapoints)
                except:
                    for xid in timeseries:
                        cur_ts = client.time_series.retrieve(external_id=xid)
                        if cur_ts == None:
                            ts = timeseries[xid]
                            asset = client.assets.retrieve(external_id=asset.external_id)
                            if asset:  # will not exist on the first iteration
                                logger.info(f"create ts {ts.external_id}")
                                ts.asset_id = asset.id
                                client.time_series.create(ts)

                    client.datapoints.insert_multiple(datapoints)

            relationships = relationships + rels

            if d["capabilities"]["iotEdge"]:

                query = f"SELECT * FROM devices.modules WHERE moduleId in ['$edgeAgent'] and deviceId in ['{deviceId}']"
                edgeAgent = iothub_client.post("/devices/query?api-version=2020-09-30", query)[0]

                # query = f"SELECT * FROM devices.modules WHERE moduleId in ['$edgeHub'] and deviceId in ['{deviceId}']"
                # edgeHub = iothub_client.post("/devices/query?api-version=2020-09-30", query)[0]

                if "modules" in edgeAgent["properties"]["desired"]:
                    for key in edgeAgent["properties"]["desired"]["modules"]:
                        desired = edgeAgent["properties"]["desired"]["modules"][key]
                        reported = None

                        if (
                            "modules" in edgeAgent["properties"]["reported"]
                            and key in edgeAgent["properties"]["reported"]["modules"]
                        ):
                            reported = edgeAgent["properties"]["reported"]["modules"][key]

                        module_asset, module_relationship = create_module_asset(
                            key, desired, reported, asset, data_set_id
                        )

                        assets.append(module_asset)

                        relationships.append(module_relationship)

            assets.append(asset)

        update_relationships(client, relationships)
        update_assets(client, assets, parent_external_id=[iothub_client.iothub_namespace])

        sleep_time = config.iothub.update_interval - ((time.time() - starttime) % config.iothub.update_interval)
        logging.info(f"Sleeping for {sleep_time} seconds")
        time.sleep(sleep_time)  #
