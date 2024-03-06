#!/usr/bin/env python

from datetime import datetime,date
import json
import sys
from pathlib import Path
import requests
from base64 import b64encode
from crayons import blue, green, yellow, white, red
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from threatresponse import ThreatResponse
import webexteamssdk

# adds /home to the path to import environment module
sys.path.insert(0, '/home')

# import API key module
import environment as env

# Setting API keys as constant variables:
# Cisco Umbrella
umbrella_api_key=env.UMBRELLA_OPENAPI_KEY
umbrella_api_secret=env.UMBRELLA_OPENAPI_SECRET
umbrella_host = env.UMBRELLA_OPENAPI_URL

# Cisco Secure Endpoint
amp_client_id = env.SECURE_ENDPOINT_CLIENT_ID
amp_api_key = env.SECURE_ENDPOINT_API_KEY
amp_host = env.SECURE_ENDPOINT_URL

# Cisco Secure Malware Analytics
tg_api_key=env.SECURE_MALWARE_ANALYTICS_API_KEY
tg_host=env.SECURE_MALWARE_ANALYTICS_URL

# Cisco XDR
xdr_client_id=env.XDR_CLIENT_ID
xdr_api_key=env.XDR_API_KEY
xdr_host=env.XDR_URL

# Webex
# webex_access_token = < INSERT WEBEX ACCESS TOKEN HERE>
webex_room_id = env.WEBEX_TEAMS_ROOM_ID


def get_amp_event_types(
    host=amp_host,
    client_id=amp_client_id,
    api_key=amp_api_key,
    ):
    """Get all Secure Endpoint event types."""

    # URL for API call
    url = f"https://{client_id}:{api_key}@{host}/v1/event_types"
    # Execute API call
    response = requests.get(url)
    # Consider any status other than 2xx an error
    response.raise_for_status()
    # Return event types as function output
    return response.json()


def get_amp_computers(
    host=amp_host,
    client_id=amp_client_id,
    api_key=amp_api_key,
    ):
    """Get a list of computers from  Cisco Secure Endpoint."""
    print("\n==> Getting computers from Cisco Secure Endpoint")
    # Construct the URL
    url = f"https://{client_id}:{api_key}@{host}/v1/computers"

    response = requests.get(url)
    # Consider any status other than 2xx an error
    response.raise_for_status()

    computer_list = response.json()["data"]

    return computer_list


def get_amp_events(query_params="",
    host=amp_host,
    client_id=amp_client_id,
    api_key=amp_api_key,
):
    """Get a list of recent events from  Cisco Secure Endpoint."""
    print("\n==> Getting events from Cisco Secure Endpoint")
    # Construct the URL
    url = f"https://{client_id}:{api_key}@{host}/v1/events"

    response = requests.get(url, params=query_params)
    # Consider any status other than 2xx an error
    response.raise_for_status()

    events_list = response.json()["data"]

    return events_list


def amp_isolation(method, computer_guid,
    host=amp_host,
    client_id=amp_client_id,
    api_key=amp_api_key,
):
    print(f"\n==> Performing {method} isolation in Cisco Secure Endpoint")

    url = f"https://{client_id}:{api_key}@{host}/v1/computers/{computer_guid}/isolation"

    if method == 'get':
        response = requests.get(url)
        response.raise_for_status()
    elif method == 'put':
        response = requests.put(url)
        if response.status_code == 409:
            print(red("ATTENTION: The computer is already isolated."))
        else:
            response.raise_for_status()
    elif method == 'delete':
        response = requests.delete(url)
        if response.status_code == 409:
            print(red("ATTENTION: Isolation has already been stopped."))
        else:
            response.raise_for_status()
    else:
        print(red("ERROR: Unrecognized REST API Method. Please use 'get', 'put' or 'delete'."))
        sys.exit(1)

    isolation_status = response.json()["data"]

    return isolation_status


def get_amp_scds(query_params="",
    host=amp_host,
    client_id=amp_client_id,
    api_key=amp_api_key,
):
    """Get a list of Simple Customer Detection lists from Cisco Secure Endpoint."""
    print("\n==> Getting SCDs from Cisco Secure Endpoint")
    url = f"https://{client_id}:{api_key}@{host}/v1/file_lists/simple_custom_detections"

    response = requests.get(url, params=query_params)
    # Consider any status other than 2xx an error
    response.raise_for_status()

    scds_list = response.json()["data"]

    return scds_list


def amp_scd(method,
    scd_guid,
    sha256,
    host=amp_host,
    client_id=amp_client_id,
    api_key=amp_api_key
):
    print(f"\n==> Performing {method} file hash {sha256} for Simple Customer Detection list {scd_guid}")

    url = f"https://{client_id}:{api_key}@{host}/v1/file_lists/{scd_guid}/files/{sha256}"

    if method == 'get':
        response = requests.get(url)
        if response.status_code == 404:
            print(red("ATTENTION: The File List Item not found for given sha256."))
        else:
            response.raise_for_status()
    elif method == 'post':
        response = requests.post(url)
        if response.status_code == 409:
            print(red("ATTENTION: The file hash is already added."))
        else:
            response.raise_for_status()
    elif method == 'delete':
        response = requests.delete(url)
        response.raise_for_status()
    else:
        print(red("ERROR: Unrecognized REST API Method. Please use 'get', 'post' or 'delete'."))
        sys.exit(1)

    file_status = response.json()["data"]

    return file_status