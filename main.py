import json
import logging
import os
import requests
from typing import Tuple, Optional

cwpUrl = "https://app0.cloud.twistlock.com/panw-app0-310"
cspmURL = "https://api0.prismacloud.io"
imagesURL = "https://app0.cloud.twistlock.com/panw-app0-310/api/v1/bff/images/collated"
logging.basicConfig(level=logging.INFO)


def allRunningContainers(token: str):
    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
        "Authorization": f"Bearer {token}",
    }

    body = {
        #   "stage": "all",
        "sort": "vulnerabilities",
        "hasRunningContainers": True,
        "limit": 300,
    }

    response = requests.post(
        imagesURL, headers=headers, json=body, timeout=60, verify=False
    )

    print(response.content)


def main():
    accessKey = os.environ.get("PC_IDENTITY")
    accessSecret = os.environ.get("PC_SECRET")
    response, cwpToken = generateCwpToken(accessKey, accessSecret)
    response, cspmToken = generateCSPMToken(accessKey, accessSecret)
    allRunningContainers(cwpToken)


def generateCSPMToken(accessKey: str, accessSecret: str) -> Tuple[int, str]:
    authURL = cspmURL + "/login"
    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
    }
    body = {"username": accessKey, "password": accessSecret}
    response = requests.post(
        authURL, headers=headers, json=body, timeout=60, verify=False
    )

    if response.status_code == 200:
        data = json.loads(response.text)
        logging.info("Token acquired")
        return 200, data["token"]
    else:
        logging.error(
            "Unable to acquire spm token with error code: %s", response.status_code
        )

    return response.status_code, ""


def generateCwpToken(accessKey: str, accessSecret: str) -> Tuple[int, str]:
    authURL = cwpUrl + "/api/v1/authenticate"
    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
    }
    body = {"username": accessKey, "password": accessSecret}
    response = requests.post(
        authURL, headers=headers, json=body, timeout=60, verify=False
    )

    if response.status_code == 200:
        data = json.loads(response.text)
        logging.info("Token acquired")
        return 200, data["token"]
    else:
        logging.error(
            "Unable to acquire token with error code: %s", response.status_code
        )

    return response.status_code, ""


if __name__ == "__main__":
    main()
