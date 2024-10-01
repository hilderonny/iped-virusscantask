# Transcription and translation of audio files
# Configuration
# =============
# enabling: enableVirusScanning
# Config file: VirusScanning.txt

import time
import json
import requests

API_URL = None

def readJsonFile(file_path):
    with open(file_path, "r", encoding="utf-8") as json_file:
        file_contents = json_file.read()
    parsed_json = json.loads(file_contents)
    return parsed_json

class VirusScanningTask:

    enabled = False

    def isEnabled(self):
        return VirusScanningTask.enabled

    def getConfigurables(self):
        from iped.engine.config import DefaultTaskPropertiesConfig
        return [DefaultTaskPropertiesConfig("enableVirusScanning", "VirusScanning.txt")]

    def init(self, configuration):
        taskConfig = configuration.getTaskConfigurable("VirusScanning.txt")
        VirusScanningTask.enabled = taskConfig.isEnabled()
        if not VirusScanningTask.enabled:
            return
        extraProps = taskConfig.getConfiguration()
        global API_URL
        taskBridgeUrl = extraProps.getProperty("taskBridgeUrl")
        if not taskBridgeUrl.endswith("/"):
            taskBridgeUrl = f"{taskBridgeUrl}/"
        API_URL = f"{taskBridgeUrl}api/"

    def finish(self):
        return
        
    def process(self, item):
        item_name = item.getName()
        # Process only if not already in cache, therefor hashing must be enabled
        hash = item.getHash()
        if (hash is None) or (len(hash) < 1):
            return

        result = self.process_via_api(item, hash)
        
        if "status" in result:
            item.setExtraAttribute("virusscan:status", result["status"])
        if "detection" in result:
            item.setExtraAttribute("virusscan:detection", result["detection"])
        logger.info(f"Processed item {item_name}: {result}")

    def process_via_api(self, item, hash):
        result = {}

        scanforvirus_fp = open(item.getTempFile().getAbsolutePath(), "rb")
        scanforvirus_files = { "file" : scanforvirus_fp }
        scanforvirus_json = { "type" : "scanforvirus" }

        # Add scanforvirus task and upload file
        add_scanforvirus_response = requests.post(f"{API_URL}tasks/add/", files=scanforvirus_files, data={ "json" : json.dumps(scanforvirus_json) })
        if add_scanforvirus_response.status_code != 200:
            result["error"] = "Error adding scanforvirus task"
            return result
        task_scanforvirus_id = add_scanforvirus_response.json()["id"]

        # Wait for scanforvirus task completion
        task_scanforvirus_completed = False
        while not task_scanforvirus_completed:
            status_scanforvirus_response = requests.get(f"{API_URL}tasks/status/{task_scanforvirus_id}")
            if status_scanforvirus_response.status_code != 200:
                result["error"] = "Error requesting scanforvirus task status"
                return result
            status_scanforvirus = status_scanforvirus_response.json()["status"]
            if status_scanforvirus == "completed":
                task_scanforvirus_completed = True
            else:
                time.sleep(3)

        # Request scanforvirus result
        result_scanforvirus_response = requests.get(f"{API_URL}tasks/result/{task_scanforvirus_id}")
        if result_scanforvirus_response.status_code != 200:
            result["error"] = "Error requesting scanforvirus task result"
            return result
        scanforvirus_result = result_scanforvirus_response.json()

        # Delete scanforvirus task
        delete_scanforvirus_response = requests.delete(f"{API_URL}tasks/remove/{task_scanforvirus_id}")
        if delete_scanforvirus_response.status_code != 200:
            result["error"] = "Error deleting scanforvirus task"
            return result

        if "error" in scanforvirus_result["result"]:
            result["error"] = scanforvirus_result["result"]["error"]
        if "status" in scanforvirus_result["result"]:
            result["status"] = scanforvirus_result["result"]["status"]
        if "detection" in scanforvirus_result["result"]:
            result["detection"] = scanforvirus_result["result"]["detection"]

        return result
