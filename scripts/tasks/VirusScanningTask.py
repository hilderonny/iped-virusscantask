# Transcription and translation of audio files
# Configuration
# =============
# enabling: enableVirusScanning
# Config file: VirusScanning.txt

import os
import time
import json
import shutil
import requests

# Configuration properties
enableProp = "enableVirusScanning"
configFile = "VirusScanning.txt"
forensicTaskBridgeApiUrlProp = "forensicTaskBridgeApiUrl"
forensicTaskBridgeShareDirectoryProp = "forensicTaskBridgeShareDirectory"

API_URL = None
API_SHARE_DIR = None

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
        return [DefaultTaskPropertiesConfig(enableProp, configFile)]

    def init(self, configuration):
        taskConfig = configuration.getTaskConfigurable(configFile)
        VirusScanningTask.enabled = taskConfig.isEnabled()
        if not VirusScanningTask.enabled:
            return
        extraProps = taskConfig.getConfiguration()
        global API_URL, API_SHARE_DIR
        API_URL = extraProps.getProperty(forensicTaskBridgeApiUrlProp)
        API_SHARE_DIR = extraProps.getProperty(forensicTaskBridgeShareDirectoryProp)

    def finish(self):
        return
        
    # Process an Item object. This method is executed on all case items.
    # It can access any method of Item class and store results as a new extra attribute.
    #
    #  Some Getters:
    #  String:  getName(), getExt(), getType(), getPath(), getHash(), getMediaType().toString(), getCategories() (categories separated by | )
    #  Date:    getModDate(), getCreationDate(), getAccessDate() (podem ser nulos)
    #  Boolean: isDeleted(), isDir(), isRoot(), isCarved(), isSubItem(), isTimedOut(), hasChildren()
    #  Long:    getLength()
    #  Metadata getMetadata()
    #  Object:  getExtraAttribute(String key) (returns an extra attribute)
    #  String:  getParsedTextCache() (returns item extracted text, if this task is placed after ParsingTask)
    #  File:    getTempFile() (returns a temp file with item content)
    #  BufferedInputStream: getBufferedInputStream() (returns an InputStream with item content)
    #
    #  Some Setters: 
    #           setToIgnore(boolean) (ignores the item and excludes it from processing and case)
    #           setAddToCase(boolean) (inserts or not item in case, after being processed: default true)
    #           addCategory(String), removeCategory(String), setMediaTypeStr(String)
    #              setExtraAttribute(key, value), setParsedTextCache(String)
    #
    def process(self, item):
        item_name = item.getName()
        # Process only if not already in cache, therefor hashing must be enabled
        hash = item.getHash()
        if (hash is None) or (len(hash) < 1):
            return

        result = self.process_via_api(item, hash)

        if "status" in result:
            item.setExtraAttribute("virusscan:status", result["status"])
        if "virus" in result:
            item.setExtraAttribute("virusscan:virus", result["virus"])
        logger.info("Processed item %s: %s", item_name, result)

    # Result format
    #   status
    #   virus

    def process_via_api(self, item, hash):
        result = {}
        # Copy file to share folder
        source_file_path = item.getTempFile().getAbsolutePath()
        share_file_path = os.path.join(API_SHARE_DIR, hash)
        shutil.copy(source_file_path, share_file_path)
        # Add virus scanning task
        response = requests.post(f"{API_URL}tasks/scanforvirus/add/{hash}/clamav")
        if response.status_code != 200:
            logger.error(f"Cannot access {API_URL}tasks/scanforvirus/add/{hash}/clamav")
            return result
        add_virusscan_json_result = response.json()
        #print(add_virusscan_json_result)
        virusscan_task_id = add_virusscan_json_result["id"]
        # Wait for completion
        while requests.get(f"{API_URL}tasks/status/{virusscan_task_id}").json()["status"] != "done":
            time.sleep(5)
        virusscan_result = requests.get(f"{API_URL}tasks/result/{virusscan_task_id}").json()
        #print(virusscan_result)
        if "error" in virusscan_result["result"]:
            result["error"] = virusscan_result["result"]["error"]
        else:
            # Collect results
            result["status"] = virusscan_result["result"]["status"]
            if "virus" in virusscan_result["result"]:
                result["virus"] = virusscan_result["result"]["virus"]
        # Delete task from bridge
        delete_result = requests.delete(f"{API_URL}tasks/remove/{virusscan_task_id}")
        #print(delete_result)
        print(result)
        return result