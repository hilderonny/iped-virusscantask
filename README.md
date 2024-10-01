# iped-virusscantask

[IPED](https://github.com/sepinf-inc/IPED) task for virus scanning via shared workers

# iped-virusscantask

[IPED](https://github.com/sepinf-inc/IPED) task for virus scanning via distributed workers. Uses [Task Bridge](https://github.com/hilderonny/taskbridge) together with [ScanForVirus](https://github.com/hilderonny/taskworker-scanforvirus) worker for distributing and doing the work.

## Output

Using this task each file will get the following additional metadata.

|Property|Description|
|-|-|
|`virusscan:status`|`FOUND``when a virus was detected and `OK` when the file is clean.|
|`virusscan:detection`|Name of the detected virus. If no virus was found, this element is empty.|

## Installation

First download an install [IPED](https://github.com/sepinf-inc/IPED).

Next copy the file `scripts/tasks/VirusScanningTask.py` into the `scripts/tasks` folder of your IPED installation.

Copy the file `conf/VirusScanning.txt` into the `conf` directory of your IPED installation.

In your IPED folder open the file `IPEDConfig.txt` and add the following line.

```
enableVirusScanning = true
```

Finally open the file `conf/TaskInstaller.xml` and look for a line containing `iped.engine.task.ParsingTask`. Add the following line after this line:

```xml
<task script="VirusScanningTask.py"></task>
```

## Configuration

The configuration is done in the file `conf/VirusScanning.txt` in your IPED directory. This files contains comments on how to setup the connection to the task bridge.
