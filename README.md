Python script to view all running containers by executing an api call to `https://app0.cloud.twistlock.com/panw-app0-310/api/v1/bff/images/collated` then processing the information to make another api call for host data

### Body example
```
hasRunningContainers: true,
limit: 30,
sort: "vulnerabilities",
stage: "all"
```
