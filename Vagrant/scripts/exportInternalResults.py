################################################################################
# Name   : CreateSpreadsheet - Create excel spreadsheets
# Author : Alexander Parent
#
# Copyright 2020 BlackBerry Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
################################################################################

import json
import os

config = None
with open('/config/config.json', 'r') as json_file:
    config = json.load(json_file)

output = "/results/output/" + config['output']

with open(output + '.json', 'r') as outfile:
    loadedValues = json.load(outfile)

parserObjs = {}

for image in loadedValues['images']:
    for vuln in loadedValues['images'][image]:
        vulnId = vuln['vulnerability']
        for parser in vuln['parsers'].keys():
            if parser not in parserObjs:
                parserObjs[parser] = {}

            if image not in parserObjs[parser]:
                parserObjs[parser][image] = []

            parserObjs[parser][image].append(vulnId)

os.makedirs(f"/results/tmp", exist_ok=True)
for parser in parserObjs:
    os.makedirs(f"/results/tmp/{parser}", exist_ok=True)
    for image in parserObjs[parser]:
        with open(f"/results/tmp/{parser}/{image}.txt", 'w') as outfile:
            outfile.write('\n'.join(parserObjs[parser][image]))
