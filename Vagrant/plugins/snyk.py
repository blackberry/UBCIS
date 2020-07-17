################################################################################
# Name   : Snyk - Snyk plugin
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
import subprocess

import sys
sys.path.insert(1, '/scipts')

import utils


def parse(vulnObj, fileLocation):
    text = open(fileLocation, 'r').read()
    firstLine = text.split('\n')[0]

    try:
        if firstLine == 'Failed to run the process ...':
            # Remove first line
            loaded = json.loads(''.join(text.split('\n')[1:]))
        else:
            loaded = json.loads(text)
    except Exception:
        return

    if 'vulnerabilities' in loaded:
        for line in loaded['vulnerabilities']:
            for cve in line['identifiers']['CVE']:
                vulnId = cve
                package = line['packageName']
                version = line['version']
                severity = line['severity']

                if vulnId not in vulnObj:
                    vulnObj[vulnId] = {}

                vulnObj[vulnId]['Snyk'] = utils.fixFields({
                    'package': package,
                    'version': version,
                    'severity': severity
                })


def configure():
    print("==========================")
    print("Running Snyk Scanner")
    print("==========================")


def scan(image):
    subprocess.run('''docker run -e "SNYK_TOKEN=$(cat /config/snyk/token)" -v "/home/tutorial/images/snyk_tests:/project" -v "/var/run/docker.sock:/var/run/docker.sock" snyk/snyk-cli:docker test --docker "''' + image + '''" > /results/snyk/''' + utils.createOutputName(image) + '''.json''', shell=True)


def destroy():
    print("Finished scanning with Snyk")
