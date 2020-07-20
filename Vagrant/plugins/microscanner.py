###############################################################################
# Name   : Microscanner - Microscanner plugin
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
###############################################################################

import json
import shutil
import subprocess
import os

import sys
sys.path.insert(1, '/scipts')

import utils


def parse(vulnObj, fileLocation):
    text = open(fileLocation, 'r').read()

    acc = ''
    inside = False
    for line in text.split('\n')[1:]:
        if line == '      "resource": {':
            inside = True
            acc += "{" + line
        elif (line == '    },' or line == '    }') and inside:
            inside = False
            acc += "}"

            loaded = json.loads(acc)

            for line in loaded['vulnerabilities']:
                severity = 'Unknown'
                url = ''

                if 'nvd_severity' in line:
                    severity = line['nvd_severity']

                if 'nvd_url' in line:
                    url = line['nvd_url']

                vulnId = line['name']
                package = loaded['resource']['name']
                version = loaded['resource']['version']
                severity = severity

                if vulnId not in vulnObj:
                    vulnObj[vulnId] = {}

                vulnObj[vulnId]['Microscanner'] = utils.fixFields({
                    'package': package,
                    'version': version,
                    'severity': severity,
                    'url': url
                })

            acc = ''
        elif inside:
            acc += line


def configure():
    print("==========================")
    print("Running Microscanner Scanner")
    print("==========================")

    os.makedirs("/tmp/microscanner", exist_ok=True)
    os.chdir("/tmp/microscanner")
    os.system("git clone https://github.com/lukebond/microscanner-wrapper.git")
    os.chdir("/tmp/microscanner/microscanner-wrapper")


def scan(image):
    subprocess.run("MICROSCANNER_TOKEN=$(cat /config/microscanner/token) ./scan.sh " + image + " > /results/microscanner/" + utils.createOutputName(image) + ".json", shell=True)


def destroy():
    os.chdir("/")
    shutil.rmtree("/tmp/microscanner", ignore_errors=True)
    print("Finished scanning with Microscanner")
