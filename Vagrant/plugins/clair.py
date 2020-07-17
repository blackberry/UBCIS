################################################################################
# Name   : Clair - Clair plugin
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
import subprocess
import shutil

import sys
sys.path.insert(1, '/scipts')

import utils


def parse(vulnObj, fileLocation):
    try:
        text = open(fileLocation, 'r').read()
        loaded = json.loads(text)
    except Exception:
        return

    if loaded is None:
        return

    for line in loaded['vulnerabilities']:
        vulnId = line['vulnerability']
        package = line['featurename']
        version = line['featureversion']
        severity = line['severity']
        # Don't use Clair's url links they don't work

        if vulnId not in vulnObj:
            vulnObj[vulnId] = {}

        vulnObj[vulnId]['Clair'] = utils.fixFields({
            'package': package,
            'version': version,
            'severity': severity,
        })


def configure():
    print("==========================")
    print("Running Clair Scanner")
    print("==========================")

    os.chdir("/config/clair")

    subprocess.run("wget -q https://github.com/arminc/clair-scanner/releases/download/v12/clair-scanner_linux_amd64", shell=True)
    shutil.move("./clair-scanner_linux_amd64", "./clair-scanner")
    os.system("chmod +x ./clair-scanner")

    os.system("touch clair-whitelist.yml")
    subprocess.run("docker run -d -p 5432:5432 --name db arminc/clair-db:latest", shell=True)
    os.system("sleep 15")
    subprocess.run("docker run -d -p 6060:6060 --link db:postgres --name clair arminc/clair-local-scan:v2.0.1", shell=True)
    os.system("sleep 15")
    os.system("docker ps")


def scan(image):
    ip = os.popen('echo $(hostname -I | cut -d" " -f1)').read().replace('\n', '').replace('\r', '')
    subprocess.run("./clair-scanner --ip=\"" + ip + "\" -r /results/clair/" + utils.createOutputName(image) + ".json " + image, shell=True)


def destroy():
    os.system("docker stop db")
    os.system("docker stop clair")
    os.system("docker rm db")
    os.system("docker rm clair")
    os.remove("clair-scanner")
    os.chdir('/')
    print("Finished scanning with Clair")
