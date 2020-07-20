################################################################################
# Name   : Trivy - Trivy plugin
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

    for line in loaded:
        if 'Vulnerabilities' in line and line['Vulnerabilities'] is not None:
            for vulnerability in line['Vulnerabilities']:
                vulnId = vulnerability['VulnerabilityID']
                package = vulnerability['PkgName']
                version = vulnerability['InstalledVersion']
                severity = vulnerability['Severity']

                if vulnId not in vulnObj:
                    vulnObj[vulnId] = {}

                vulnObj[vulnId]['Trivy'] = utils.fixFields({
                    'package': package,
                    'version': version,
                    'severity': severity
                })


def configure():
    print("==========================")
    print("Running Trivy Scanner")
    print("==========================")

    os.system("apt-get -y install wget apt-transport-https gnupg lsb-release")
    subprocess.run("wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add -", shell=True)
    subprocess.run("echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | tee -a /etc/apt/sources.list.d/trivy.list", shell=True)
    subprocess.run("apt-get update", shell=True)
    subprocess.run("apt-get install -y trivy", shell=True)
    subprocess.run("trivy --version", shell=True)


def scan(image):
    subprocess.run("trivy -f json -o /results/trivy/" + utils.createOutputName(image) + ".json " + image, shell=True)


def destroy():
    print("Finished scanning with Trivy")
