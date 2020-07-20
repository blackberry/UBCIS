################################################################################
# Name   : Anchore - Anchore plugin
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

import os

import sys
sys.path.insert(1, '/scipts')

import utils


def parse(vulnObj, fileLocation):
    text = open(fileLocation, 'r').read()

    # Remove first line
    lines = text.split('\n')

    if len(lines) <= 1:
        return

    body = lines[1:]

    for line in body:
        parts = line.split()
        if len(parts) > 3:
            vulnId = parts[0]
            package = parts[1]
            version = ''
            severity = parts[2]
            url = parts[5]

            if vulnId not in vulnObj:
                vulnObj[vulnId] = {}

            vulnObj[vulnId]['Anchore'] = utils.fixFields({
                'package': package,
                'version': version,
                'severity': severity,
                'url': url
            })


def configure():
    print("==========================")
    print("Running Anchore Scanner")
    print("==========================")

    os.system("docker pull docker.io/anchore/anchore-engine:latest")
    os.chdir("/config/anchore")
    os.system("docker-compose pull")
    os.system("docker-compose up -d")
    os.system("sleep 60")
    os.system("docker ps")

    os.system("docker-compose exec -T engine-api anchore-cli system feeds list")

    # This will only wait for at least one feed being populated, not all the feeds so check results
    os.system("docker-compose exec -T engine-api anchore-cli system wait")

def scan(image):
    os.system("docker-compose exec -T engine-api anchore-cli image add " + image)
    os.system("docker-compose exec -T engine-api anchore-cli image wait " + image)
    os.system("docker-compose exec -T engine-api anchore-cli image vuln " + image + " all > /results/anchore/" + utils.createOutputName(image) + ".json")

def destroy():
    print("Finished scanning with Anchore")
