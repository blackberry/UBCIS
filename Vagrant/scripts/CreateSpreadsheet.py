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

from openpyxl import Workbook
import os
import json
import parse
import utils

oldData = {
    'images': [],
    'parsers': []
}

config = None
with open('/config/config.json', 'r') as json_file:
    config = json.load(json_file)

output = "/results/output/" + config['output']

containerNames = []

# Load container names from config
for container in config['images']:
    containerNames.append(utils.createOutputName(container))

scanners = config['scanners']

if os.path.isfile(output + '.json'):
    with open(output + '.json', 'r') as json_file:
        oldData = json.load(json_file)


def createRow(vulnInfo, oldImageData, newImageData, parsers):
    vulnerability = vulnInfo['vulnerability']

    fields = {
        'package': set(),
        'version': set(),
        'severity': set(),
        'url': set()
    }

    parserFound = [0] * len(parsers)

    for parser in vulnInfo['parsers']:
        parserIndex = parsers.index(parser.lower())
        parserFound[parserIndex] = 1

        for field in fields.keys():
            if vulnInfo['parsers'][parser][field] != '':
                fields[field].add(vulnInfo['parsers'][parser][field])

    versions = vulnInfo['version']
    packages = vulnInfo['package']

    trueVuln = ''
    notes = ''

    # Move old data to new data
    filtered = list(filter(lambda x: x['vulnerability'] == vulnerability, oldImageData))
    if len(filtered) == 1:
        trueVuln = filtered[0]['trueVulnerability']
        notes = filtered[0]['notes']

    filtered = list(filter(lambda x: x['vulnerability'] == vulnerability, newImageData))
    if len(filtered) == 1:
        filtered[0]['trueVulnerability'] = trueVuln
        filtered[0]['notes'] = notes

    # Add url
    hyperlink = ''
    if len(list(fields['url'])) > 0:
        hyperlink = '=HYPERLINK("{}", "{}")'.format(list(fields['url'])[0], 'Link')

    return [packages, vulnerability, versions, ', '.join(fields['severity']), hyperlink, '', trueVuln, notes, ''] + parserFound


def createSpreadsheet():
    os.makedirs("/results/output", exist_ok=True)

    data = parse.parseContainers(containerNames, scanners, oldData)
    images = data['images']

    data['parsers'].sort()

    wb = Workbook()
    wb.remove(wb.active)

    titles = ['Library', 'Vulnerability ID', 'Version Detected', 'Severity', 'Url', 'Fixed At', 'True Vulnerability', 'Notes', ''] + data['parsers']

    # Loop through images and create sheet
    for image in images:
        ws = wb.create_sheet(title=image)
        ws.append(titles)

        # Resize columns
        letter = 'A'
        for title in titles:
            ws.column_dimensions[letter].width = len(title) + 5
            letter = chr(ord(letter) + 1)

        # Add data from json to spreadsheet
        for vuln in images[image]:
            if image in oldData['images']:
                ws.append(createRow(vuln, oldData['images'][image], data['images'][image], data['parsers']))
            else:
                ws.append(createRow(vuln, [], data['images'][image], data['parsers']))

        ws.append([])
        ws.append(['Totals'] + [''] * 8 + ['=SUM(INDIRECT(ADDRESS(1,COLUMN())&":"&ADDRESS(ROW()-1,COLUMN())))'] * len(data['parsers']))

    # Save the files
    with open(output + '.json', 'w') as outfile:
        json.dump(data, outfile)

    if config['createXLSX']:
        wb.save(output + '.xlsx')


if __name__ == "__main__":
    createSpreadsheet()
