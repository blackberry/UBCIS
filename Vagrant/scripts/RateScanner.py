################################################################################
# Name   : RateScanner - Rate scanners
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
import glob
import os

dataFilePath = '../benchmark/benchmark.json'

with open(dataFilePath, 'r') as json_file:
    loadedJson = json.load(json_file)

    for scanner in glob.glob('./vulns/*/'):
        scannerName = os.path.split(scanner)[-2]
        print('Rating scanner', scannerName)

        for file in glob.glob(scanner + '/*.txt'):
            imageName = os.path.split(".".join(file.split('.')[:-1]))[-1]

            counter = {
                'tp': 0,
                'c': 0,
                'mm': 0,
                'd': 0,
                'fp': 0
            }

            totals = {
                'tp': 0,
                'c': 0,
                'mm': 0,
                'd': 0,
                'fp': 0
            }

            if imageName not in loadedJson['images']:
                raise Exception('Image ' + imageName + ' is not currently supported.')

            # Find totals for current image
            for vuln in loadedJson['images'][imageName]:
                rating = vuln['trueVulnerability']
                if rating is not None:
                    rating = rating.lower()
                    if rating not in counter:
                        # This is a problem with a CVE not being marked. To fix this, add a mark in the spreadsheet
                        raise Exception("Invalid rating", rating, "for CVE", vuln, 'in', imageName)
                    else:
                        totals[rating] += 1

            print("Results for", imageName)

            with open(file, 'r') as vulnList:
                # Loop through user list, and check if the cve is in our list
                for findVuln in set(vulnList.read().splitlines()):
                    found = False

                    for vuln in loadedJson['images'][imageName]:
                        if findVuln == vuln['vulnerability']:
                            found = True
                            rating = vuln['trueVulnerability']
                            if rating is not None:
                                rating = rating.lower()
                                if rating not in counter:
                                    raise Exception("Invalid rating '" + rating + "'")
                                else:
                                    counter[rating] += 1
                    if not found:
                        print("No mark found for", findVuln, ". It has been ignored")

                counterTotal = counter['c'] + counter['tp'] + counter['fp'] + counter['mm'] + counter['d']
                totalTotal = totals['c'] + totals['tp'] + totals['fp'] + totals['mm'] + totals['d']

                if counterTotal == 0 or totalTotal == 0:
                    print("No vulnerabilities labelled for", imageName)
                    print()
                    continue

                print()
                precisionRelaxed = counter['tp'] / counterTotal
                precisionParanoid = (counterTotal - counter['fp']) / counterTotal

                recallRelaxed = 1.0 if totals['tp'] == 0 else counter['tp'] / totals['tp']
                recallParanoid = 1.0 if totalTotal - totals['fp'] == 0 else (counterTotal - counter['fp']) / (totalTotal - totals['fp'])

                fMeasureRelaxed = 2 * precisionRelaxed * recallRelaxed / (precisionRelaxed + recallRelaxed)
                fMeasureParanoid = 2 * precisionParanoid * recallParanoid / (precisionParanoid + recallParanoid)

                print('Relaxed', precisionRelaxed, recallRelaxed, fMeasureRelaxed)
                print('Paranoid', precisionParanoid, recallParanoid, fMeasureParanoid)
                print()
