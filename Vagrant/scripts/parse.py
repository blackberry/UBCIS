###############################################################################
# Name   : Parse - Parse scanner output
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
import os.path
import sys
import utils

sys.path.insert(1, '/plugins')
resultsPath = '/results'


def parseContainer(containerName, scanners):
    vulnObj = {}

    plugins = utils.loadPlugins()

    # If plugin for scanner is found, use it
    for scanner in scanners:
        if scanner in plugins:
            fileLocation = f'{resultsPath}/{scanner}/{containerName}.json'

            if os.path.isfile(fileLocation):
                plugins[scanner].parse(vulnObj, fileLocation)

    return vulnObj


# Map package names for output
imageLibs = {
    'alpine_3_9_4': {
    },
    'debian_10_2': {
        'libgcrypt': 'libgcrypt20'
    },
    'fedora_29': {

    },
    'ubuntu_18_10': {

    },
    'centos_7_7_1908': {
        'gnutls': 'gnutls28',
        'libgnutls30': 'gnutls28',
        'python': 'python-libs',
        'glibc': 'glibc-common',
        'glib': 'glib2',
        'gnupg2': 'libcrypt',
        'pcre': None,
        'gnupg2-2.0.22-5.el7_5': 'gpupg2'
    }
}


def getRealName(name, libs):
    currentName = name

    # Traverse tree
    while currentName in libs and libs[currentName] is not None:
        currentName = libs[currentName]

    return currentName


def getLetters(string):
    count = 0
    for char in string:
        if char.isalpha():
            count += 1
    return count


def getNumbers(string):
    count = 0
    for char in string:
        if char.isnumeric():
            count += 1
    return count


def getNumbersLettersRatio(string):
    letters = getLetters(string)
    numbers = getNumbers(string)

    if numbers == 0:
        numbers = 1

    return letters / numbers


def parseContainers(containerNames, scanners, oldData=None):
    allVulns = {'images': {}}
    for containerName in containerNames:
        packageVersions = {}
        vulnMapping = {}

        allVulns['images'][containerName] = []
        vulns = parseContainer(containerName, scanners)

        if oldData is not None and containerName in oldData['images']:
            for oldVuln in oldData['images'][containerName]:
                if oldVuln['vulnerability'] not in vulns:
                    vulns[oldVuln['vulnerability']] = oldVuln['parsers']

        # Generate mappings for lib names
        if containerName not in imageLibs:
            imageLibs[containerName] = {}

        libs = imageLibs[containerName]

        packages = set()

        for vuln in vulns:
            tempPackages = {}

            for parser in vulns[vuln]:
                info = vulns[vuln][parser]
                name = info['package']
                # Take the one with better ration of letters:numbers
                # This will remove the package names that aren't parsed correctly

                if getNumbers(name) > 3:
                    split = name.split('-')

                    # Find where split becomes version by checking number letter ratio
                    place = 0
                    for part in split:
                        if getNumbers(part) > 2 or getNumbersLettersRatio(part) < 0.3:
                            break
                        place += 1

                    newName = '-'.join(split[:place])
                    version = '-'.join(split[place:])
                    libs[name] = newName
                    packageVersions[newName] = set([version])

                tempPackages[name] = getNumbersLettersRatio(name)

            foundName = None
            for temp in tempPackages:
                if foundName is None:
                    foundName = temp
                elif tempPackages[temp] > tempPackages[foundName]:
                    foundName = temp

            for temp in tempPackages:
                if foundName not in libs and foundName != temp:
                    libs[temp] = foundName

        packages = sorted(packages, key=len, reverse=True)

        # pp = pprint.PrettyPrinter(depth=6)
        # pp.pprint(libs)

        for name in packages:
            # find if package name is in libs
            found = [s for s in libs.keys() if name in s]

            if len(found) == 0:
                libs[name] = None
            elif name not in found and name not in libs:
                if len(found) > 1:
                    print('Error: Multiple mapping for', name, ' -> ', found)
                    print("Using first entry", found[0])
                    print()

                if found[0] not in libs:
                    libs[name] = found[0]

        # Get package versions for mappings
        # Get package name, go down branch, and insert version in to set for that package name
        for vuln in vulns:
            for parser in vulns[vuln]:
                info = vulns[vuln][parser]
                version = info['version']
                name = getRealName(info['package'], libs)
                vulnMapping[vuln] = name

                if name not in packageVersions:
                    packageVersions[name] = set()

                if len(version) != 0:
                    packageVersions[name].add(version)

        # Remove version if it is a subset
        for package in packageVersions:
            versions = packageVersions[package]
            removeVersions = set()

            for version in versions:
                for sub in versions:
                    if version.find(sub) != -1 and sub != version:
                        removeVersions.add(sub)

            versions = versions.difference(removeVersions)
            packageVersions[package] = versions

        # pp = pprint.PrettyPrinter(depth=6)
        # pp.pprint(packageVersions)

        for vuln in vulns:
            allVulns['images'][containerName].append({
                "parsers": vulns[vuln],
                "vulnerability": vuln,
                "trueVulnerability": '',
                "notes": '',
                "version": ', '.join(packageVersions[vulnMapping[vuln]]),
                "package": vulnMapping[vuln]
            })

        allVulns['images'][containerName].sort(key=lambda x: x['package'], reverse=False)

    allVulns['parsers'] = scanners
    return allVulns


if __name__ == "__main__":
    containerNames = ['alpine_3_9_4']
    # containerNames = ['ubuntu_18_10']
    scanners = ["anchore", "clair", "microscanner", "trivy", "synk"]

    (json.dumps(parseContainers(containerNames, scanners)))
