################################################################################
# Name   : utils - Utilities
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


def fixFields(fields):
    for field in fields:
        fields[field] = fields[field].lower()

    if 'url' not in fields:
        fields['url'] = ''

    return fields


def loadPlugins():
    pluginFiles = os.listdir('/plugins')
    plugins = {}

    # Import plugins and map to plugins object
    for pluginFile in pluginFiles:
        module = pluginFile.split('.')

        if len(module) != 2 or module[-1] != 'py':
            continue

        lib = __import__(module[0], globals(), locals(), [], 0)
        plugins[module[0]] = lib

    return plugins


def createOutputName(image):
    return image.replace(".", "_").replace(":", "_").replace("/", "_")
