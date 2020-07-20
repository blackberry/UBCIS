###############################################################################
# Name   : Scan - Image scanner
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

import os
import json
import sys
import CreateSpreadsheet
import utils

from multiprocessing import Process

sys.path.insert(1, '/plugins')


def runScanner(plugins, scanner, image):
    plugins[scanner].configure()
    plugins[scanner].scan(image)
    plugins[scanner].destroy()


with open('/config/config.json') as f:
    config = json.load(f)

    if 'auths' in config:
        os.makedirs(os.path.dirname('/home/vagrant/.docker/config.json'), exist_ok=True)
        with open('/home/vagrant/.docker/config.json', 'w') as f:
            f.write(json.dumps({'auths': config['auths']}))

        os.makedirs(os.path.dirname('/root/.docker/config.json'), exist_ok=True)
        with open('/root/.docker/config.json', 'w') as f:
            f.write(json.dumps({'auths': config['auths']}))

    if 'scanners' not in config:
        print("Scanners array does not exist in config.json file. See README.")
    if 'images' not in config:
        print("Images array does not exist in config.json file. See README.")

    if len(config['scanners']) == 0:
        print("Scanners list in config is empty.")

    if len(config['images']) == 0:
        print("Images list in config is empty.")

    for image in config['images']:
        os.system("docker pull " + image)

    plugins = utils.loadPlugins()
    # Scan images
    processes = []

    for scanner in config['scanners']:
        if scanner not in plugins:
            print("Cannot run scanner", scanner, "plugin not loaded.")
        else:
            os.makedirs(f"/results/{scanner}", exist_ok=True)
            for image in config['images']:
                p = Process(target=runScanner, args=(plugins, scanner, image,))
                processes.append(p)
                p.start()

                if not config['parallel']:
                    p.join()

    if config['parallel']:
        for p in processes:
            p.join()

    print("All scanners have finished")

    CreateSpreadsheet.createSpreadsheet()
