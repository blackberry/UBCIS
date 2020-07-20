# UBCIS

Ultimate Benchmark for Container Image Scanning (UBCIS) is a benchmark for detecting the scanner performance in terms of precision and vulnerability coverage on most common Linux Docker basic images. UBCIS can evaluate your scanner and score it using statistical notations of precision, recall and f-measure. UBCIS can also run a set of scanners on a set of container images and smartly merge the results without you worrying about the setup.

## Getting Started

### Pre-requisites

* VirtualBox / VMware /KVM or any other hypervisor is required. Vagrant traditionally works with all the major hypervisors.

* Vagrant - UBCIS uses Vagrant to reduce container image scanning into one simple command. Vagrant is a tool for building and managing virtual machine environments in a single workflow. To install Vagrant on your system simply download the latest Vagrant version for your platform from [here](https://www.vagrantup.com/downloads) and run the installer. The installer will automatically add vagrant to your system path so that it is available in terminals. Refer to [this](https://www.vagrantup.com/docs/installation) page for more detailed instructions.

### Usage

UBCIS installation and operation was tested on Windows and Ubuntu but should work equally well on any system with Vagrant and supported hypervisor. 

Getting the source:
```
git clone https://github.com/blackberry/UBCIS.git
```

You are ready to go, no installation required.

UBCIS has two main functionalities: (1) scanning the set of images with the set of scanners with one powerful command (**Superscan**) and (2) evaluating your own scanner against the benchmark (**Scorer**). 

Internally, we use Superscan to generate the benchmark as it does exactly want we need - runs multiple scanners on multiple images, merges the resulted vulnerabilities and eliminates the duplicates. After that, we manually judge / associate the vulnerabilities with TP, FP or other applicability classes. The judged vulnerabilities constitute the benchmark that is used on Scorer to evaluate other scanners. If you only want to take a look at the benchmrak itself you can find it here: `./Vagrant/benchmark/benchmark.json`. As of June 2020, the resulting benchmark on three chosen images consisted of 90 Debian vulnerabilities, 76 Ubuntu vulnerabilities and 10 Alpine vulnerabilities.

#### Superscan

Installation, setup and configuration of container image scanners is an adventure. Some scanners make it easy, while others require hours of setup work. Superscan is a powerful tool that abstracts away the headaches of setting up container image scanners and allows for easy scanning of multiple images. Supported scanners are: Anchore, Clair, Microscanner, Snyk and Trivy. To configure the Superscan follow these steps:

1. Update `./Vagrant/config/config.json` with the images to be scanned, and the scanners to use. For example:

```
{
    "images": ["debian:10.2", "ubuntu:18.10", "alpine:3.9.4", "centos:7_7_1908", "fedora:29"],
    "scanners": ["anchore", "clair", "microscanner", "trivy", "snyk"],
    "createXLSX": true,
    "output": "test",
    "parallel": true,
    "auths": {
    }
}
```

If connecting to a private registry you will need to fill the `auths` object similar to how the credentials are specified in Docker credentials [store](https://docs.docker.com/engine/reference/commandline/login/):

```
    "auths": {
        "https://index.docker.io/v1/": {
            "auth": "XXXXX",
            "email": "<your-email>"
        }
    }
```

where `auth` string is a base64-encoded username:password sequence.

2. If scanners need auth tokens, add them in `./Vagrant/config/<scanner>/token`. In our experience, at least two of the scanners (Snyk and Microscanner) require token. 

3. If needed make changes to `./Vagrant/config/anchore/docker-compose.yaml` and `./Vagrant/config/clair/config.json` to configure Anchore and Clair respectively. 

4. Run Vagrant file. Use the following command if running for the first time (provider is only needed if using provider other than Virtualbox):

```
vagrant up --provider x
```

Use the following command when running subsequent times:

```
vagrant reload --provision
```

This will ensure that provision script runs after VM reset. If one or more scanners fail on one or more images Superscan will try and continue with further scans. 

Finally, after the scanners have generated the output, Vagrantfile will run the python script that parses the scanner's output and generates `test.json` and `test.xlsx` spreadsheet. The json file will contain all the data in parsable json format, whereas the spreadsheet contains the same data in Excel format. If during the Superscan any scanner has failed for whatever reason the final output may be missing these results. To ensure results completeness check for failures in Vagrant ssh console or check for scanner output in `./Vagrant/results/<scanner>` directory.


#### Scorer

You do not need to run Vagrant to evaluate your scanner. RateScanner is a script that will accept your list of vulnerabilities and an image name and will output the scores like so:

```
python RateScanner.py
```

**Input.** 
Text files containing the list of vulnerabilities your scanner has reported. The expected location of these files is `./Vagrant/vulns/<scanner_name>/<image_name>.txt`. Where `<image_name>` is name of the image the above vulnerabilities were detected on. User can supply up to three files. The image can be one of the following: debian_10_2, ubuntu_18_10 or alpine_3_9_4.

**Output.**
Six numbers describing (1) vulnerability distribution across the applicability classes (TP / I / MM / D / FP) and (2) Precision, Recall and F-measure metrics of your scanner on the image as in the input. The metrics appear twice: first line shows metrics in Relaxed mode; second line shows the same metrics in Paranoid mode. See [paper](./paper/ubcis.pdf) for detailed description of statistical metrics and of the modes. Sample output:

```
$ python RateScanner.py
Rating scanner testscanner
Results for alpine_3_9_4

Relaxed 0.6 1.0 0.7499999999999999
Paranoid 0.6 1.0 0.7499999999999999

Results for debian_10_2

Relaxed 0.5212765957446809 0.9423076923076923 0.6712328767123288
Paranoid 0.8936170212765957 0.9545454545454546 0.9230769230769231

Results for ubuntu_18_10
No mark found for CVE-2017-18078 . It has been ignored
No mark found for CVE-2012-0871 . It has been ignored
No mark found for CVE-2018-16588 . It has been ignored
No mark found for CVE-2018-18751 . It has been ignored

Relaxed 0.35714285714285715 0.9259259259259259 0.5154639175257733
Paranoid 0.8571428571428571 0.967741935483871 0.909090909090909
```

### Troubleshooting

* When pulling the image if you see `Error response from daemon: Get <Your Registry URL>: x509: certificate signed by unknown authority` then you need to use one of the methods from [Docker documentation](https://docs.docker.com/registry/insecure/) to circumvent the insecure connection. Changes can be done through Vagrant console or by SSH-ing to the Vagrant VM and then rerunning `vagrant reload --provision` command.


### Limitations

Current UBCIS limitations include:
1. Benchmark only applies to OS-level vulnerabilities.
2. More images are coming including ubuntu:19.10, debian:10.3 and alpine:3.11.5

## Authors

* **Shay Berkovich** - *Lead* - [sshayb](https://github.com/sshayb)
* **Alexander Parent** - *Contributor* - [iam4722202468](https://github.com/iam4722202468)
* **Glenn Wurster** - *Contributor* - [gwurster](https://github.com/gwurster)
* **Jeffrey Kam** - *Contributor* - [lazypanda10117](https://github.com/lazypanda10117)

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
