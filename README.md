# cfawsinit
Automate Creation of CloudFoundry deployment in AWS

Automates steps outlined in 
http://docs.pivotal.io/pivotalcf/customizing/cloudform.html

## Progress So far
Given a configuration file you can create a fully working ops manager
with Elastic Runtime tile staged.

## Features
1. Supports Ops Manager 1.6 and 1.7.
2. Uses network.pivotal.io / pivnet to resolve and fetch needed artifacts.
3. Idempotence
4. Creates Elastic Runtime
5. Registers correct dns entries for the domain 
6. Supports HA configuration in 1.7

## TODO
1. Autocreate self signed ssl cert and arn
2. Show first failure event when stack creation fails.

## Goals
1. Minimal input configuration file
2. Input file is resolved to a specific configuration file
3. Idempotence. The job can be killed and restarted anytime.

## Usage
```shell
mjog@ mac ~/cfawsinit$ ./awsdeploy.py  --help
usage: awsdeploy [prepare|deploy] [-h] --action {prepare,deploy} [--cfg CFG]
                                  [--prepared-cfg PREPARED_CFG]
                                  [--timeout TIMEOUT]

optional arguments:
  -h, --help            show this help message and exit
  --action {prepare,deploy}
  --cfg CFG
  --prepared-cfg PREPARED_CFG
  --timeout TIMEOUT
```
### Minimal input file  (awsdeploy.yml)
```yml
region: us-east-1
email: email@gmail.com
ssh_private_key_path: ~/.ssh/id_rsa
ssh_key_name: mjog
domain: "{ssh_key_name}{uid}.pcf-practice.com"
PIVNET_TOKEN: AAAA-h6BBBBBCotwXFi
ops-manager:
    version: latest
    beta-ok: true
elastic-runtime:
    version: latest
    beta-ok: true
ssl_cert_arn: arn:aws:iam::375783000519:server-certificate/mjogCertificate
```
```shell
mjog@ mac ~/cfawsinit $ ./awsdeploy.py --action prepare --cfg awsdeploy.yml --prepared-cfg awsout.yml
```
### This command produces the following fully resolved yaml file
The resolve (prepared) yaml file is used to deploy cloud foundry
```yml
PIVNET_TOKEN: h6TTTTTTT
__PREPARED__: true
date: 2016-05-11 15:56:34.506636
domain: mjog0f64e4.pcf-practice.com
elastic-runtime:
  beta-ok: false
  cloudformation-template: pcf_1_7_cloudformation.json
  cloudformation-template-url: https://network.pivotal.io/api/v2/products/elastic-runtime/releases/1730/product_files/4060/download
  cloudformation-template-version: 1.7.1
  image-build: 1.7.1-build.3
  image-file-url: https://network.pivotal.io/api/v2/products/elastic-runtime/releases/1730/product_files/4542/download
  image-filename: cf-1.7.1-build.3.pivotal
  version: 1.7.1
  template-params:
    20VPCCidr: 10.0.0.0/16
email: mjog@pivotal.io
ops-manager:
  ami-id: ami-9cf508fc
  ami-name: pivotal-ops-manager-v1.7.1.0
  beta-ok: false
  version: 1.7.1.0
opsman-password: keepitsimple
opsman-username: admin
rds-password: keepitsimple
rds-username: dbadmin
region: us-west-2
ssh_key_name: mjog
ssh_private_key_path: /Users/mjog/.ssh/piv-ec2-mjog.pem
ssl_cert_arn: arn:aws:iam::375783000519:server-certificate/mjogCertificate
stack-name: mjog-pcf-0f64e4
uid: 0f64e4
_START_INSTALLS_: false
```
### The prepared yaml file is used during deploy
Many operations take a long time. You may press Ctrl-C and restart the same command later

```shell
mjog@ mac ~/CFWORK/cfinit$ ./awsdeploy.py --action deploy --prepared-cfg ./awsout.yml
Creating stack mjog-pcf-431699 
It takes about 22 minutes to create the stack
^CTraceback (most recent call last):
KeyboardInterrupt

mjog@ mac ~/CFWORK/cfinit$ ./awsdeploy.py --action deploy --prepared-cfg ./awsout.yml
stack mjog-pcf-431699 is in state CREATE_IN_PROGRESS
^CTraceback (most recent call last):
KeyboardInterrupt
```
After about 20 mins ...
```shell
mjog@ mac ~/CFWORK/cfinit$ ./awsdeploy.py --action deploy --prepared-cfg ./awsout.yml
stack mjog-pcf-431699 is in state CREATE_COMPLETE
Waiting for instance to start i-2361c5b8 ...
Admin user established.
Configuring Ops Manager
Applying Changes...
Downloading (1.7.0.alpha4) cf-1.7.0-build.58.pivotal to ops manager... done
Installing Elastic runtime (1.7.0.alpha4) cf-1.7.0-build.58.pivotal ... done
Staged {u'product_version': u'1.7.0-build.58', u'name': u'cf'}
Ops manager is now available at  https://ec2-51-9-24-33.compute-1.amazonaws.com
```

After a loooong time, Success!!

As always, if it times out waiting for a certain operation, restart it.
Alternatively use --timeout parameter to give a very large timeout
