#!/usr/bin/env python

from boto3.session import Session
import botocore.exceptions
import uuid
import yaml
from datetime import datetime
import os
import requests
import requests.exceptions
import pivnet
import opsmanapi
import wait_util
import sys
import json
import dnsmapping


# Othwerise urllib3 warns about
# self signed certs
requests.packages.urllib3.disable_warnings()

THIS_DIR = os.path.dirname(os.path.abspath(__file__))


def get_stack_outputvars(stack, ec2):
    ops = {v['OutputKey']: v['OutputValue'] for v in stack.outputs}
    # group name is needed in a few places
    ops['PcfVmsSecurityGroupName'] = list(
        ec2.security_groups.filter(
            GroupIds=[ops['PcfVmsSecurityGroupId']]))[0].group_name

    if 'PcfVpc' in ops:
        vpc = ec2.Vpc(ops['PcfVpc'])
        ops['PcfPrivateSubnetAvailabilityZone'] = list(vpc.subnets.filter(
            SubnetIds=[ops['PcfPrivateSubnetId']]))[0].availability_zone
    return ops


def get_stack(stackName, cff):
    try:
        stt = list(cff.stacks.filter(StackName=stackName))
        return stt[0]
    except botocore.exceptions.ClientError as e:
        if "{} does not exist".format(stackName) in\
                e.response['Error']['Message']:
            return None
        else:
            raise


def create_stack(opts, ec2, cff, timeout=300):
    """
    ensure idempotency

    returns a stack that is either in
    'CREATE_COMPLETE' or 'CREATE_IN_PROGRESS'
    """
    st = get_stack(opts['stack-name'], cff)

    if st is not None:
        msg = "stack {} is in state {}".format(st.name, st.stack_status)
        if st.stack_status in ('CREATE_IN_PROGRESS', 'CREATE_COMPLETE'):
            print msg
            return st
        else:
            raise Exception(msg)

    templateBody = open(
        opts['elastic-runtime']['cloudformation-template'], 'rt').read()
    templ = json.loads(templateBody)
    # stack does not exist create it
    args = {"01NATKeyPair": opts['ssh_key_name'],
            "05RdsUsername": opts['rds-username'],
            "06RdsPassword": opts['rds-password'],
            "07SSLCertificateARN": opts['ssl_cert_arn']}
    if 'opsman-template-url' in opts:
        args['08OpsManagerTemplate'] = opts['opsman-template-url']
    if 'template-params' in opts['elastic-runtime']:
        args.update(opts['elastic-runtime']['template-params'])

    # filter out args that are not needed
    args = {k: v for k, v in args.items() if k in templ["Parameters"]}
    paramaters = [{"ParameterKey": k, "ParameterValue": v,
                   "UsePreviousValue": True} for k, v in args.items()]
    tags = [{"Key": "email", "Value": opts["email"]}]
    st = cff.create_stack(
        StackName=opts['stack-name'],
        TemplateBody=templateBody,
        Tags=tags,
        Parameters=paramaters,
        Capabilities=['CAPABILITY_IAM'])

    print "Creating stack", opts['stack-name'],
    print ". Takes about 22 minutes to create the stack"
    return st


def launch_ops_manager(opts, stack_vars, ec2):
    """
    given a stack in CREATE_COMPLETE launch an ops manager
    """
    insts = list(ec2.instances.filter(
        Filters=[{'Name': 'tag:Name', 'Values': ['Ops Manager']},
                 {'Name': 'tag:stack-name', 'Values': [opts['stack-name']]},
                 {'Name': 'instance-state-name', 'Values': ['running']}]))
    if len(insts) == 1:
        print insts
        print "Found running ops manager {} {}".format(
            insts[0].id, get_addr(insts[0]))
        return insts[0]
    elif len(insts) > 1:
        raise Exception("Several Ops Managers running {} for stack {}".format(
            insts, opts['stack-name']))

    # no instance is running, create one
    inst = ec2.create_instances(
        ImageId=opts['ops-manager']['ami-id'],
        MinCount=1,
        MaxCount=1,
        KeyName=stack_vars.get('PcfKeyPairName', opts['ssh_key_name']),
        InstanceType='m3.large',
        NetworkInterfaces=[
            {'DeviceIndex': 0,
             'SubnetId': stack_vars['PcfPublicSubnetId'],
             'Groups': [stack_vars['PcfOpsManagerSecurityGroupId']],
             'AssociatePublicIpAddress': True}],
        BlockDeviceMappings=[
            {"DeviceName": "/dev/sda1",
             "Ebs": {"VolumeSize": 100,
                     "VolumeType": "gp2"
                     }
             }]
        )[0]
    inst.wait_until_exists()
    inst.create_tags(
        Tags=[{'Key': 'Name', 'Value': 'Ops Manager'},
              {'Key': 'stack-name', 'Value': opts['stack-name']}])
    print "Waiting for Ops Manager to start", inst.id, "...",
    sys.stdout.flush()
    inst.wait_until_running()
    inst.reload()
    print get_addr(inst)
    return inst


def configure_ops_manager(opts, stack_vars, inst, vpc):
    ops = opsmanapi.get(
        "https://"+get_addr(inst),
        opts['opsman-username'],
        opts['opsman-password'],
        os.path.expanduser(opts['ssh_private_key_path']),
        stack_vars,
        opts['region'],
        opts=opts,
        vpc=vpc)

    ops.setup()
    ops.login()
    ops.configure()
    return ops


def wait_for_stack_ready(st, timeout):
    waitFor = wait_util.wait_while(
        lambda: st.stack_status == 'CREATE_IN_PROGRESS',
        lambda: st.reload())
    waitFor(timeout)

    if st.stack_status == 'CREATE_COMPLETE':
        return True

    raise Exception("Stack {} is in bad state {}".format(
        st.name, st.stack_status))


def get_addr(inst):
    addr = inst.public_dns_name
    addr = addr or inst.public_ip_address
    return addr


def wait_for_opsman_ready(inst, timeout):
    addr = get_addr(inst)

    def should_wait():
        try:
            resp = requests.head(
                "https://{}/".format(addr),
                verify=False, timeout=1)
            return resp.status_code >= 400
        except requests.exceptions.RequestException as ex:
            pass
        except requests.HTTPError as ex:
            print ex
        return True

    waitFor = wait_util.wait_while(should_wait)
    waitFor(timeout)


#
# Main deploy driver function
#
def deploy(prepared_file, timeout=300):
    """
    Topline driver
    idempotent
    """
    opts = yaml.load(open(prepared_file, 'rt'))

    if '__PREPARED__' not in opts:
        raise Exception("using 'unprepared' file to deploy."
                        " First run prepare on it")

    session = Session(profile_name=opts.get('profile_name'),
                      region_name=opts['region'])
    ec2 = session.resource("ec2")
    cff = session.resource("cloudformation")
    route53 = session.client("route53")
    elb = session.client("elb")

    stack = create_stack(opts, ec2, cff)
    # ensure that stack is ready
    wait_for_stack_ready(stack, timeout)
    # 'arn:aws:cloudformation:us-east-1:375783000519:stack/mjog-pcf-42f062-OpsManStack-13R2QRZJCIPTB/ec4e3010-ef99-11e5-9206-500c28604c82'
    # opsman_stack_arn = next(
    #     ll for ll in stack.resource_summaries.iterator()
    #     if ll.logical_id == 'OpsManStack').physical_resource_id
    # opsman_stack = get_stack(opsman_stack_arn.split('/')[1], cff)
    stack_vars = get_stack_outputvars(stack, ec2)
    # stack_vars.update(get_stack_outputvars(stack, ec2))
    ops_manager_inst = launch_ops_manager(opts, stack_vars, ec2)
    # ensure that ops manager is ready to receive requests
    wait_for_opsman_ready(ops_manager_inst, timeout)
    names = []
    if 'apps_domain' not in opts:
        opts['apps_domain'] = "apps." + opts["domain"]
    else:
        names.append("*."+opts['apps_domain'])
    if 'system_domain' not in opts:
        opts['system_domain'] = "system." + opts["domain"]
    else:
        names.append("*."+opts['system_domain'])

    try:
        dnsmapping.map_ert_domain(
            stackname=opts['stack-name'],
            domain=opts['domain'],
            route53=route53,
            elb=elb,
            names=names)
    except Exception as ex:
        print ex
        print "Unable to create dns mappings, create manually"
    vpc = ec2.Vpc(stack_vars['PcfVpc'])
    ops = configure_ops_manager(opts, stack_vars, ops_manager_inst, vpc)
    ops.create_ert_databases(opts)
    print "Ops manager is now available at ", ops.url

    if not hasattr(ops, 'install_elastic_runtime'):
        print ops, "Does not support deploying elastic runtime on < 1.7"
        return 0

    ops.wait_for_deployed('p-bosh', timeout=timeout)
    ops.bosh("status")
    ops.configure_ipsec()
    ops.install_elastic_runtime(opts, timeout)
    ops.configure_elastic_runtime(opts, timeout)
    ops.bosh("vms", ignore_error='No deployments')
    ops.wait_for_deployed('cf', timeout=timeout)
    ops.wait_while_install_running(timeout=timeout)


AMI_PREFIX = "pivotal-ops-manager-v"
PCF_AWS_OWNERID = '364390758643'


def resolve_versions(token, opsman, ert, ec2):
    """
    resolve and return 2 new dicts which will replace the old
    """
    piv = pivnet.Pivnet(token=token)
    opsman_vers = piv._latest(
        'ops-manager',
        opsman['beta-ok'],
        opsman['version'])

    amidict = {
        e.name[len(AMI_PREFIX):]: e for e in
        ec2.images.filter(
            Owners=[PCF_AWS_OWNERID])
        if e.name.startswith(AMI_PREFIX)}

    ami = next(
        amidict[vv['version']] for vv in opsman_vers
        if vv['version'] in amidict)

    opsman_out = {'version': opsman_vers[0]['version'],
                  'beta-ok': opsman['beta-ok'],
                  'ami-id': ami.image_id,
                  'ami-name': ami.name}
    elastic_runtime_ver = piv.latest('elastic-runtime',
                                     ert['beta-ok'],
                                     ert['version'])
    ert_out = {'version': elastic_runtime_ver['version'],
               'beta-ok': ert['beta-ok']}

    files = piv.productfiles('elastic-runtime', elastic_runtime_ver['id'])
    cloudformation = next((f for f in files
                          if f['aws_object_key'].endswith(
                              "cloudformation.json")),
                          None)
    if cloudformation is None:
        cloudformation = next((f for f in files
                              if 'CloudFormation' in f['name']),
                              None)
    if cloudformation is not None:
        filename, dn = piv.download(
            elastic_runtime_ver, cloudformation, quiet=True)
        ert_out['cloudformation-template-version'] = \
            elastic_runtime_ver['version']
    else:
        print "Could not find cloudformation template for ver = {}".format(
            elastic_runtime_ver['version'])
        print "Trying latest available"
        vv = piv.latest_file(
            'elastic-runtime',
            ert['beta-ok'],
            ert['version'],
            selector=lambda x:
            x['aws_object_key'].endswith('cloudformation.json'))
        if vv is not None:
            vr, cloudformation = vv
            filename, dn = piv.download(vr, cloudformation, quiet=True)
            ert_out['cloudformation-template-version'] = vr['version']
            print "Found cloudformation template for ver = {}".format(
                vr['version'])
        else:
            raise Exception(
                ("Could not find link for "
                 "'cloudformation template for aws' in {} {}".format(
                     elastic_runtime_ver, files)))

    ert_out['cloudformation-template'] = filename
    ert_out['cloudformation-template-url'] = \
        pivnet.href(cloudformation, 'download')
    er = next((f for f in files if 'PCF Elastic Runtime' == f['name']), None)
    if er is None:
        raise Exception(
            "Could not find link for 'PCF Elastic Runtime' in "
            + str(elastic_runtime_ver) + " "+files)
    ert_out['image-file-url'] = \
        pivnet.href(er, 'download')
    fname = os.path.basename(er['aws_object_key'])

    ert_out['image-filename'] = fname
    # extract build
    # cf-1.7.0-build.58.pivotal ==> 1.7.0-build.58
    ert_out['image-build'] = \
        fname.partition('-')[2].rpartition('.')[0]

    return opsman_out, ert_out


def prepare_deploy(infilename, outfilename):
    """
    given infile.yml
    fully resolve it and produce outfile.yml
    """
    infile = yaml.load(open(infilename, 'rt'))
    if 'uid' not in infile:
        infile['uid'] = str(uuid.uuid4())[:6]
    stack_name = infile['email'].partition('@')[0] + "-pcf-" + infile['uid']
    date = datetime.utcnow()

    outfile = {k: v.format(**infile)
               if hasattr(v, 'format')
               else v for k, v in infile.items()}
    outfile['stack-name'] = stack_name
    outfile['date'] = date

    ec2 = Session(profile_name=None,
                  region_name=outfile['region']).resource("ec2")

    opsman_ver, elastic_runtime_ver =\
        resolve_versions(infile['PIVNET_TOKEN'],
                         infile['ops-manager'],
                         infile['elastic-runtime'],
                         ec2)

    outfile['ops-manager'] = opsman_ver
    outfile['elastic-runtime'] = elastic_runtime_ver

    verify_ssh_key(ec2, outfile['ssh_private_key_path'],
                   outfile['ssh_key_name'])

    outfile['__PREPARED__'] = True

    def set_if_empty(key, val):
        if key not in outfile:
            outfile[key] = val

    # default params
    set_if_empty('rds-username', 'dbadmin')
    set_if_empty('rds-password', 'keepitsimple')
    set_if_empty('opsman-username', 'admin')
    set_if_empty('opsman-password', 'keepitsimple')
    set_if_empty('_START_INSTALLS_', True)

    set_if_empty('apps_domain', "apps." + outfile["domain"])
    set_if_empty('system_domain', "system." + outfile["domain"])
    set_if_empty('skip_cert_verify', False)

    yamlout = open(outfilename, 'wt')\
        if outfilename is not None \
        else sys.stdout

    yaml.safe_dump(outfile, yamlout,
                   indent=2, default_flow_style=False)
    return outfile


def verify_ssh_key(ec2, key_file, ec2_keypair_name):
    """
    ensure that the keypair matches
    """
    ec2.KeyPair(ec2_keypair_name)
    # TODO verify this fingerprint with the key on disk
    open(os.path.expanduser(key_file), 'rt').read()


def get_args():
    import argparse
    argp = argparse.ArgumentParser("awsdeploy [prepare|deploy]")
    argp.add_argument('--action', choices=["prepare", "deploy"], required=True)
    argp.add_argument('--cfg')
    argp.add_argument('--prepared-cfg')
    argp.add_argument('--timeout', type=int, default=360)
    return argp


def validate_creds(opts):
    session = Session(profile_name=opts.get('profile_name'),
                      region_name=opts['region'])
    ec2 = session.resource("ec2")
    try:
        ec2.meta.client.describe_id_format()
    except botocore.exceptions.NoCredentialsError as ex:
        print "Missing ~/.aws/credentials ? missing profile_name from cfg file"
        print "http://boto3.readthedocs.org/en/latest/guide/configuration.html"
        print ex
        return False

    try:
        pivnet.Pivnet(token=opts['PIVNET_TOKEN'])
    except pivnet.AuthException as ex:
        print "Get API TOKEN from "
        print "https://network.pivotal.io/users/dashboard/edit-profile"
        print ex
        return False

    return True


def main(argv):
    args = get_args().parse_args(argv)

    cfg = args.cfg or args.prepared_cfg
    if cfg is None:
        print "One of --cfg or --prepared-cfg is required"
        return -1
    opts = yaml.load(open(cfg, 'rt'))

    if validate_creds(opts) is False:
        return -1

    if args.action == 'prepare':
        prepare_deploy(args.cfg, args.prepared_cfg)
    elif args.action == 'deploy':
        deploy(args.prepared_cfg, timeout=args.timeout)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
