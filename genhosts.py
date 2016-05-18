#!/usr/bin/env python
import socket
import sys
import yaml
from boto3.session import Session


def genhosts(elbip, sysdomain, outfile=sys.stdout):
    SYS_PREFIXES = [
        'console',
        'uaa',
        'apps',
        'login',
        'api',
        'loggregator',
        'doppler']

    print >>outfile, elbip, sysdomain
    for prefix in SYS_PREFIXES:
        print >>outfile, elbip, prefix+"."+sysdomain


def get_elbip(elb, stackname, lbsuffix="-pcf-elb"):
    lbname = stackname + lbsuffix
    resp = elb.describe_load_balancers(
        LoadBalancerNames=[lbname])
    if len(resp.get('LoadBalancerDescriptions', [])) == 0:
        raise Exception(lbname + " Loadbalacer could not be found")
    dnsname = resp['LoadBalancerDescriptions'][0]['DNSName']
    return socket.gethostbyname(dnsname)


def get_args():
    import argparse
    argp = argparse.ArgumentParser()
    argp.add_argument('--profile')
    argp.add_argument('--stack-name')
    argp.add_argument('--outfile')
    argp.add_argument('--prepared-cfg')
    argp.add_argument('--system-domain')
    argp.add_argument('--region', default='us-east-1')
    return argp


def fix_args(args):
    if args.prepared_cfg is not None:
        opts = yaml.load(open(args.prepared_cfg, 'rt'))
        args.system_domain = args.system_domain or opts["system_domain"]
        args.stack_name = args.stack_name or opts["stack-name"]
        args.region = opts["region"]

    if args.outfile is not None:
        args.outfile = open(args.outfile, "wt")


def genallhosts(elb, args):
    print >>args.outfile, "#"*16,
    print >>args.outfile, "Generated for /etc/hosts by cfawsinit", "#"*16
    genhosts(
        get_elbip(elb, args.stack_name),
        args.system_domain,
        args.outfile)
    print >>args.outfile, get_elbip(elb, args.stack_name, "-pcf-ssh-elb"),
    print >>args.outfile, "ssh."+args.system_domain
    print >>args.outfile, "#"*16,
    print >>args.outfile, "Generated for /etc/hosts by cfawsinit", "#"*16


def main(argv):
    args = get_args().parse_args(argv)

    if args.prepared_cfg is None and\
            args.system_domain is None:
                print ("Either --prepared-cfg or "
                       "(--system-domain and --stack-name) are required")
                return -1
    fix_args(args)
    session = Session(profile_name=args.profile, region_name=args.region)
    elb = session.client("elb")
    genallhosts(elb, args)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))
