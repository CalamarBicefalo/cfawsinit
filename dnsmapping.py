import boto3


def map_ert_domain(stackname, domain, lbname=None,
                   route53=None, elb=None, names=None):
    """
    maps *.domain, *.system.domain, *.apps.domain
    to stackname-pcf-elb load balancer
    """
    route53 = route53 or boto3.client('route53')
    elb = elb or boto3.client('elb')
    prefixes = ["", "*.", "*.system.", "*.apps."]
    names = names or [prefix + domain for prefix in prefixes]

    if not domain.endswith('.'):
        domain += '.'

    zone = next(
        (z for z in route53.list_hosted_zones()['HostedZones']
         if domain.endswith(z['Name'])), None)

    # based on standard naming
    lbname = lbname or stackname + "-pcf-elb"
    resp = elb.describe_load_balancers(
        LoadBalancerNames=[lbname])

    if len(resp.get('LoadBalancerDescriptions', [])) == 0:
        raise Exception(lbname + " Loadbalacer could not be found")

    dnsname = resp['LoadBalancerDescriptions'][0]['DNSName']

    if zone is None:
        print domain + " Is not managed in route53"
        print "Manually map {} <-- {}".format(dnsname, names)
        return

    changes = [
        {
            'Action': 'UPSERT',
            'ResourceRecordSet': {
                'Name': name,
                'Type': 'CNAME',
                'TTL': 300,
                'ResourceRecords': [
                    {
                        'Value': dnsname
                    },
                ],
            }
        } for name in names]

    route53.change_resource_record_sets(
        HostedZoneId=zone['Id'],
        ChangeBatch={
            'Comment': "for stack="+stackname,
            'Changes': changes
        })
