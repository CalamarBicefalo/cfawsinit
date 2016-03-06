import requests
import json
import os
import urllib
from pkg_resources import parse_version
import sys
import time


class Pivnet(object):

    def __init__(self, token=None, url_base=None):
        self.url_base = url_base or 'https://network.pivotal.io/api/v2'
        self.token = token or os.getenv('PIVNET_TOKEN')
        self.auth_header = {"Authorization": "Token {}".format(self.token)}
        self._validate_()

    def _validate_(self):
        """ ensure that you can logon to pivnet """
        if self.token is None:
            raise Exception("PIVNET_TOKEN env var is not exported")
        ans = self.get("{}/authentication".format(self.url_base))
        if ans.status_code != 200:
            raise Exception(ans.text)

    def get(self, url, **kwargs):
        return requests.get(url, headers=self.auth_header, **kwargs)

    def post(self, url, **kwargs):
        return requests.post(url, headers=self.auth_header, **kwargs)

    def latest(self, product, include_unreleased=False, version=None):
        """ https://network.pivotal.io/api/v2/products/elastic-runtime/releases """
        ans = self.get(
            "{}/products/{}/releases".format(self.url_base, product))
        releases = {parse_version(r['version']): r for r in ans.json()['releases']}
        vers = releases.keys()
        if include_unreleased is False:
            vers = [v for v in vers if v.is_prerelease is False]

        if version is not None:
            vers = [v for v in vers if v.base_version.startswith(version)]
        maxver = max(vers)
        return releases[maxver]

    def productfiles(self, product, releaseNumber):
        return self.get("{}/products/{}/releases/{}/product_files".format(self.url_base, product, releaseNumber)).json()['product_files']


    def acceptEULA(self, verDict):
        # eula acceptance per spec
        print "Accepting EULA for the relase"
        resp = self.post(href(verDict, 'eula_acceptance'), allow_redirects=False)
        if resp.status_code != 200:
           raise Exception ("Could not auto accept eula" + href(verDict, 'eula_acceptance') + " " +str(resp.headers)) 

    """ 'https://network.pivotal.io/api/v2/products/elastic-runtime/releases/1530/product_files/2946/download'
    """
    def download(self, ver, filedict):
        filename = os.path.basename(filedict['aws_object_key'])
        resp = self.post(href(filedict, 'download'), allow_redirects=False)
        if resp.status_code == 451:
            self.acceptEULA(ver)
            resp = self.post(href(filedict, 'download'), allow_redirects=False)

        if resp.status_code != 302:
            raise Exception("Could not download " +
                    href(filedict, 'download') + " " 
                    +str(resp.headers))

        class _progress_hook(object):
            lpr = 10
            started = False
            tm = time.time()
            def __call__(self, nblocks, block_size, size):
                if self.started is False:
                    self.started = True
                    print " size: ", size
                if (100.0 * nblocks * block_size)/size > self.lpr:
                    tm_end = time.time() 
                    print >> sys.stderr, self.lpr," ({} kBps)".format(int((nblocks * block_size)/(1000.0*(tm_end-self.tm)))),
                    self.lpr += 10

        print "\nDownloading ", filename, 
        return urllib.urlretrieve(resp.headers['location'], filename, _progress_hook())

def href(obj, key):
    return obj['_links'][key]['href']


if __name__ == "__main__":

    piv = Pivnet()
    ver = piv.latest('elastic-runtime')
    print "Selected version", ver["version"]
    files = piv.productfiles('elastic-runtime', ver['id'])

    cloudformation = next((f for f in files if 'cloudformation script for aws' in f['name'].lower()), None)
    if cloudformation is None:
        raise Exception ("Could not find link for 'cloudformation script for aws' in "+ver+" "+files)

    er = next((f for f in files if 'PCF Elastic Runtime' == f['name']), None)
    if er is None:
        raise Exception ("Could not find link for 'PCF Elastic Runtime' in "+ver+" "+files)
    #dn = piv.download(ver, cloudformation)
    #dn1 = piv.download(ver, er)
