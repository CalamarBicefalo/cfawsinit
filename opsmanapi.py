from bs4 import BeautifulSoup
from robobrowser import RoboBrowser
from robobrowser import forms
import yaml
import urlparse
import requests
import requests.auth
import os
import time
from StringIO import StringIO
import copy
import sys
import stemplate
import tempfile
import wait_util
import paramiko

import pivnet

# Othwerise urllib3 warns about
# self signed certs
requests.packages.urllib3.disable_warnings()


THIS_DIR = os.path.dirname(os.path.abspath(__file__))


def get(*args, **kwargs):
    # bs4.find("span", {'class': 'version'})
    resp = requests.head(
        args[0]+"/uaa/login",
        verify=False,
        allow_redirects=False)
    # somewhat of a hack
    # pre api ops manager does not have /api/v0 endpoints
    if resp.status_code == 404:
        return OpsManApi(*args, **kwargs)
    else:
        return OpsManApi17(*args, **kwargs)


class OpsManApi(object):
    def __init__(self, url, username, password, private_key_file,
                 stack_vars, region, opts, vpc):
        self.url = url
        self.username = username
        self.password = password
        self.auth = requests.auth.HTTPBasicAuth(username, password)
        self.private_key = open(private_key_file, "rt").read()
        if not self.private_key.endswith('\r\n\r\n'):
            self.private_key += '\r\n'

        self.self_signed_key = open(
            THIS_DIR+"/Selfsigned/my-private-key.pem", "rt").read()
        self.self_signed_cert = open(
            THIS_DIR+"/Selfsigned/my-certificate.pem", "rt").read()

        if 'ssl_cert_file' in opts:
            self.ssl_cert = open(opts['ssl_cert_file'], "rt").read()
        else:
            self.ssl_cert = self.self_signed_cert

        if 'ssl_key_file' in opts:
            self.ssl_key = open(opts['ssl_key_file'], "rt").read()
        else:
            self.ssl_key = self.self_signed_key

        self.browser = RoboBrowser(history=True)
        self.var = stack_vars
        self.region = region
        if region == 'us-east-1':
            self.s3_endpoint = "https://s3.amazonaws.com"
        else:
            self.s3_endpoint = "https://s3-{}.amazonaws.com".format(region)
        self.action_map_file = THIS_DIR+'/opsman_mappings.yml'
        self.opts = opts
        self._login = False
        if 'PcfKeyPairName' not in self.var:
            self.var['PcfKeyPairName'] = self.opts['ssh_key_name']
        self._sshclient = None
        self.vpc = vpc

    def setup(self):
        setup_data = {'setup[eula_accepted]': 'true',
                      'setup[password]': self.password,
                      'setup[password_confirmation]': self.password,
                      'setup[user_name]': self.username}
        resp = requests.post(
            self.url + "/api/setup",
            data=setup_data,
            verify=False,
            allow_redirects=False)

        if resp.status_code == 200:
            print "Admin user established", resp.json()
        elif resp.status_code == 422:
            jx = resp.json()
            if 'errors' in jx:
                raise Exception("Could not establish user: {}".
                                format(jx['errors']))
            else:
                print "Admin user is previously established"
        return self

    def login(self):
        self.browser.open(self.url + "/login", verify=False)
        form = self.browser.get_form(action='/login')
        form['login[user_name]'].value = self.username
        form['login[password]'].value = self.password
        self.browser.submit_form(form)
        if self.browser.response.status_code >= 400:
            raise Exception("Error login in {}\n{}".
                            format(self.username, self.browser.response.text))
        return self

    def is_prepared(self, product='p-bosh'):
        # check if this is previously prepared
        resp = requests.get(
            self.url+"/api/installation_settings",
            verify=False,
            auth=self.auth)
        if resp.status_code == 200:
            cfg = stemplate.Cfg(resp.json())
            if cfg['products'][product].obj.get('prepared', False) is True:
                print product, "is previously prepared"
                return True

        return False

    def process_action(self, action, mappings):
        if self.is_prepared():
            return self

        self.browser.open(self.url + "/", verify=False)
        form = None
        suffix = mappings.get('__edit__', "/edit")
        self.browser.open(self.url + "/" + action + suffix, verify=False)
        form = self.browser.get_form(action='/' + action)

        """
        for suffix in ["/new", "/edit"]:
            self.browser.open(self.url + "/" + action + suffix, verify=False)
            raise Exception()
            form = self.browser.get_form(action='/' + action)
            if form is not None:
                break
        """
        if form is None:
            raise Exception("Could not find form for action="+action)

        # forms use ruby hash style params
        print form
        for k, v in mappings.items():
            if k.startswith("__"):
                continue
            if k not in form.keys() and "__force__" in mappings:
                field = forms.form._parse_fields(
                    BeautifulSoup('<input type="text" name="{}" />'.format(k))
                )[0]
                form.add_field(field)

            form[k].value = v
            print k, "=", v

        print form
        self.browser.submit_form(form)
        soup = BeautifulSoup(self.browser.response.text)
        # check if errors-block class is there in the output
        # ops manager sometime returns a 200 with and errors block
        # in html
        # HACK warning
        errblock = soup.select('.errors-block')

        if self.browser.response.status_code >= 400 or len(errblock) > 0:
            if '__IGNORE_ERROR__' not in mappings or \
                    mappings['__IGNORE_ERROR__'] not in errblock[0].text:
                raise Exception("Error submitting form " +
                                self.browser.response.text)

        return self

    def _load_mappings(self, filename):
        """
        load mappings and hydrate using self, stack_vars
        """
        # TODO use self.resolve_yml after updating opsman_mappings.yml
        # template spiff style
        mappings = yaml.load(open(filename, 'rt'))
        for mapping in mappings:
            mp = mapping.values()[0]
            for key, val in mp.items():
                if isinstance(val, (bool, int, long)):
                    continue
                if val.startswith("$."):
                    attrib = val[2:]
                    if hasattr(self, attrib):
                        mp[key] = getattr(self, attrib)
                    else:
                        raise Exception(val + " Is not provided"
                                        " as a mapping variable")
                elif val.startswith("$"):
                    attrib = val[1:]
                    if attrib in self.var:
                        mp[key] = self.var[attrib]
                    else:
                        raise Exception(val + " Is not provided"
                                        " as a stack output variable")
        return mappings

    def configure(self, filename=None, action=None):
        filename = filename or self.action_map_file

        mappings = self._load_mappings(filename)
        for mapping in mappings:
            ac, mp = mapping.items()[0]
            if action is None or action == ac:
                self.process_action(ac, mp)

        self.apply_changes()
        return self

    def apply_changes(self):
        print "Applying Changes"
        self.browser.open(self.url, verify=False)
        soup = BeautifulSoup(self.browser.response.text)
        fx = soup.find('meta', {"name": 'csrf-token'})
        csrf_token = fx.attrs["content"]

        rsp = self.browser.session.put(self.url+"/install",
                                       data={'authenticity_token': csrf_token})

        if rsp.status_code == 422 and \
                'Ignore errors and start the install' in rsp.text:
            # This happens because of the icmp error
            sp = BeautifulSoup(rsp.text)
            inst_form = sp.find("form", {"action": "/install"})
            if inst_form is None:
                raise Exception("Unable to complete installation")
            self.browser.submit_form(forms.form.Form(inst_form))

    boshprefix = (
        'BUNDLE_GEMFILE=/home/tempest-web/tempest/web/vendor/bosh/Gemfile '
        'bundle exec bosh ')

    def boshlogin(self, out=None):
        """
        ensure that bosh on opsmanager in logged in
        """
        boshcmd = (
            self.boshprefix +
            '-n '
            '--ca-cert /var/tempest/workspaces/default/root_ca_certificate '
            'target 10.0.16.10')
        self.execute_on_opsman(
            self.opts,
            boshcmd,
            out)

        handle, bosh_cfg_path = tempfile.mkstemp()
        self.copy_from_opsman(self.opts, ".bosh_config", bosh_cfg_path)
        bosh_cfg = yaml.load(open(bosh_cfg_path, 'rt'))

        if 'auth' in bosh_cfg:
            all_set = True
            for dep, dd in bosh_cfg['auth'].items():
                if 'access_token' not in dd:
                    all_set = False
            if all_set:
                print "Bosh prior login present"
                self._login = True
                return self

        # set deployment and auth fields
        if 'deployment' not in bosh_cfg:
            deployed_products = {
                p['type']: p
                for p in self.getJSON("/api/v0/deployed/products")}
            if 'cf' in deployed_products:
                boshcmd = (
                    self.boshprefix +
                    '-n deployment '
                    '/var/tempest/workspaces/'
                    'default/deployments/{}.yml').format(
                        deployed_products['cf']['installation_name'])

                self.execute_on_opsman(
                    self.opts,
                    boshcmd,
                    out)

        respjson = self.getJSON(
            "/api/v0/deployed/director/credentials/director_credentials")
        creds = respjson['credential']['value']

        _, cred_path = tempfile.mkstemp()
        with open(cred_path, "wt") as handle:
            handle.write(
                creds['identity'] +
                '\n' +
                creds['password'] +
                '\n')
            handle.close()

        self.copy_to_opsman(self.opts, cred_path, "creds.txt")
        boshcmd = (
            self.boshprefix +
            'login < creds.txt')

        try:
            self.execute_on_opsman(
                self.opts,
                boshcmd,
                out)
        except Exception as ex:
            if 'Non-interactive UAA login is not supported'\
                    not in str(ex.stderr):
                raise

        self._login = True
        return self

        """
        auth = bosh_cfg.get('auth', {})
        target_auth = getUAA_Auth_Header(
            self.url,
            creds['identity'],
            creds['password'],
            client_id='bosh_cli'
            )
        raise Exception()
        auth[bosh_cfg['target']] = target_auth
        bosh_cfg['auth'] = auth
        """
    def bosh(self, cmd, out=None, ignore_error=None):
        if not self._login:
            self.boshlogin()

        boshcmd = (
            self.boshprefix +
            cmd)
        try:
            return self.execute_on_opsman(
                self.opts,
                boshcmd,
                out)
        except Exception as ex:
            if ignore_error is not None and ignore_error\
                    not in str(ex):
                raise

    def execute_on_opsman(self, opts, cmd, out=None):
        stdin, stdout, stderr = self.sshclient.exec_command(cmd)
        sout = ""
        serr = ""
        while stdout.channel.exit_status_ready() is False:
            time.sleep(2)
            _sout = stdout.read()
            print _sout
            sout += _sout
            serr += stderr.read()

        if stdout.channel.exit_status != 0:
            raise Exception(cmd + " failed "+sout + serr)

        print serr
        return sout, serr

    @property
    def sshclient(self):
        if self._sshclient is None:
            host = urlparse.urlparse(self.url).netloc
            clnt = paramiko.SSHClient()
            clnt.set_missing_host_key_policy(paramiko.WarningPolicy())
            clnt.connect(
                host, username="ubuntu",
                key_filename=self.opts['ssh_private_key_path'])
            self._sshclient = clnt

        return self._sshclient

    def copy_to_opsman(self, opts, source, target=None):
        scp = self.sshclient.open_sftp()
        target = target or os.path.basename(source)
        scp.put(source, target)

    def copy_from_opsman(self, opts, source, target):
        scp = self.sshclient.open_sftp()
        scp.get(source, target)

    def create_ert_databases(self, opts):
        file_name = 'create_dbs.ddl'
        cmd = 'mysql < {file_name}'.format(file_name=file_name)
        MY_CNF = (
            '[client]\n'
            'host={PcfRdsAddress}\n'
            'user={PcfRdsUsername}\n'
            'password={PcfRdsPassword}\n\n'
        ).format(**self.var)

        _, my_cnf_path = tempfile.mkstemp()
        with open(my_cnf_path, "wt") as _fll:
            _fll.write(MY_CNF)

        self.copy_to_opsman(opts, my_cnf_path, ".my.cnf")
        self.copy_to_opsman(opts, THIS_DIR+"/"+file_name, file_name)
        self.execute_on_opsman(opts, cmd)


class AuthException(Exception):
    pass


class CFAuthHandler(requests.auth.AuthBase):
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.uaa = None

    def __call__(self, req):
        if self.uaa is None:
            url = req.url[:-len(req.path_url)]
            self.uaa = self._uaa(url)

        req.headers['Authorization'] = "Bearer "+self.uaa['access_token']
        return req

    def _uaa(self, url):
        resp = requests.post(
            url+"/uaa/oauth/token",
            verify=False,
            data={'grant_type': 'password',
                  'username': self.username,
                  'password': self.password},
            auth=('opsman', ''))

        if resp.status_code != 200:
            exp = AuthException("Unable to authenticate ")
            exp.resp = resp
            raise exp

        return resp.json()


def getUAA_Auth_Header(url, username, password, client_id="opsman"):
    # client_id = bosh_cli
    resp = requests.post(
        url+"/uaa/oauth/token",
        verify=False,
        data={'grant_type': 'password',
              'username': username,
              'password': password},
        auth=(client_id, ''))

    if resp.status_code != 200:
        raise Exception("Unable to authenticate "+resp.text)

    return resp.json()


class OpsManApi17(OpsManApi):

    def __init__(self, *args, **kwargs):
        super(OpsManApi17, self).__init__(*args, **kwargs)
        # self.action_map_file = THIS_DIR+'/opsman_mappings17.yml'
        self.action_map_file = THIS_DIR+'/installation-aws-1.7.yml'

    def setup(self, timeout=300):
        setup_data = {
            'setup[eula_accepted]': 'true',
            'setup[identity_provider]': 'internal',
            'setup[decryption_passphrase]': self.password,
            'setup[decryption_passphrase_confirmation]': self.password,
            'setup[admin_password]': self.password,
            'setup[admin_password_confirmation]': self.password,
            'setup[admin_user_name]': self.username}

        resp = requests.post(
            self.url + "/api/v0/setup",
            data=setup_data,
            verify=False,
            allow_redirects=False)

        if resp.status_code == 200:
            print "Admin user established"

            def should_wait():
                try:
                    self.login()
                    return False
                except Exception as ex:
                    if hasattr(ex, 'resp') and\
                            ex.resp.status_code >= 400:
                        return True

                    raise

            print "Waiting for ops manager login"
            waiter = wait_util.wait_while(should_wait)
            waiter(timeout)

        elif resp.status_code == 422:
            jx = resp.json()
            if 'errors' in jx:
                raise Exception("Could not establish user: {}".
                                format(jx['errors']))
            else:
                print "Admin user is previously established"
        return self

    def login(self):
        self.auth = CFAuthHandler(self.username, self.password)
        resp = self.get("/eula")
        if resp.status_code >= 400:
            exp = Exception("Error login in {}\n{}".
                            format(self.username, resp.text))
            exp.resp = resp
            raise exp
        return self

    def post(self, uri, **kwargs):
        return requests.post(
            self.url+uri,
            verify=False,
            auth=self.auth,
            **kwargs)

    def getJSON(self, uri, **kwargs):
        resp = self.get(uri, **kwargs)
        if resp.status_code < 400:
            return resp.json()
        else:
            raise Exception(resp.text)

    def postJSON(self, uri, **kwargs):
        resp = self.post(uri, **kwargs)
        if resp.status_code < 400:
            return resp.json()
        else:
            raise Exception(resp.text)

    def get(self, uri, **kwargs):
        return requests.get(
            self.url+uri,
            verify=False,
            auth=self.auth,
            **kwargs)

    def resolve_yml(self, filename=None):
        filename = filename or self.action_map_file
        yobj = yaml.load(open(filename, 'rt'))
        var = copy.copy(self.var)
        if 'PcfKeyPairName' not in var:
            var['PcfKeyPairName'] = self.opts['ssh_key_name']
        var.update({"Opts_"+k: v for k, v in self.opts.items()})
        var['v'] = self
        stemplate.resolve(
            yobj, var,
            replacefn=lambda x: x.replace('(( ', '{').replace(' ))', '}'))

        buf = StringIO()
        yaml.safe_dump(
            yobj, buf, indent=2, default_flow_style=False)
        yamlfile = buf.getvalue()
        return yamlfile, yobj

    def get_ip_insubnet(self, cidr, num=1):
        ipr, _, mask = cidr.partition('/')
        vs = map(int, ipr.split('.'))
        addr = 0
        for idx, val in enumerate(vs[::-1]):
            addr += val << (8*idx)
        v2 = []
        addr += num  # make into gateway
        while addr > 0:
            v2.append(str(addr % 256))
            addr = addr >> 8

        return '.'.join(v2[::-1])

    def update_subnet(self, yobj, subnet_id):
        subnet = list(self.vpc.subnets.filter(
            SubnetIds=[subnet_id]))[0]
        subnet_gw = self.get_ip_insubnet(subnet.cidr_block)
        res_hosts = int(
            self.opts.get(
                "reserved_hosts",
                "9"))
        subnet_reserved = "{}-{}".format(
            subnet_gw, self.get_ip_insubnet(subnet.cidr_block, res_hosts))

        dns = self.opts.get(
            'dns', self.get_ip_insubnet(self.vpc.cidr_block, 2))

        sb = stemplate.Cfg(
            yobj['infrastructure']['networks'][0], idfield='iaas_identifier')
        subnetobj = sb['subnets'][subnet.id].obj
        subnetobj['dns'] = dns
        subnetobj['cidr'] = subnet.cidr_block
        subnetobj['gateway'] = subnet_gw
        subnetobj['reserved_ip_ranges'] = subnet_reserved

    def update_boshnetworkinfo(self, yobj):
        self.update_subnet(yobj, self.var["PcfPrivateSubnetId"])
        self.update_subnet(yobj, self.var["PcfPrivateSubnet2Id"])

    def configure(self, filename=None, action=None, force=False):
        force = force or '_FORCE_PREPARE_' in os.environ
        if force or not self.is_prepared():
            _, yobj = self.resolve_yml(filename=filename)
            self.update_boshnetworkinfo(yobj)
            # update network configuration
            buf = StringIO()
            yaml.safe_dump(
                yobj, buf, indent=2, default_flow_style=False)
            yamlfile = buf.getvalue()

            files = {'installation[file]':
                     ('installation-integration-minimal.yml',
                         yamlfile, 'text/yaml')}
            resp = requests.post(
                self.url+"/api/installation_settings",
                files=files,
                verify=False,
                auth=self.auth)
            if resp.status_code != 200:
                raise Exception("Unable to configure "+resp.text)

        # check if its either deployed or staged
        if self.is_deployed('p-bosh'):
            return self

        if self.opts.get("_START_INSTALLS_", True) is False and\
                self.is_install_running() is False:
            raise Exception("Not Starting install per _START_INSTALLS_ flag\n"
                            "Verify that the configuration is correct and "
                            "manually start install")

        print "Starting Ops Manager Director install...",
        sys.stdout.flush()
        self.apply_changes(in_progress_ok=True)
        print "Done"
        return self

    # TODO enable errands, it is needed now
    def apply_changes(self, in_progress_ok=False, post_args=None):
        postdata = [('ignore_warnings', True)]
        if post_args is not None:
            postdata += post_args

        resp = requests.post(
            self.url+'/api/v0/installations',
            verify=False,
            data=postdata,
            auth=self.auth)
        if resp.status_code == 422:
            if 'install in progress' not in resp.text.lower():
                print resp.text
            if in_progress_ok is True:
                return
        if resp.status_code != 200:
            raise Exception(
                "Unable to start install, status: {}, error: {}".format(
                    resp.status_code, resp.text))

    def stage_elastic_runtime(self, opts, timeout, products):
        # TODO if we are running in ec2, don't have to do this
        # ssh magic
        if 'cf' not in products:
            # upload and make available for staging
            filename = self._download_ert_to_opsman(opts)
            self._add_ert_to_opsman(opts, filename)

            def should_wait():
                products.update({
                    p['name']: p
                    for p in self.getJSON("/api/v0/available_products")})
                return 'cf' not in products

            print "Waiting for elastic runtime to be available for staging"
            waiter = wait_util.wait_while(should_wait)
            waiter(timeout)

        self.postJSON("/api/v0/staged/products", data=products['cf'])

        staged_products = {
            p['type']: p
            for p in self.getJSON("/api/v0/staged/products")}
        print "Staged", products['cf']
        return staged_products

    def _download_ert_to_opsman(self, opts):
        """
        logon to opsman and download the
        ert file from pivnet

        it runs the command *from* ops manager
        so it can be locally uploaded
        """
        piv = pivnet.Pivnet(token=self.opts['PIVNET_TOKEN'])
        rel, _, _ = opts['elastic-runtime']['image-file-url'].partition(
            'product_files')

        resp = piv.post(rel+"eula_acceptance")
        if resp.status_code != 200:
            raise Exception(
                "Could not auto accept eula" +
                opts['elastic-runtime']['image-file-url'] +
                " " + str(resp.headers))

        filename = opts['elastic-runtime']['image-filename']
        ver = opts['elastic-runtime']['version']
        print "Downloading ({}) {} to ops manager...".format(ver, filename),
        sys.stdout.flush()
        CMD = ""
        if '_NO_CACHE_' not in os.environ:
            CMD += '[[ -e {filename} ]] || '
        CMD += (
            'wget -q -O {filename} --post-data="" '
            '--header="Authorization: Token {token}" {url}')

        cmd = CMD.format(
            filename=filename,
            token=opts['PIVNET_TOKEN'],
            url=opts['elastic-runtime']['image-file-url'])

        self.execute_on_opsman(opts, cmd)
        print "done"
        return filename

    def _add_ert_to_opsman(self, opts, ert_file):
        # TODO ensure that ops manager is ready to install ert
        CMD = (
            'curl -s -k https://localhost/api/v0/available_products '
            '-F \'product[file]=@{filename}\' '
            '-X POST '
            '-H "Authorization: {auth}"')

        cmd = CMD.format(
            filename=ert_file,
            auth="Bearer "+self.auth.uaa['access_token'])

        ver = opts['elastic-runtime']['version']
        print "Installing Elastic runtime ({}) {} ...".format(ver, ert_file),
        sys.stdout.flush()
        self.execute_on_opsman(opts, cmd)
        print "done"

    def is_staged(self, product):
        products = {
            p['type']: p
            for p in self.getJSON(
                "/api/v0/staged/products")}
        return product in products

    def is_deployed(self, product):
        products = {
            p['type']: p
            for p in self.getJSON(
                "/api/v0/deployed/products")}
        return product in products

    def wait_for_deployed(self, product, timeout=400):
        """
        wait until a product is deployed
        """
        def should_wait():
            return not self.is_deployed(product)

        if should_wait() is False:
            print product, "previously deployed"
            return

        print "Waiting for {} to deploy...".format(product),
        sys.stdout.flush()
        waitFor = wait_util.wait_while(should_wait)
        waitFor(timeout)
        print "done"

    def is_install_running(self):
        instno = self.find_lastest_install()

        if instno == -1:
            return False
        respjson = self.getJSON("/api/v0/installations/{}".format(instno))
        return respjson.get("status", "success") == "running"

    def find_lastest_install(self):
        instno = -1
        respjson = self.getJSON("/api/v0/installations")
        if len(respjson["installations"]) > 0:
            instno = max([inst["id"] for inst in respjson["installations"]])

        return instno

    def wait_while_install_running(self, timeout=400):
        """
        if there is an ongoing install, wait for
        it to finish
        """
        instno = self.find_lastest_install()

        if instno == -1:
            return

        def should_wait():
            respjson = self.getJSON("/api/v0/installations/{}".format(instno))
            return respjson.get("status", "success") == "running"

        print "Waiting while install {} is running...".format(instno),
        sys.stdout.flush()
        waitFor = wait_util.wait_while(should_wait)
        waitFor(timeout)
        print "done"
        print self.getJSON("/api/v0/installations/{}".format(instno))

    def install_elastic_runtime(self, opts, timeout=400):
        """
        idempotent just like everything else
        """
        # prereq is 'p-bosh' is fully deployed

        self.wait_for_deployed('p-bosh', timeout=timeout)

        # check if it is previously installed.
        deployed_products = {
            p['type']: p
            for p in self.getJSON("/api/v0/deployed/products")}
        products = {
            p['name']: p
            for p in self.getJSON("/api/v0/available_products")}

        if 'cf' in deployed_products:
            print "Elastic runtime is deployed", products['cf']
            return

        staged_products = {
            p['type']: p
            for p in self.getJSON("/api/v0/staged/products")}

        if 'cf' in staged_products:
            print "Elastic runtime ", products['cf']['product_version'],
            print "is previously staged"
        else:
            staged_products = self.stage_elastic_runtime(
                opts, timeout, products)
        return self

    def configure_elastic_runtime(self, opts, timeout=300, force=False):
        force = force or 'FORCE_PREPARE' in os.environ
        if not force and self.is_prepared('cf'):
            return self

        current = self.getJSON("/api/installation_settings")
        cfg_current = stemplate.Cfg(current)
        yaml.safe_dump(
            current,
            open('installation_settings_pre.yml', 'wt'),
            indent=2, default_flow_style=False)
        _, yobj = self.resolve_yml(filename=THIS_DIR+"/ert.yml")
        stemplate.cfgmerge(
            cfg_current,
            stemplate.Cfg(yobj))
        yaml.safe_dump(
            current,
            open('installation_settings_post.yml', 'wt'),
            indent=2, default_flow_style=False)
        buf = StringIO()
        yaml.safe_dump(
            current, buf, indent=2, default_flow_style=False)
        yamlfile = buf.getvalue()
        files = {'installation[file]':
                 ('installation-integration-minimal.yml',
                     yamlfile, 'text/yaml')}
        prod_guid = cfg_current['products']['cf'].obj['guid']
        # FIXME get this from the manifest
        # This can be done by unzip  cf-1.7.0-build.167.pivotal metadata/cf.yml
        # and reading from post_deploy_errands key in that yml
        enabled_errands =\
            ['smoke-tests', 'push-apps-manager', 'notifications',
             'notifications-ui', 'autoscaling', 'autoscaling-register-broker']
        post_args =\
            [("enabled_errands[{}][post_deploy_errands][]".
                format(prod_guid), err) for err in enabled_errands]
        self.postJSON(
            "/api/installation_settings",
            files=files)

        if self.opts.get("_START_INSTALLS_", True) is False and\
                self.is_install_running() is False:
            raise Exception("Not Starting install per _START_INSTALLS_ flag\n"
                            "Verify that the configuration is correct and "
                            "manually start install")

        self.apply_changes(post_args=post_args)
        return self
