from bs4 import BeautifulSoup
from robobrowser import RoboBrowser
from robobrowser import forms
import yaml
import urlparse
import requests
import requests.auth
import os
from StringIO import StringIO
import copy
import sys
import stemplate
import wait_util


# Othwerise urllib3 warns about
# self signed certs
requests.packages.urllib3.disable_warnings()


THIS_DIR = os.path.dirname(os.path.abspath(__file__))


def get(*args, **kwargs):
    # bs4.find("span", {'class': 'version'})
    resp = requests. head(
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
                 stack_vars, region, opts):
        self.url = url
        self.username = username
        self.password = password
        self.auth = requests.auth.HTTPBasicAuth(username, password)
        self.private_key = open(private_key_file, "rt").read()
        self.self_signed_key = open(
            THIS_DIR+"/Selfsigned/my-private-key.pem", "rt").read()
        self.self_signed_cert = open(
            THIS_DIR+"/Selfsigned/my-certificate.pem", "rt").read()
        self.browser = RoboBrowser(history=True)
        self.var = stack_vars
        self.region = region
        if region == 'us-east-1':
            self.s3_endpoint = "https://s3.amazonaws.com"
        else:
            self.s3_endpoint = "https://s3-{}.amazonaws.com".format(region)
        self.action_map_file = THIS_DIR+'/opsman_mappings.yml'
        self.opts = opts

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

    def execute_on_opsman(self, opts, cmd):
        host = urlparse.urlparse(self.url).netloc
        from sh import ssh
        try:
            ssh("-oStrictHostKeyChecking=no",
                "-i {} ".format(opts['ssh_private_key_path']),
                "ubuntu@"+host,
                cmd)
        except Exception as ex:
            print "Error running", cmd
            print ex.stdout
            print ex.stderr
            raise

    def copy_to_opsman(self, opts, source, target=""):
        host = urlparse.urlparse(self.url).netloc
        from sh import scp
        try:
            scp("-oStrictHostKeyChecking=no",
                "-i {} ".format(opts['ssh_private_key_path']),
                source,
                "ubuntu@"+host+":"+target)
        except Exception as ex:
            print "Error copying", source, target
            print ex.stdout
            print ex.stderr
            raise

    def create_ert_databases(self, opts):
        file_name = 'create_dbs.ddl'
        self.copy_to_opsman(opts, THIS_DIR+"/"+file_name, file_name)
        CMD = (
            'mysql --host={PcfRdsAddress} '
            '--user={PcfRdsUsername} '
            '--password={PcfRdsPassword} '
            '< {file_name}')
        cmd = CMD.format(
            file_name=file_name,
            **self.var)

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


def getUAA_Auth_Header(username, password, url):
    resp = requests.post(
        url+"/uaa/oauth/token",
        verify=False,
        data={'grant_type': 'password',
              'username': username,
              'password': password},
        auth=('opsman', ''))

    if resp.status_code != 200:
        raise Exception("Unable to authenticate "+resp.text)

    return "Bearer "+resp.json()['access_token']


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
        resp = self.get("/api/v0/api_version")
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

    def configure(self, filename=None, action=None, force=False):
        if not force and self.is_prepared():
            return self
        yamlfile, _ = self.resolve_yml(filename=filename)
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

        print "Configuring Ops Manager...",
        sys.stdout.flush()
        self.apply_changes()
        print "Done"
        return self

    def apply_changes(self):
        resp = requests.post(
            self.url+'/api/v0/installation',
            verify=False,
            data={'ignore_warnings': True},
            auth=self.auth)
        if resp.status_code != 200:
            raise Exception("Unable to start install, "+resp.text)

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
                    for p in self.getJSON("/api/v0/products")})
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
        filename = opts['elastic-runtime']['image-filename']
        ver = opts['elastic-runtime']['version']
        print "Downloading ({}) {} to ops manager...".format(ver, filename),
        sys.stdout.flush()
        CMD = ""
        if '_NO_CACHE_' not in os.environ:
            CMD += '[[ -e {filename} ]] || '
        CMD += (
            'wget -O {filename} --post-data="" '
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
            'curl -v -k https://localhost/api/v0/products '
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

    def find_lastest_install(self):
        # if ops manager had better api to simply get
        # the currently active install
        # we would not need this
        instno = 1
        resp = self.get("/api/v0/installation/{}".format(instno))
        while resp.status_code == 200:
            instno += 1
            resp = self.get("/api/v0/installation/{}".format(instno))

        return instno-1

    def wait_while_install_running(self, timeout=400):
        """
        if there is an ongoing install, wait for
        it to finish
        """
        instno = self.find_lastest_install()

        def should_wait():
            respjson = self.getJSON("/api/v0/installation/{}".format(instno))
            return respjson.get("status", "success") == "running"

        print "Waiting while install {} is running...".format(instno),
        sys.stdout.flush()
        waitFor = wait_util.wait_while(should_wait)
        waitFor(timeout)
        print "done"
        print self.getJSON("/api/v0/installation/{}".format(instno))

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
            for p in self.getJSON("/api/v0/products")}

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

    def configure_elastic_runtime(self, opts, timeout=300):
        if self.is_prepared('cf'):
            return self

        current = self.getJSON("/api/installation_settings")
        yaml.safe_dump(
            current,
            open('installation_settings_pre.yml', 'wt'),
            indent=2, default_flow_style=False)
        _, yobj = self.resolve_yml(filename=THIS_DIR+"/ert.yml")
        stemplate.cfgmerge(
            stemplate.Cfg(current),
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

        self.postJSON(
            "/api/installation_settings",
            files=files)
        self.apply_changes()
        return self
