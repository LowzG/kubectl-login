#!/usr/bin/env python3

import os
import sys
import yaml
import webbrowser
import logging
import argparse
import base64
from threading import Timer
from flask import Flask, request, redirect, session
from requests_oauthlib import OAuth2Session
from getpass import getpass
from hvac import Client as vault

redirect_uri = 'http://localhost:5000/oidc_callback'
issuer_url = 'https://openid-connect.onelogin.com/oidc'
auth_url = f'{issuer_url}/auth'
token_url = f'{issuer_url}/token'
userinfo_url = f'{issuer_url}/me'
scopes = ['openid', 'profile', 'groups']

os.environ['FLASK_ENV'] = 'development'
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

log = logging.getLogger('werkzeug')
log.setLevel(logging.FATAL)

app = Flask(__name__)
secret_key = os.urandom(12)
app.config['SECRET_KEY'] = secret_key
app.config['TESTING'] = False


def get_args(supported_contexts):
    """Return the command line arguments."""
    parser = argparse.ArgumentParser(description="kubectl-login is a kubectl "
                                     "plugin used to provide kubeconfig "
                                     "authentication configurations for access"
                                     " to Kubernetes clusters.")
    parser.add_argument('--new-config', action="store_true",
                        default=False, help="Build a new kubeconfig")
    parser.add_argument('--context', '-c', metavar='ContextName',
                        choices=supported_contexts,
                        help="Switch to a different context")
    args = parser.parse_args()

    return(args)


def get_config():
    """Load configuration file."""
    repo_url = 'https://github.com/LowzG/kubectl-login'
    configfile_path = os.path.expanduser('~/.kubectl-login/config.yaml')
    if not os.path.exists(configfile_path):
        print(f"Config file not found. Please write config file at {configfile_path}")
        print(f"For more information visit {repo_url}")
        sys.exit()
    with open(os.path.expanduser(configfile_path)) as configfile:
        config = yaml.load(configfile, Loader=yaml.FullLoader)

    return config


def retreive_oidc_secrets(current_context, config):
    """Retreive OIDC ClientID and Client Secret from Vault."""
    secrets = {}
    vault_server = config['contexts'][current_context]['vault_server']
    vault_ca_path = config['vault_servers'][vault_server]['vault_ca_path']
    secrets_path = config['vault_servers'][vault_server]['secrets_path']
    secret_names = config['vault_servers'][vault_server]['secrets']
    vault_address = config['vault_servers'][vault_server]['address']
    os.environ['VAULT_ADDR'] = vault_address

    vault_test = os.system(f"curl -k {vault_address}/v1/sys/init "
                           ">/dev/null 2>&1")
    if vault_test != 0:
        print(f"Vault server at {vault_address} is unreachable.")
        sys.exit()

    token_path = os.path.expanduser(f'~/.kubectl-login/.vault-token_{vault_server}')
    if os.path.exists(token_path):
        with open(token_path) as token_file:
            token = token_file.read().rstrip('\n')
    else:
        token = ''

    client = vault(verify=vault_ca_path, token=token)

    if not client.is_authenticated():
        print("Authentication to Vault is required")
        client.auth.ldap.login(username=input('Username: '),
                               password=getpass("Password (will be hidden): "))
        with open(os.path.expanduser(token_path), 'w') as token_file:
            token_file.write(client.token)

    for secret in secret_names:
        secret_dict = client.read(f'{secrets_path}/{current_context}/{secret_names[secret]}')
        try:
            secrets[secret] = secret_dict['data']['value']
        except TypeError:
            print(f"ERROR: The {secret} secret was not found in Vault. "
                  f"Please make sure this secret exists in {secrets_path}/{current_context}"
                  f" and that you have the proper permissions to read its value.")
            sys.exit()

    b = secrets['cluster_ca'].encode('utf-8')
    cluster_ca_base64 = base64.b64encode(b)
    cluster_ca = cluster_ca_base64.decode('utf-8')
    secrets['cluster_ca'] = cluster_ca

    return secrets


def new_context(context_name, cluster_ca, config, username):
    """Build a new context and return cluster and context dictionaries."""
    cluster_address = config['contexts'][context_name]['cluster_address']
    cluster_dict = {'cluster': {'api-version': 'v1',
                    'certificate-authority-data': cluster_ca, 'server':
                    cluster_address}, 'name': context_name}
    context_dict = {'context': {'cluster': context_name, 'user': username},
                    'name': context_name}

    return {'context': context_dict, 'context_cluster': cluster_dict}


def new_kubeconfig(contexts, config, username):
    """Build a new kubeconfig and return it as a dictionary."""
    newconfig_dict = {'apiVersion': 'v1',
                      'clusters': [], 'contexts': [],
                      'current-context': 'LDE', 'kind': 'Config',
                      'users': [{'name': username, 'user': {'token': 'token'}}]}

    for context in contexts:
        secrets = retreive_oidc_secrets(context, config)
        cluster_ca = secrets['cluster_ca']
        context_dict = new_context(context, cluster_ca, config, username)
        newconfig_dict['clusters'].append(context_dict['context_cluster'])
        newconfig_dict['contexts'].append(context_dict['context'])

    return newconfig_dict


def get_kubeconfig():
    """Return dictionary containing kubeconfig information."""
    if 'KUBECONFIG' not in os.environ:
        kubeconfig_file = os.path.expanduser('~/.kube/config')
        os.environ['KUBECONFIG'] = kubeconfig_file
        if not os.path.exists(kubeconfig_file):
            new_kubeconfig()

    with open(os.path.expanduser(os.environ['KUBECONFIG'])) as kubeconfig:
        kubeconfig = yaml.load(kubeconfig, Loader=yaml.FullLoader)

    return kubeconfig


def update_kubeconfig(username, id_token, kubeconfig, current_context, # noqa: C901
                      config, cluster_ca):
    """Update kubeconfig file with new information."""
    context = new_context(current_context, cluster_ca, config, username)
    cluster_dict = context['context_cluster']
    context_dict = context['context']
    user_dict = {'name': username, 'user': {'token': id_token}}
    kubeconfig['current-context'] = current_context

    if not args.new_config:
        userfound = False
        for entry in kubeconfig['users']:
            if entry['name'] == username:
                entry['user']['token'] = id_token
                userfound = True
                break
        if not userfound:
            kubeconfig['users'].append(user_dict)

        context_found = False
        for entry in kubeconfig['contexts']:
            if entry['name'] == current_context:
                entry['context']['user'] = username
                context_found = True
                break
        if not context_found:
            kubeconfig['contexts'].append(context_dict)

        cluster_found = False
        for cluster in kubeconfig['clusters']:
            if cluster['name'] == current_context:
                cluster_found = True
                break
        if not cluster_found:
            kubeconfig['clusters'].append(cluster_dict)
    else:
        kubeconfig['users'][0]['user']['token'] = id_token

    with open(os.path.expanduser(os.environ['KUBECONFIG']), 'w') as file:
        yaml.dump(kubeconfig, file, default_flow_style=False)


def open_browser():
    """Open webbrowser tab to Flask app site."""
    url = 'http://localhost:5000'
    webbrowser.open_new(url)


def shutdown_server():
    """Shutdown the server."""
    server_shutdown = request.environ.get('werkzeug.server.shutdown')
    if server_shutdown is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    else:
        server_shutdown()


@app.route('/')
def auth():
    """Redirect user to Onelogin for authentication."""
    onelogin = OAuth2Session(client_id, scope=scopes,
                             redirect_uri=redirect_uri)
    ol_auth, state = onelogin.authorization_url(auth_url)
    session['oauth_state'] = state
    return redirect(ol_auth)


@app.route('/oidc_callback')
def callback():
    """Retreive Token."""
    code = request.args.get('code')
    state = session['oauth_state']
    onelogin = OAuth2Session(client_id, scope=scopes, state=state,
                             redirect_uri=redirect_uri)
    token = onelogin.fetch_token(token_url, client_secret=client_secret,
                                 code=code, include_client_id=True)
    session['oauth_token'] = token
    return redirect('/write_kubeconfig')


@app.route('/write_kubeconfig')
def write_kubeconfig():
    """Update kubeconfig with information from token."""
    onelogin = OAuth2Session(client_id, token=session['oauth_token'])
    user_info = onelogin.get(userinfo_url).json()
    username = user_info['preferred_username']
    id_token = session['oauth_token']['id_token']
    global kubeconfig

    if args.new_config:
        kubeconfig = new_kubeconfig(supported_contexts, config, username)

    update_kubeconfig(username, id_token, kubeconfig, current_context, config,
                      cluster_ca)

    return redirect('/success')


@app.route('/success')
def shutdown():
    """Remove session cookie and send server shutdown request."""
    session.clear()
    shutdown_server()
    print("Your kubeconfig has been updated!")
    return '<html><head></head>\
    <body onLoad="window.open(\'\', \'_self\', \'\'); window.close();"> \
    Your kubeconfig has been updated! You may now close this window.'


def main():
    global config
    global supported_contexts
    global args
    global current_context
    global kubeconfig
    global cluster_ca
    global client_id
    global client_secret

    config = get_config()
    supported_contexts = []
    for context in config['contexts']:
        supported_contexts.append(context)

    args = get_args(supported_contexts)

    current_context = ''
    if args.context:
        current_context = args.context
        kubeconfig = get_kubeconfig()
    else:
        if args.new_config:
            print(supported_contexts)
            while current_context not in supported_contexts:
                current_context = input("Select a context from the "
                                        "options above: ")
        else:
            kubeconfig = get_kubeconfig()
            current_context = kubeconfig['current-context']
            if current_context not in supported_contexts:
                print(supported_contexts)
                while current_context not in supported_contexts:
                    current_context = input("Select a context from the "
                                            "options above: ")

    print(f"Currently working on the {current_context} context.")

    secrets = retreive_oidc_secrets(current_context, config)
    cluster_ca = secrets['cluster_ca']
    client_id = secrets['oidc_client_id']
    client_secret = secrets['oidc_client_secret']

    Timer(.5, open_browser).start()
    app.run(debug=False)


if __name__ == '__main__':
    main()
