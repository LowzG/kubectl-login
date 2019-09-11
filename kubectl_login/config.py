#!/usr/bin/env python3

import yaml
import os
import sys

config_path = os.path.expanduser('~/.kubectl-login/')
config_file = f'{config_path}config.yaml'


def yes_no(question):
    """Ask question via user input and return True False."""
    reply = ''
    while reply not in ['Y', 'N']:
        reply = input(f"{question} (y/n): ").upper().strip()
        reply = reply[0]
        if reply == 'Y':
            return True
        elif reply == 'N':
            return False
        else:
            continue


def new_vault_server():
    """Build dictionary of Vault server entry."""
    name = input("Enter a unique name for this Vault server: ")
    address = input("Enter the address of the Vault server: ")
    ca_path = input("Enter the full path of your Vault CA file: ")
    secrets_path = input("Enter the path where your Kubernetes secrets live in Vault: ")
    oidc_client_id = input("Enter key name containing the OIDC Client ID: ")
    oidc_client_secret = input("Enter key name containing the OIDC Client Secret: ")
    cluster_ca = input("Enter key name containing the Cluster CA: ")

    server = {'name': name, 'dict': {'address': address,
              'vault_ca_path': ca_path, 'secrets_path': secrets_path,
              'secrets': {'oidc_client_id': oidc_client_id,
              'oidc_client_secret': oidc_client_secret,
              'cluster_ca': cluster_ca}
              }}

    return server


def secrets():
    """Build dictionary containing required secrets."""
    client_id = input("Enter the OIDC Client ID: ")
    client_secret = input("Enter the OIDC Client Secret: ")

    print("Enter the cluster CA (Must be Base64 encoded): ")
    lines = []
    while True:
        line = input()
        if line:
            lines.append(line)
        else:
            break
    cluster_ca = ''.join(lines)

    secrets = {'oidc_client_id': client_id, 'oidc_client_secret': client_secret,
               'cluster_ca': cluster_ca}

    return secrets


def new_context(using_vault=True, vault_server_name='', vault_servers=''):
    """Build dictionary of Context entry."""
    name = input("Enter a unique name for this context: ")
    address = input("Enter the cluster node address for this context: ")

    if not using_vault:
        secret_dict = secrets()
        context = {'name': name, 'dict': {'cluster_address': address,
                   'secrets': secret_dict}}
    else:
        print(vault_servers)
        vault_server_name = ''
        while vault_server_name not in vault_servers:
            vault_server_name = input("Chose a Vault server from the "
                                      "options above that you will be using "
                                      f"to source secrets for the {name} "
                                      "context: ")
        context = {'name': name, 'dict': {'cluster_address': address,
                   'vault_server': vault_server_name}}
    return context


def build_config():
    """Build new config."""
    using_vault = yes_no("Will you be using Vault to source secrets?")

    if using_vault:
        servers = []
        config = {'settings': {'secrets_source': 'vault'}, 'vault_servers': {},
                  'contexts': {}}

        print("Adding Vault servers")
        cont = True
        while cont:
            server = new_vault_server()
            config['vault_servers'].update({server['name']: server['dict']})
            servers.append(server['name'])
            cont = yes_no('Would you like to add another Vault server?')
        cont = True

        print("Adding contexts")
        while cont:
            context = new_context(vault_servers=servers)
            config['contexts'].update({context['name']: context['dict']})
            cont = yes_no('Would you like to add another context?')
    else:
        print("Warning: Storing secrets in the config file is not recommended "
              "and should only be used for development purposes.")
        if yes_no("Would you like to proceed?"):
            config = {'settings': {'secrets_source': 'Local'}, 'contexts': {}}
            cont = True
        else:
            sys.exit()
        while cont:
            context = new_context(using_vault=False)
            config['contexts'].update({context['name']: context['dict']})
            cont = yes_no('Would you like to add another context?')

    with open(config_file, 'w+') as configfile:
        yaml.dump(config, configfile, default_flow_style=False, sort_keys=False)


def get_config():
    """Load configuration file."""
    wiki_url = 'https://github.com/LowzG/kubectl-login'
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    if not os.path.exists(config_file):
        print("Warning: The kubectl-login config file was not found.")
        print(f"It is recommended that you visit {wiki_url} to see some "
              "sample config files and write your own, then save it in "
              f"{config_file}")
        if yes_no("Would you like to use the CLI and be assisted in writing "
                  "one instead?"):
            build_config()
        else:
            sys.exit()
    with open(config_file) as configfile:
        config = yaml.load(configfile, Loader=yaml.FullLoader)

    return config
