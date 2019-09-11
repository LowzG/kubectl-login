# kubectl-login

#### Table of Contents

1. [Description](#description)
1. [Requirements](#requirements)
1. [Installation](#installation)
1. [Usage](#usage)

## Description

kubectl-login is a kubectl plugin that authenticates the user with OneLogin and updates their kubeconfig file with all the necessary entries required to authenticate to kubernetes clusters.

## Requirements
- python3
- pip3

## Installation

```bash
git clone https://github.com/LowzG/kubectl-login.git && pip3 install ./kubectl-login
```

Notes:
- PIP will place the executable in $HOME/.local/bin so make sure that this directory is in your PATH.
- This tool requires a config file placed in $HOME/.kubectl-login/config.yaml. I have included a sample config [HERE](configuration/config.yaml) to get you started.

## Usage

For all the options below that have [ContextName], if you don't pass the context you will be presented with options from your config file.
Alternatively you can pass the context via --context to any of those options if you prefer.

If  you need to build a new kubeconfig file:
```bash
kubectl login --new-config [ContextName]
```
If  you need to add/switch to/select a new context:
```bash
kubectl login --context [ContextName]
```
To open the Kubernetes Dashboard for selected context:
```bash
kubectl login --board [ContextName]
```
Otherwise:
```bash
kubectl login
```
