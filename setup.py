#!/usr/bin/env python

from setuptools import setup

with open('requirements.txt') as f:
    requirements = f.readlines()

with open('README.md') as f:
    long_description = f.read()


setup(
    name='kubectl-login',
    version="1.0.0",
    author="Carlos Gonzalez",
    author_email="tech.lowz@gmail.com",
    description=("A kubeconfig plugin that builds/updates your kubeconfig file "
                 "with all necessary entries to auth to kubernetes clusters."),
    license="MIT",
    keywords="Kubernetes kubectl OneLogin authentication",
    url="https://github.com/LowzG/kubectl-login",
    packages=['kubectl_login'],
    entry_points={'console_scripts':
                  ['kubectl-login=kubectl_login.kubectl_login:main']},
    long_description=long_description,
    install_requires=requirements,
    zip_safe=False
    )
