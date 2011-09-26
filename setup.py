#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Distutils setup script for plow"""

from distutils.core import setup

# obtain name and version from the debian changelog
dch_data = open("debian/changelog").readline().split()
dch_name = dch_data[0]
# version is the second token ([1])
# we need to remove the parenthesis ([1:-1])
dch_version = dch_data[1][1:-1]

setup(
    name=dch_name,
    version=dch_version,
    description="python-ldap object wrapper",
    author="Vincent Vinet",
    author_email="vince.vinet@gmail.com",
    url="https://github.com/veloutin/plow",
    license="LGPLv3",
    platforms=["Linux"],
    long_description="""Open Account Provisionning System""",
    packages=['plow'],
    scripts=[],
    data_files=[],
    )
