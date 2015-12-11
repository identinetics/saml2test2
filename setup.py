#!/usr/bin/python
#
# Copyright (C) 2015 Umea Universitet, Sweden
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import re

from setuptools import setup, find_packages

__author__ = 'rohe0002'

version = ''
with open('src/saml2/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

setup(
    name="saml2test",
    version=version,
    description="Test framework for testing SAML2 IDPs and SPs conformance",
    author="Roland Hedberg",
    author_email="roland.hedberg@umu.se",
    license="Apache 2.0",
    package_dir={"saml2test": "src/saml2test"},
    packages=find_packages('src'),
    package_data={
        'saml2test': [
            'templates/*.html'
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    install_requires=[
        "pysaml2",
        "requests >= 2.0.0",
        ''
        'flask'
    ],
    zip_safe=False,
)
