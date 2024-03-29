#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys

sys.path.append(os.path.abspath('..'))

extensions = ['sphinx.ext.autodoc', 'jaraco.packaging.sphinx', 'rst.linker']
autoapi_type = 'python'
autoapi_dirs = ['../ctap_keyring_device']

master_doc = "index"

autodoc_mock_imports = [
    'pyobjc',
    'cryptography',
    'CoreFoundation',
    'Security',
    'LocalAuthentication',
    'cbor',
    'winsdk',
]

link_files = {
    '../CHANGES.rst': dict(
        using=dict(GH='https://github.com'),
        replace=[
            dict(
                pattern=r'(Issue #|\B#)(?P<issue>\d+)',
                url='{package_url}/issues/{issue}',
            ),
            dict(
                pattern=r'^(?m)((?P<scm_version>v?\d+(\.\d+){1,2}))\n[-=]+\n',
                with_scm='{text}\n{rev[timestamp]:%d %b %Y}\n',
            ),
            dict(
                pattern=r'PEP[- ](?P<pep_number>\d+)',
                url='https://www.python.org/dev/peps/pep-{pep_number:0>4}/',
            ),
        ],
    )
}


html_theme = 'alabaster'
