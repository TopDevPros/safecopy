#!/usr/bin/env python3
'''
    Tests the doctests for safecopy.

    This is a unit test that includes doctests when we run unit tests.

    Copyright 2020-2021 DeNova
    Last modified: 2021-04-20
'''

import json
import os
from doctest import testmod

import denova.open.safecopy.views
from denova.open.safecopy.app import safecopy
from denova.os.command import run
from denova.python.log import Log
from denova.tests.denova_test_case import DeNovaTestCase


log = Log()


class TestDoctests(DeNovaTestCase):
    ''' Include doctests when we run unit tests. '''

    """
    fixtures = [
                'safeget.app.json',
                'safeget.hashvalue.json',
                'safeget.pubkey.json',
                'safeget.signature.json',
                'safeget.signedhash.json'
               ]
    """

    def test_safecopy(self):
        ''' Test safecopy doctests. '''

        # we cannot run doctests through the testmod because we need the
        # environment set up properly
        run(*['python3', os.path.abspath(safecopy.__file__), '--test'])

    def test_views(self):
        ''' Test views doctests. '''

        failure_count, test_count = testmod(denova.open.safecopy.views)
        self.assertEqual(failure_count, 0)
        print(f'Passed {test_count} "open.safecopy.views" doctests')
