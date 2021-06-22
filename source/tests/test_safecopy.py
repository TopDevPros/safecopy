#!/usr/bin/env python3
'''
    Tests safecopy.

    Copyright 2019-2021 DeNova
    Last modified: 2021-06-21
'''

import os
from subprocess import CalledProcessError
from tempfile import gettempdir
from unittest import TestCase

try:
    from denova.os.command import run
    from denova.python.log import Log
except ImportError:
    sys.exit('You need the denova package from PyPI to run the tests')


CURRENT_DIR = os.path.realpath(os.path.abspath(os.path.dirname(__file__)))
SAFECOPY_APP = os.path.abspath(os.path.join(CURRENT_DIR, '..', 'safecopy'))
TMP_DIR = os.path.join(gettempdir(), 'safecopy.test')

log = Log()


class TestSafecopy(TestCase):

    @classmethod
    def setUpClass(cls):

        # test in a temp dir
        if os.path.exists(TMP_DIR):
            if not os.path.isdir(TMP_DIR):
                os.remove(TMP_DIR)
                os.mkdir(TMP_DIR)
        else:
            os.mkdir(TMP_DIR)

    def test_app(self):
        ''' Test the app. '''

        FILENAME = os.path.basename(__file__)
        FROM_PATH = os.path.abspath(os.path.join(CURRENT_DIR, FILENAME))
        command = ['python3', SAFECOPY_APP, FROM_PATH, TMP_DIR]
        run(*command)

        TO_FILE = os.path.join(TMP_DIR, FILENAME)
        self.assertTrue(os.path.exists(TO_FILE))

    def test_no_permission(self):
        ''' Test that an error is reported when a file/directory doesn't have permission. '''

        FROM_FILE = os.path.abspath(os.path.join(CURRENT_DIR, 'file-owned-by-root'))
        command = [SAFECOPY_APP, '--verbose', FROM_FILE, TMP_DIR]
        try:
            run(*command)
            self.fail('A permission error should have occurred')
        except CalledProcessError as cpe:
            pass

    def test_doctests(self):
        ''' Test safecopy doctests. '''

        # we cannot run doctests through the testmod because we need the
        # environment set up properly
        results = run(*['python3', SAFECOPY_APP, '--test', '--verbose'])
        self.assertEqual(results.returncode, 0)

    def test_version(self):
        ''' Test that the version show up. '''

        args = ['python3', SAFECOPY_APP] + ['--version']

        results = run(*args)
        self.assertEqual(results.returncode, 0)
        self.assertIn('Safecopy', results.stdout)
        self.assertIn('Copyright', results.stdout)
        self.assertIn('GPLv3', results.stdout)
