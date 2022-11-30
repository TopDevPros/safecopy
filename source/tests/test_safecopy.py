#!/usr/bin/env python3
'''
    Tests safecopy.

    Copyright 2019-2021 DeNova
    Last modified: 2021-07-18
'''

import os
from subprocess import CalledProcessError
from tempfile import gettempdir
from unittest import TestCase

from denova.os.command import run
from denova.python.format import to_bytes
from denova.python.log import Log

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

        FROM_FILENAME = 'file-owned-by-root'
        FROM_PATH = os.path.abspath(os.path.join(CURRENT_DIR, FROM_FILENAME))
        TO_PATH = os.path.join(TMP_DIR, FROM_FILENAME)

        command = [SAFECOPY_APP, '--verbose', FROM_PATH, TMP_DIR]
        run(*command)
        from_stat = os.lstat(FROM_PATH)
        to_stat = os.lstat(TO_PATH)
        self.assertNotEqual(from_stat.st_uid, to_stat.st_uid)
        self.assertNotEqual(from_stat.st_gid, to_stat.st_gid)
        os.remove(TO_PATH)

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
