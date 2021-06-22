#! /usr/bin/python3
'''
    Simple secure file copy.

    Recommended:
        pip3 install denova pyrsync2

    See docs at https://denova.com/open/safecopy/

    Copyright 2018-2021 DeNova
    Last modified: 2021-06-21
'''

import argparse
import doctest
import filecmp
import os
import platform
import stat
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from glob import glob
from shutil import copystat, rmtree
from tempfile import mkstemp
from traceback import format_exc

try:
    from pyrsync2 import blockchecksums, rsyncdelta, patchstream
except ImportError:
    pass


CURRENT_VERSION = '1.2.6'
COPYRIGHT = 'Copyright 2018-2021 DeNova'
LICENSE = 'GPLv3'

UID_GID_MASK = stat.S_ISUID | stat.S_ISGID
BUFFER_1K = 1024
BUFFER_1M = BUFFER_1K * BUFFER_1K

# global variables
args = None
changed_dirs = set()
system = platform.system()

try:
    from denova.python.log import Log, get_log_path

    log = Log()
except ImportError:
    log = None

def main():
    """
        Main for safecopy.

        >>> from subprocess import run

        >>> PYTHON = 'python3'
        >>> TEST_LENGTH = 5

        >>> def test_safecopy(*args):
        ...     CURRENT_DIR = os.path.realpath(os.path.abspath(os.path.dirname(__file__)))
        ...     safecopy_cmd = os.path.join(CURRENT_DIR, 'safecopy')
        ...     command = [safecopy_cmd, '--verbose'] + list(args)
        ...     log_message(f'safecopy command: {command}')
        ...     run(command)

        >>> def diff(from_path, to_path):
        ...     with open(from_path, 'rb') as from_file:
        ...         with open(to_path, 'rb') as to_file:
        ...             from_data = from_file.read()
        ...             to_data = to_file.read()
        ...     assert from_data == to_data, f'from_data={from_data}, to_data={to_data}'

        >>> def safecopy_check(from_path, to_path):
        ...     test_safecopy(from_path, to_path)
        ...     assert os.path.getsize(from_path) == os.path.getsize(to_path)
        ...     assert os.path.getsize(from_path) == os.path.getsize(to_path)
        ...     diff(from_path, to_path)
        ...     from_stats = os.lstat(from_path)
        ...     to_stats = os.lstat(to_path)
        ...     assert from_stats.st_mtime == to_stats.st_mtime
        ...     assert from_stats.st_mode == to_stats.st_mode

        >>> _, from_path = mkstemp()
        >>> _, to_path = mkstemp()

        >>> with open(from_path, 'wb') as from_file:
        ...     file_length = from_file.write(bytes(range(TEST_LENGTH)))
        >>> file_length == TEST_LENGTH
        True
        >>> os.path.getsize(from_path) == TEST_LENGTH
        True
        >>> safecopy_check(from_path, to_path)

        >>> with open(from_path, 'ab') as from_file:
        ...     _ = from_file.write(b'more')
        >>> safecopy_check(from_path, to_path)

        >>> os.remove(from_path)
        >>> os.remove(to_path)
    """

    global args

    parser, args = parse_args()

    if args.test:
        doctest.testmod()

    elif args.version:
        show_version()

    else:
        if len(args.paths) >= 2:
            start_safecopy()

        else:
            parser.print_help()
            error_exit('need one or more source paths and the destination path')

def show_version():
    ''' Show safecopy's name and version.

        >>> show_version()
        <BLANKLINE>
        Safecopy 1.2.6
        Copyright 2018-2021 DeNova
        License: GPLv3
        <BLANKLINE>
        <BLANKLINE>
    '''

    details = f'\nSafecopy {CURRENT_VERSION}\n{COPYRIGHT}\nLicense: {LICENSE}\n\n'

    print(details)

def start_safecopy():
    ''' Housekeeping, error checking, then start the copy. '''

    global args

    try:
        from_paths, to_root, to_path = parse_paths()

        if args.delete:
            delete_files(from_paths, to_path)

        if args.exclude:
            exclude_paths = args.exclude.split(',')
            for exc_path in exclude_paths:
                if ('*' in exc_path or '?' in exc_path):
                    exc_path(glob(exc_path))
            log_message(f'exclude: {exclude_paths}')

        else:
            exclude_paths = []

        for path in from_paths:

            from_path = os.path.abspath(path)
            log_message(f'from_path={from_path}')
            # from_root is the part of from_path that is definitely a dir
            # the basename may be a dir or file
            from_root = os.path.dirname(from_path)
            log_message(f'from_root={from_root}')

            # If the destination is a dir, the sources are copied into that dir
            if os.path.isdir(to_path):
                full_to_path = os.path.join(to_path, os.path.basename(from_path))
            else:
                full_to_path = to_path

            copy(from_path, full_to_path, from_root, to_root, exclude_paths)

    except KeyboardInterrupt:
        log.exception_only()

    except Exception as exc:
        log.exception()
        error_exit(exc)

def copy(from_path, to_path, from_root, to_root, exclude_paths):
    ''' Copy files from from_path to to_path. Copy directories recursively.

        >>> def check_dir(from_path, to_path, shared_path):
        ...    dir_entries = os.scandir(from_path)
        ...    for dir_entry in dir_entries:
        ...        to_path = os.path.join(to_path, dir_entry.name)
        ...        if dir_entry.is_dir():
        ...            check_dir(dir_entry.path, to_path, shared_path)
        ...        else:
        ...             verify_copy(dir_entry.path, to_path, shared_path)

        >>> from tempfile import gettempdir

        >>> temp_dir = gettempdir()
        >>> test_from = os.path.join(temp_dir, 'test-safecopy-from')
        >>> if os.path.exists(test_from):
        ...     rmtree(test_from)
        >>> test_to = os.path.join(temp_dir, 'test-safecopy-to')
        >>> to_root = os.path.dirname(test_to)
        >>> if os.path.exists(test_to):
        ...     rmtree(test_to)

        # create a multi-level directory so we can verify metadata matches at all levels
        >>> from_test_subdir = os.path.join(test_from, 'subdir1', 'subdir2')
        >>> from_test_path = os.path.join(from_test_subdir, 'test-file.txt')
        >>> from_root = os.path.dirname(test_from)
        >>> os.makedirs(from_test_subdir)
        >>> with open(from_test_path, 'wt') as outfile:
        ...     __ = outfile.write('this is a test')

        >>> exclude_paths = []
        >>> copy(test_from, test_to, from_root, to_root, exclude_paths)

        >>> os.path.isdir(test_to)
        True

        >>> shared_path = test_from[len(from_root):].lstrip(os.sep)
        >>> verify_copy(test_from, test_to, shared_path)
        >>> check_dir(test_from, test_to, shared_path)

        >>> to_test_path = os.path.join(test_to, 'subdir1', 'subdir2', 'test-file.txt')
        >>> os.path.isfile(to_test_path)
        True

        >>> with open(to_test_path) as infile:
        ...     print(infile.read())
        this is a test
    '''

    # shared_path is the shared part of the path
    # that currently exists in from_path,
    # and will exist in to_path, excluding the from_root
    shared_path = from_path[len(from_root):].lstrip(os.sep)

    if exclude_path(from_path, from_root, exclude_paths):
        log_message(f'excluding {from_path}')

    else:
        file_pair = FileCopier(from_path, to_path, shared_path)
        if file_pair.equal():
            log_message(f'already equal: {shared_path}')

        else:
            # the dir entries to copy are in self.from_path and self.to_path
            # from_root and to_root are just so we can make and update dirs
            file_pair.make_dirs_and_copy(from_root, to_root)

        if os.path.isdir(from_path):
            log_message(f'dir: {shared_path}')

            # copy dir contents recursively
            dir_entries = sorted(os.scandir(from_path), key=lambda k: k.name)
            # for rsync compatibility, files then dirs
            for entry in dir_entries:
                # if entry is a file or symlink
                if entry.is_file():
                    full_from = entry.path
                    full_to = os.path.join(to_path, entry.name)
                    copy(full_from, full_to, from_root, to_root, exclude_paths)
            for entry in dir_entries:
                # symlinks are included above by entry.is_file()
                # if entry is a dir that is not a symlink
                if entry.is_dir(follow_symlinks=False):
                    full_from = entry.path
                    full_to = os.path.join(to_path, entry.name)
                    copy(full_from, full_to, from_root, to_root, exclude_paths)

            if not args.dryrun:
                # we need a check for stats_equal,
                # for the stats that copystat copies
                log(f'copy dir metadata from: {from_path}')
                log(f'                    to: {to_path}')
                # from_path and to_path are the dirs we just copied
                file_pair.copy_metadata(from_path, to_path)

def copy_rsync_delta(from_path, to_path):
    ''' Copy using pyrsync2 implementation of rsync delta-copy algo.

        Based on benchmarks, the delta-copy algo may be good for huge
        files with small changes on a slow network. For most cases today,
        a straight byte comparison and full copy is faster and more
        secure. Even rsync doesn't use delta-copy by default.
    '''

    try:
        log_message('hash old file')
        unpatched = open(to_path, "rb")
        hashes = blockchecksums(unpatched)

        log_message('get changes')
        patchedfile = open(from_path, "rb")
        delta = rsyncdelta(patchedfile, hashes)

        log_message('apply changes')
        unpatched.seek(0)
        _, temp_path = mkstemp()
        save_to = open(temp_path, "wb")
        patchstream(unpatched, save_to, delta)

        save_to.close()
        unpatched.close()
        patchedfile.close()

        os.rename(unpatched, to_path)
    except ImportError:
        pass

def verify_copy(from_path, to_path, shared_path):
    ''' Verify the copy. '''

    # fresh copier to verify
    file_pair = FileCopier(from_path, to_path, shared_path)
    if file_pair.equal():
        verbose(f'verified: {shared_path}')
    else:
        # verify failure takes precendence over --persist
        error_exit('Unable to verify')

def parse_paths():
    '''
        Parse the paths from args passed on the command line.
    '''

    global args

    if len(args.paths) <= 1:
        log_message(f'more than one path needed: safecopy SOURCE... DEST; args: {args}')
        error_exit('More than one path needed: safecopy SOURCE... DEST')

    # get from_paths
    from_paths = []
    # the last path is the destination
    for raw_path in args.paths[:-1]:
        if os.path.isfile(raw_path):
            # glob.glob() considers '[' and ']' wildcard chars
            # but these chars can appear in filenames
            from_paths.append(raw_path.rstrip(os.sep))
        else:
            # expand wildcards in from_paths
            glob_paths = glob(raw_path)
            if not glob_paths:
                error_exit(f'Unable to read: {raw_path}')
            for path in glob_paths:
                from_paths.append(path.rstrip(os.sep))
    log_message(f'from {from_paths}')

    # the last path is the destination
    to_path = args.paths[-1]
    log_message(f'to {to_path}')

    for path in from_paths:
        if not os.path.exists(path):
            error_exit(f'Source not found: {path}')

    if not os.path.exists(to_path):
        to_path_parent = os.path.dirname(to_path)
        if not os.path.isdir(to_path_parent):
            error_exit(f'Destination directory not found {to_path_parent}')

    if len(from_paths) > 1:
        if not os.path.isdir(to_path):
            error_exit(f'With more than one source path, destination must be a dir: {to_path}')

    to_path = os.path.abspath(to_path)
    if os.path.isdir(to_path):
        to_root = to_path
    else:
        to_root = os.path.dirname(to_path)
    log_message(f'to_root={to_root}')

    return from_paths, to_root, to_path

def exclude_path(from_path, from_root, exclude_names):
    ''' Determine if this path should be excluded. '''

    exclude = False
    if exclude_names:
        for exclude_name in exclude_names:
            exclude = from_path == os.path.abspath(os.path.join(from_root, exclude_name))
            if exclude:
                break

    return exclude

def delete_files(from_paths, to_path):
    ''' Delete files in to_path that are not in any of the from_paths '''

    def relative_path(path, root):
        return path[len(root):].strip(os.sep)

    def delete_paths_in_dir():
        '''
            Get paths to delete in this dir
            use a list instead of set, so we delete in the expected order
        '''

        to_root = os.path.abspath(to_path)
        for dirpath, dirnames, filenames in os.walk(to_root):
            for name in sorted(dirnames + filenames):
                path = os.path.join(dirpath, name)
                to_rel_path = relative_path(path, to_root)
                if to_rel_path not in shared_paths:
                    if args.dryrun:
                        verbose(f'would delete {path}')
                    else:
                        verbose(f'Deleted {path}')
                        delete(path)

    if os.path.isdir(to_path):

        # to do: for speed do as much as possible during the first pass over sources

        # get a list of all shared source paths in the source dirs

        # shouldn't be adding any dups, but set lookups are faster than lists
        shared_paths = set()

        verbose(f'Deleting extraneous files from: {to_path}')
        log_message(f'comparing to {from_paths}')
        for from_path in from_paths:

            if os.path.isdir(from_path):
                ''' Because to_path is a dir, we copy from_path into to_path.
                    That means the shared_path must include the from_path
                    basename, and so from_root must *not* include the from_path
                    basename.
                    To do that, from_root is the parent dir of from_path.
                '''
                log_message(f'checking {from_path} for extraneous files')
                from_root = os.path.dirname(os.path.abspath(from_path))

                for dirpath, dirnames, filenames in os.walk(from_root):
                    for name in dirnames + filenames:
                        path = os.path.join(dirpath, name)
                        from_rel_path = relative_path(path, from_root)
                        shared_paths.add(from_rel_path)

                delete_paths_in_dir()

def delete(path):
    ''' Delete path.

        If dir, delete all files in dir.
    '''

    log_message(f'delete {path}')
    if os.path.islink(path):
        os.remove(path)
        log_message(f'after remove, path {path} lexists: {os.path.lexists(path)}')
    elif os.path.isdir(path):
        rmtree(path)
    elif os.path.isfile(path):
        os.remove(path)

def verbose(msg):
    ''' Print and log verbose message '''

    if args.verbose:
        print(msg)
        log_message(msg)
        sys.stdout.flush()

def warn(msg):
    ''' Print and log warning message '''

    if args and not args.nowarn:
        msg = 'Warning: ' + msg
        print(msg)
        sys.stdout.flush()
        log_message(msg)

def error_exit(why=None):
    '''
        Exit on error.

        >>> why = PermissionError("[Errno 1] Operation not permitted: 'file-owned-by-root'")
        >>> try:
        ...     error_exit(why)
        ... except SystemExit as se:
        ...    se.code == 1
        <BLANKLINE>
        <BLANKLINE>
        Permission error on: 'file-owned-by-root'
        <BLANKLINE>
        <BLANKLINE>
        <BLANKLINE>
        True
        >>> why = FileNotFoundError('No such file or directory: [test]')
        >>> try:
        ...     error_exit(why)
        ... except SystemExit as se:
        ...    se.code == 1
        <BLANKLINE>
        <BLANKLINE>
        No such file or directory: [test]
        <BLANKLINE>
        <BLANKLINE>
        <BLANKLINE>
        True
        >>> try:
        ...     error_exit()
        ... except SystemExit as se:
        ...    se.code == 1
        <BLANKLINE>
        <BLANKLINE>
        Error copying file(s)
        <BLANKLINE>
        <BLANKLINE>
        <BLANKLINE>
        True
    '''
    NOT_PERMITTED = '[Errno 1] Operation not permitted: '
    ERROR_NUMBER2 = '[Errno 2] '
    DETAILS = 'Error copying file(s)'

    if args and args.test:
        output = sys.stdout
    else:
        output = sys.stderr

    if why:
        if isinstance(why, FileNotFoundError):
            why_string = str(why)
            index = why_string.find(ERROR_NUMBER2)
            if index >= 0:
                why = why_string[index+len(ERROR_NUMBER2):]
            full_details = why
        elif isinstance(why, PermissionError):
            why_string = str(why)
            index = why_string.find(NOT_PERMITTED)
            if index >= 0:
                why = why_string[index+len(NOT_PERMITTED):]
            full_details = f'Permission error on: {why}'
        else:
            full_details = f'{DETAILS}: {why}'
    else:
        full_details = DETAILS

    log_message(full_details)
    print(f'\n\n{full_details}', file=output)

    try:
        if args and args.verbose:
            log_message(f'See details in {get_log_path()}\n\n')
            print(f'See details in {get_log_path()}\n\n', file=sys.stderr)
        else:
            print(f'\n\n', file=output)
    except NameError:
        print(f'\n\n', file=output)

    sys.exit(1)

def parse_args():
    ''' Parsed command line. '''

    parser = argparse.ArgumentParser(description='Sync files.')

    parser.add_argument('paths',
                        nargs='*',
                        help='Copy files to the destination. The last path is the destination.')
    parser.add_argument('--verbose',
                        help="Show progress",
                        action='store_true')
    parser.add_argument('--quick',
                        help="Only update files if the size or last modified time is different",
                        action='store_true')
    # argparse does not allow dashes in flags, so --dryrun, not rsync's --dry-run
    parser.add_argument('--dryrun',
                        help="Show what would be done, but don't do anything",
                        action='store_true')
    parser.add_argument('--delete',
                        help='Delete all files that are not in the source before copying any files',
                        action='store_true')
    parser.add_argument('--nowarn',
                        help='No warnings',
                        action='store_true')
    parser.add_argument('--test',
                        help='Run tests. You must use --test to run doctests.',
                        action='store_true')
    parser.add_argument('--exclude',
                        nargs='?',
                        help='Exclude the following files and/or directories (comma separated).')
    parser.add_argument('--verify',
                        help='Verify copies',
                        action='store_true')
    parser.add_argument('--persist',
                        help='Continue on errors, except verify error.',
                        action='store_true')
    parser.add_argument('--retries',
                        help='How many times to retry a failed copy. Default is not to retry',
                        type=int,
                        default=0)
    parser.add_argument('--version', help='show the product and version number', action='store_true')

    # print(f'type parser args: {parser.parse_args()}')
    return parser, parser.parse_args()


class FileCopier():
    ''' Copy a file to another path.

        FileCopier.equal() returns True if the files are byte-for-byte
        equal. This does not say anything about metadata.

        FileCopier.count_equal_bytes() returns the count of equal bytes. The count
        lets us start a copy at the first unequal byte.
        This is particularly effective if the last copy to to_path
        wasn't complete, or if from_path was updated by appending.
    '''

    def __init__(self, from_path, to_path, shared_path):

        self.from_path = from_path
        self.to_path = to_path
        self.shared_path = shared_path

        self.count = 0

    def count_equal_bytes(self):
        ''' Count how many leading bytes are equal. '''

        # In order to directly compare equal size buffers from from_path
        # and to_path, we don't rely on read() to guess the buffer size
        buffer_size = BUFFER_1K

        if self.count == 0:

            with LogElapsedTime('self.count_equal_bytes'):
                if (os.path.isfile(self.from_path) and
                    (not os.path.islink(self.from_path)) and
                    os.path.exists(self.to_path)):

                    with open(self.from_path,'rb') as from_file:
                        with open(self.to_path, 'rb') as to_file:
                            self.count = 0

                            log_message('read from_file')
                            from_bytes = from_file.read(buffer_size)
                            log_message('read to_file')
                            to_bytes = to_file.read(buffer_size)
                            while from_bytes and to_bytes and (from_bytes == to_bytes):
                                self.count = self.count + len(from_bytes)
                                # log_message('equal so far: {}'.format(self.count))
                                # log_message('read from_file')
                                from_bytes = from_file.read(buffer_size)
                                # log_message('read to_file')
                                to_bytes = to_file.read(buffer_size)

                            log_message('count last partial buffer')
                            last_buffer_size = min(len(from_bytes),
                                                   len(to_bytes))
                            index = 0
                            while ((index < last_buffer_size) and
                                   (from_bytes[index] == to_bytes[index])):
                                self.count = self.count + 1
                                index = index + 1

        log_message(f'{self.count} equal bytes')

        return self.count

    def both_exist(self):
        ''' Test that both files exist. '''

        with LogElapsedTime('both_exist'):
            # check to_path first, since from_path very likely exists
            to_exists = os.path.exists(self.to_path)
            if to_exists:
                from_exists = os.path.exists(self.from_path)
                if from_exists:
                    equal = True
                else:
                    equal = False
                    log_message(f'unequal because source path does not exist: {self.from_path}')
            else:
                equal = False
                log_message(f'unequal because dest path does not exist: {self.to_path}')

            return equal

    def types_equal(self):
        ''' Test that paths are both files, or both dirs,
            or both links with the same target.
        '''

        with LogElapsedTime('types_equal'):
            if os.path.islink(self.from_path):
                if os.path.islink(self.to_path):
                    from_target = os.readlink(self.from_path)
                    to_target = os.readlink(self.to_path)
                    equal = (from_target == to_target)
                    if not equal:
                        log_message(f'unequal: link targets are different: {self.shared_path}')
                else:
                    equal = False
                    log_message(f'unequal: from_path is a link and to_path is not: {self.shared_path}')

            # isfile() returns True on regular files and links
            # so we checked for links above
            elif os.path.isfile(self.from_path):
                equal = os.path.isfile(self.to_path)
                if not equal:
                    log_message(f'unequal: from_path is a file and to_path is not: {self.shared_path}')

            elif os.path.isdir(self.from_path):
                equal = os.path.isdir(self.to_path)
                if not equal:
                    log_message(f'unequal: from_path is a dir and to_path is not: {self.shared_path}')

            else:
                log_message(f'skipped because file is not a link, file, or dir: {self.from_path}')
                # set equal so we won't try to copy it
                equal = True

        return equal

    def permissions_equal(self):
        ''' Test that permissions are equal.

            Because we don't set uid/gid in the dest, this test ignores
            setuid/setgid. See copy_metadata().

            This test is necessary, but weak.
        '''

        with LogElapsedTime('permissions_equal'):
            from_stat = os.lstat(self.from_path)
            to_stat = os.lstat(self.to_path)

            if from_stat.st_mode & UID_GID_MASK:
                warn(f'setuid/setgid bit set on {self.from_path}')
                # mask out uid/gid in source
                # so we don't set uid/gid in dest
                from_mode = from_stat.st_mode & ~UID_GID_MASK
                to_mode = to_stat.st_mode & ~UID_GID_MASK
            else:
                from_mode = from_stat.st_mode
                to_mode = to_stat.st_mode

            equal = (from_mode == to_mode)
            if not equal:
                log_message(f'unequal because permissions are different: {self.shared_path}')

        return equal

    def modified_times_equal(self):
        ''' Test that modified times are equal.

            Because safecopy sets the dest stats from the source after copying,
            comparing times is a good quick test. If the file is the same
            size and the last-modified time is the same, the files are very
            likely equal. But this test can fail if an attacker has reduced
            the size of a file by the length of their embedded malware,
            then restored the file times.
        '''

        with LogElapsedTime('modified_times_equal'):
            from_stats = os.lstat(self.from_path)
            to_stats = os.lstat(self.to_path)
            equal = (from_stats.st_mtime == to_stats.st_mtime)
            if not equal:
                log_message(f'unequal because modified times are different: {self.shared_path}')
                log_message(f'{from_stats.st_mtime} is not {to_stats.st_mtime}')

        return equal

    def byte_for_byte_equal(self):
        ''' Compare byte by byte. If one doesn't match, stop.

            This comparison is as safe as it gets.

            filecmp.cmp() is smart about buffers, etc.
        '''

        with LogElapsedTime('byte_for_byte_equal'):
            if os.path.isfile(self.from_path) and not os.path.islink(self.from_path):
                if os.path.exists(self.to_path):
                    equal_bytes = self.count_equal_bytes()
                    if ((equal_bytes == os.path.getsize(self.from_path)) and
                        (equal_bytes == os.path.getsize(self.to_path))):

                        log_message('files are byte-for-byte equal; metadata unknown')
                        equal = True
                        # equal = filecmp.cmp(self.from_path, self.to_path, shallow=False)

                    else:
                        equal = False
                        log_message(f'unequal because bytes not equal: from size {os.path.getsize(self.from_path)}')
                        log_message(f'                                   to size {os.path.getsize(self.to_path)}')

                else:
                    equal = False
                    log_message(f'byte for byte not equal because {self.to_path} does not exist')

            else:
                # no bytes to compare for links or dirs, so all bytes are equal
                equal = True

        return equal

    def metadata_equal(self):
        '''
            Just compare metadata, not byte-for-byte.
        '''

        # Cheap comparisons first. Shortcut compare when we can. If unequal, log why.

        if os.path.exists(self.to_path):

            # double check our metadata compare
            # filecmp.cmp(self.from_path, self.to_path, shallow=True)

            equal = (self.both_exist() and
                     self.types_equal() and
                     self.sizes_equal() and
                     self.permissions_equal() and
                     self.modified_times_equal())
            if not equal:
                log_message(f'{self.from_path} not equal to {self.to_path}')
        else:

            equal = False
            log_message(f'unequal because path does not exist: {self.to_path}')

        return equal

    def sizes_equal(self, from_path=None, to_path=None):
        ''' Test that file sizes are equal.

            This test can fail if an attacker has reduced the size of a file
            by the length of their embedded malware.
        '''

        with LogElapsedTime('sizes_equal'):
            if from_path is None:
                from_path = self.from_path
            if to_path is None:
                to_path = self.to_path

            if os.path.isdir(self.from_path) or os.path.islink(self.from_path):
                # no meaningful size
                equal = True

            elif not os.path.exists(self.to_path):
                equal = False

            else:
                from_size = os.path.getsize(self.from_path)
                to_size = os.path.getsize(self.to_path)
                equal = (from_size == to_size)
                if not equal:
                    log_message(f'unequal because sizes not equal: {from_size} != {to_size}')

        return equal

    def equal(self):
        ''' Return True if metadata is equal and files are byte-for-byte equal.

            '--quick' just checks metadata.
        '''

        with LogElapsedTime('compare_files'):
            # Cheap comparisons first. Shortcut compare when we can. If unequal, log why.
            if args.quick:
                equal = self.metadata_equal()

            else:
                equal = (self.metadata_equal() and
                         self.byte_for_byte_equal())

        return equal

    def try_to_copy(self):
        ''' Try to copy from_path to to_path. '''

        if os.path.islink(self.from_path):
            target = os.readlink(self.from_path)
            delete(self.to_path)
            os.symlink(target,
                       self.to_path,
                       target_is_directory=os.path.isdir(self.from_path))
            verbose(f'Linked from {self.to_path} to {target}')

        elif os.path.isfile(self.from_path):
            # if we start copying from equal bytes, we don't remove the to_path
            # delete(self.to_path)

            if self.byte_for_byte_equal():

                log_message('files are byte-for-byte equal; metadata unchecked')

            elif os.path.getsize(self.from_path) == 0:
                with open(self.to_path, 'wb'):
                    log_message(f'created empty file {self.to_path} to match original')

            else:
                self.copy_bytes()
                verbose(f'Copied {os.path.basename(self.from_path)} to {self.to_path}')

        elif os.path.isdir(self.from_path):
            # to_path must be a dir
            if not os.path.isdir(self.to_path):
                delete(self.to_path)

            if not os.path.exists(self.to_path):
                log_message(f'makedirs {self.to_path}')
                os.makedirs(self.to_path)
                verbose(f'Created: {self.to_path}')

        # set to_path attrs from from_path
        self.copy_metadata(from_path=self.from_path, to_path=self.to_path)

    def copy_bytes(self):
        ''' Copy bytes from_path to to_path, skipping those that match. '''

        def copy_remaining_bytes(from_file, to_file, buffer_size=None):
            if buffer_size:
                buf = from_file.read(buffer_size)
            else:
                buf = from_file.read()
            while buf:
                to_file.write(buf)
                if buffer_size:
                    buf = from_file.read(buffer_size)
                else:
                    buf = from_file.read()

        log_message(f'copying "{self.from_path}" to "{self.to_path}"')
        # open both files as random access
        with open(self.from_path, 'rb+') as from_file:
            # open the to_path for appending so that part
            # which matches the from_path will be kept and
            # we'll seek to the correct position before writing
            with open(self.to_path, 'ab+') as to_file:

                equal_bytes = self.count_equal_bytes()
                log_message(f'copy from byte {equal_bytes + 1}')
                # seek position is zero-based, so the count
                # of equal bytes is the seek position
                from_file.seek(equal_bytes)
                to_file.seek(equal_bytes)

                to_file.truncate(equal_bytes)

                buffer_size = BUFFER_1M
                copy_remaining_bytes(from_file, to_file, buffer_size=buffer_size)

                copy_remaining_bytes(from_file, to_file, buffer_size=buffer_size)
                """ this can fail silently
                try:
                    copy_remaining_bytes(from_file, to_file, buffer_size=buffer_size)

                except MemoryError:
                    log_message(f'memory error while trying to copy with {buffer_size} buffer')
                    buffer_size = BUFFER_1K
                    copy_remaining_bytes(from_file, to_file, buffer_size=buffer_size)
                """

        log_message('copied bytes')

    def make_dirs_and_copy(self, from_root, to_root):
        '''
            Make parent dirs and copy one directory entry
            from self.from_path to self.to_path.

            The dir entries to copy are in self.from_path and
            self.to_path. The params from_root and to_root are just
            so we can make and update dirs.
        '''

        def make_parent_dirs(path):
            ''' Create parent dirs, outermost first.

                For rsync compatibility. '''

            if path and path != os.sep:
                log(f'make_parent_dirs(): {path}')

                # recurse early to make highest level dir first
                make_parent_dirs(os.path.dirname(path))

                if path not in changed_dirs:
                    log(f'making parent dir: {path}')

                    changed_dirs.add(path)

                    from_dir = os.path.join(from_root, path)
                    to_dir = os.path.join(to_root, path)

                    if not os.path.exists(to_dir):
                        verbose(f'Creating: {path + os.sep}')
                        if not args.dryrun:
                            os.makedirs(to_dir)

                else:
                    log(f'parent dir already exists: {path}')

        def copy_persistently():
            ''' Copy and retry as needed. '''

            try:
                ok = False
                try:
                    self.try_to_copy()
                    ok = True
                except:
                    log.exception()
                    retries = args.retries
                    while retries:

                        log_message('retry copy path after error')
                        try:
                            self.try_to_copy()
                        except:
                            if retries:
                                log.exception_only()
                                retries = retries - 1
                        else:
                            ok = True
                            retries = 0

                    if not ok:
                        raise

                else:
                    if args.verify:
                        verify_copy(self.from_path, self.to_path, self.shared_path)

            except:
                if args.persist:
                    # log exception and continue
                    log.exception()
                    log_message('continue with next path after error')

                else:
                    raise

        with LogElapsedTime('make_dirs_and_copy'):
            path = os.path.dirname(self.shared_path)
            make_parent_dirs(path)
            if not args.dryrun:
                copy_persistently()

    def copy_metadata(self, from_path=None, to_path=None):
        '''
            Copy metadata from from_path to to_path.

            >>> from shutil import copyfile, copytree, rmtree

            >>> # verify that we set the metadata on a file
            >>> from tempfile import gettempdir
            >>> from_path = os.path.abspath(__file__)
            >>> to_path = os.path.join(gettempdir(), os.path.basename(from_path))
            >>> from_root = os.path.dirname(from_path)
            >>> shared_path = from_path[len(from_root):].lstrip(os.sep)
            >>> if os.path.exists(to_path):
            ...     if os.path.isdir(to_path):
            ...         rmtree(to_path)
            ...     else:
            ...         os.remove(to_path)
            >>> __ = copyfile(from_path, to_path)
            >>> fc = FileCopier(from_path, to_path, shared_path)
            >>> fc.copy_metadata()
            >>> filecmp.cmp(from_path, to_path)
            True

            >>> from shutil import copyfile, copytree, rmtree
            >>> def verify_metadata_in_dir(fc, from_path, to_path):
            ...     entries = sorted(os.scandir(from_path), key=lambda k: k.name)
            ...     for entry in entries:
            ...         full_from = entry.path
            ...         full_to = os.path.join(to_path, entry.name)
            ...         log_message(f'comparing: {full_from} to {full_to}')
            ...         if not fc.metadata_equal():
            ...             log_message(f'from: {os.stat(full_from)}')
            ...             log_message(f'to {os.stat(full_to)}')
            ...         assert fc.metadata_equal() == True
            ...         if entry.is_dir():
            ...             fname = os.path.join(to_path, entry.name)
            ...             verify_metadata_in_dir(fc, entry.path, fname)

            >>> # verify that we set the metadata on a directory and all its components
            >>> from tempfile import gettempdir
            >>> from_path = os.path.abspath(os.path.dirname(__file__))
            >>> to_path = os.path.join(gettempdir(), os.path.basename(from_path))
            >>> from_root = os.path.dirname(from_path)
            >>> shared_path = from_path[len(from_root):].lstrip(os.sep)
            >>> if os.path.exists(to_path):
            ...     if os.path.isdir(to_path):
            ...         rmtree(to_path)
            ...     else:
            ...         os.remove(to_path)
            >>> __ = copytree(from_path, to_path)
            >>> fc = FileCopier(from_path, to_path, shared_path)
            >>> fc.copy_metadata()
            >>> verify_metadata_in_dir(fc, from_path, to_path)
        '''

        if from_path != to_path:

            log_message(f'copy metadata:\n    from_path={from_path}\n    to_path={to_path}')

            if from_path is None:
                from_path = self.from_path
            if to_path is None:
                to_path = self.to_path

            # links don't have normal stat, and the permissions are for the target path
            # or if the target does not exist, the permissions are 0o777 placeholders
            if os.path.islink(to_path):

                log_message('links do not have normal metadata')

            else:

                if os.path.isfile(from_path):
                    if not self.sizes_equal(from_path=from_path, to_path=to_path):
                        msg = f'Cannot copy {from_path} metadata because file sizes are not equal'
                        error_exit(msg)

                from_stat = os.lstat(from_path)

                # Windows does not support os.chown
                if system != 'Windows':
                    os.chown(to_path, from_stat.st_uid, from_stat.st_gid)

                if from_stat.st_mode & UID_GID_MASK:
                    warn(f'setuid/setgid bit set on {from_path}')
                    # mask out uid/gid in source
                    # so we don't set uid/gid in dest
                    mode = from_stat.st_mode & ~UID_GID_MASK
                else:
                    mode = from_stat.st_mode
                os.chmod(to_path, mode)

                """
                # not portable, and
                # this is inside "if not os.path.islink(to_path)"

                # this gets "NotImplementedError: chmod: follow_symlinks unavailable on this platform"
                os.chmod(to_path, mode, follow_symlinks=False)

                # this gets "AttributeError: module 'os' has no attribute 'lchmod'"
                if os.path.islink(to_path):
                    os.lchmod(to_path, mode)
                else:
                    os.chmod(to_path, mode)
                """

                # filecmp cmp compares all the times (ctime, atime, and mtime)
                # but python doesn't let us set ctime so the comparison can
                # fail even though the important stats match
                # don't use self.metadata_equal() here, because it
                # checks self.from_path and self.to_path and sometimes we want
                # to pass in values that aren't in the class
                if not filecmp.cmp(from_path, to_path):
                    copystat(from_path, to_path, follow_symlinks=False)

                # earlier metadata updates apparently change last
                # modified/accessed times
                # shutil.copystat() does not seem to reliably
                # change mtime, so we do
                atime = os.path.getatime(from_path)
                mtime = os.path.getmtime(from_path)
                os.utime(to_path, (atime, mtime))

                os.utime(to_path, (atime, mtime))

                log_message(f'copied metadata to {to_path}')

def log_message(message):
    ''' Log a message if the denova package is available. '''

    try:
        log(message)
    except TypeError:
        pass


class LogElapsedTime():
    ''' Context manager to log elapsed time.

        >>> from time import sleep
        >>> ms = 200
        >>> with LogElapsedTime('test sleep'):
        ...     sleep(float(ms)/1000)
    '''

    def __init__(self, msg=None):

        self.start = self.now()
        self.msg = msg

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        elapsed = self.now() - self.start
        if self.msg:
            log_message(f'{self.msg} elapsed time {elapsed}')
        else:
            log_message(f'elapsed time {elapsed}')

    def now(self):
        return datetime.utcnow().replace(tzinfo=timezone.utc)


if __name__ == "__main__":
    main()
