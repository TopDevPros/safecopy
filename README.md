Safecopy
--------

Safecopy syncronizes drives and directories very carefully. Like rsync, without rsync's insecure default metadata check. Securely copies to and from remote filesystems through sshfs.

Description
-----------

Reliably Synchronize Drives and Directories

Safecopy synchronizes drives and directories, and carefully verifies the copy. When you are copying massive files or large directory trees, it's important to know that every file was copied accurately. Safecopy verifies byte-by-byte, or you can choose a quick metadata check.


Install
-------

pip3 install safecopy


How it Works
------------

    safecopy SOURCE ... DESTINATION

It's just like the standard cp command. You can have as many source paths as you like. The destination path is always last.

Safecopy gives you a lot of control:
  -h, --help                Show this help message
  --verbose                 Show progress
  --quick               Only update files if the size or last modified time is different
  --dryrun              Show what would be done, but don't do anything
  --delete              Delete all files that are not in the source before copying any files
  --nowarn              No warnings
  --test                Run tests
  --exclude EXCLUDE_PATH...   Exclude the files or directories (comma separated)
  --verify              Verify copies
  --persist             Continue on errors, except verify error
  --retries RETRIES     How many times to retry a failed copy. Default is not to retry

If you need the rsync protocol run "pip3 install pyrsync2". But it's almost always better to replace rsync with safecopy and sshfs.
Error messages

Warning: setuid/setgid bit set on ...

Safecopy detects when the setuid/setgid bit is set. This is almost always a serious security risk. To remove the bit:

    chmod -s PATH
