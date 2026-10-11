import subprocess
import sys


def test_import_leaves_builtins_untouched():
    """
    Importing pymerkle used to define builtins.profile process-wide.
    """
    code = 'import builtins, pymerkle; print(hasattr(builtins, "profile"))'
    result = subprocess.run([sys.executable, '-c', code], capture_output=True,
        text=True, check=True)

    assert result.stdout.strip() == 'False'


def test_profiler_decorator_honored():
    code = '\n'.join([
        'import builtins',
        'calls = []',
        'builtins.profile = lambda func: calls.append(func) or func',
        'import pymerkle',
        'assert calls, "profiler decorator not applied"',
    ])
    subprocess.run([sys.executable, '-c', code], check=True)
