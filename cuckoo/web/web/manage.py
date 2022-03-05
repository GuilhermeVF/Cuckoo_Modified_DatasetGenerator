#!/usr/bin/env python
import sys

path = '/home/cuckoo/cuckoo-code/cuckoo/web'
if path not in sys.path:
    sys.path.append(path)

if __name__ == "__main__":
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
