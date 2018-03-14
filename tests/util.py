import os
import json

ROOT = os.path.abspath(os.path.dirname(__file__))


def get_file_path(name):
    return os.path.join(ROOT, 'files', name)


def read_file_path(name):
    with open(get_file_path(name), 'r') as f:
        if name.endswith('.json'):
            return json.load(f)
        return f.read()
