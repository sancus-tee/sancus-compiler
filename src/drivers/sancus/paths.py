import os

def get_data_path():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
