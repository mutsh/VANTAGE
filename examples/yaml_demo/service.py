import yaml


def load_config(text):
    return yaml.unsafe_load(text)
