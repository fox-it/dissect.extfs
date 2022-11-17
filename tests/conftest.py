import gzip
import os

import pytest


def absolute_path(filename):
    return os.path.join(os.path.dirname(__file__), filename)


def gzip_file(filename):
    with gzip.GzipFile(absolute_path(filename), "rb") as fh:
        yield fh


@pytest.fixture
def ext4_simple():
    yield from gzip_file("data/ext4.bin.gz")
