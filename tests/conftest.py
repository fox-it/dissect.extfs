import gzip
import os
from typing import BinaryIO, Iterator

import pytest


def absolute_path(filename) -> str:
    return os.path.join(os.path.dirname(__file__), filename)


def gzip_file(filename) -> Iterator[BinaryIO]:
    with gzip.GzipFile(absolute_path(filename), "rb") as fh:
        yield fh


@pytest.fixture
def ext4_bin() -> Iterator[BinaryIO]:
    yield from gzip_file("data/ext4.bin.gz")


@pytest.fixture
def ext4_sparse_bin() -> Iterator[BinaryIO]:
    yield from gzip_file("data/ext4_sparse.bin.gz")
