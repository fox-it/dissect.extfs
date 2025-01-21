from __future__ import annotations

import datetime
import gzip
import stat
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO
from unittest.mock import call, patch

import pytest

from dissect.extfs.c_ext import c_ext
from dissect.extfs.extfs import EXT4, ExtFS, INode

if TYPE_CHECKING:
    from logging import Logger


def test_ext4(ext4_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_bin)

    assert extfs.type == EXT4
    assert extfs.block_count == 2048
    assert extfs.groups_count == 1
    assert extfs.groups_offset == 2048
    assert extfs._group_desc_size == 64
    assert str(extfs.uuid) == "ab98e08e-e2da-4bc9-bfc6-1ac5eafb1001"
    assert extfs.volume_name == ""
    assert extfs.last_mount == "/tmp/mnt"

    root = extfs.root
    assert root.size == 1024
    assert root.filetype == stat.S_IFDIR
    assert root.filename == "/"
    assert sorted(root.dirlist().keys()) == [".", "..", "lost+found", "test_file", "xattr_cap"]

    inode = extfs.get("test_file")
    assert inode.size == 26
    assert inode.filetype == stat.S_IFREG
    assert inode.filename == "test_file"
    assert inode.open().read() == b"dissect test file in ext4\n"

    assert inode.atime == datetime.datetime(2018, 5, 29, 8, 57, 58, tzinfo=datetime.timezone.utc)
    assert inode.atime_ns == 1527584278000000000

    assert extfs.journal
    assert len(list(extfs.journal.commits())) == 2


def test_xattr(ext4_bin: BinaryIO) -> None:
    e = ExtFS(ext4_bin)

    inode = e.get("xattr_cap")

    xattrs = inode.xattr
    assert len(xattrs) == 2
    assert xattrs[0].name == "security.selinux"
    assert xattrs[0].value == b"unconfined_u:object_r:unlabeled_t:s0\x00"
    assert xattrs[1].name == "security.capability"
    assert xattrs[1].value == b"\x01\x00\x00\x02\x00\x04@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def test_sparse(ext4_sparse_bin: BinaryIO) -> None:
    extfs = ExtFS(ext4_sparse_bin)

    sparse_start = extfs.get("sparse_start")
    assert sparse_start.size == 0x3C000
    assert sparse_start.dataruns() == [(None, 160), (1833, 80)]

    sparse_hole = extfs.get("sparse_hole")
    assert sparse_hole.size == 0x3C000
    assert sparse_hole.dataruns() == [(1537, 80), (None, 80), (1697, 80)]

    sparse_end = extfs.get("sparse_end")
    assert sparse_end.size == 0x28000
    assert sparse_end.dataruns() == [(1793, 40), (None, 120)]

    sparse_all = extfs.get("sparse_all")
    assert sparse_all.size == 0x500000
    assert sparse_all.dataruns() == [(None, 5120)]


@pytest.mark.parametrize(
    "image_file",
    [
        ("tests/data/ext4_symlink_test1.bin.gz"),
        ("tests/data/ext4_symlink_test2.bin.gz"),
        ("tests/data/ext4_symlink_test3.bin.gz"),
    ],
)
def test_symlinks(image_file: str) -> None:
    path = "/path/to/dir/with/file.ext"
    expect = b"resolved!\n"

    def resolve(node: INode) -> INode:
        while node.filetype == stat.S_IFLNK:
            node = node.link_inode
        return node

    with gzip.open(image_file, "rb") as disk:
        assert resolve(ExtFS(disk).get(path)).open().read() == expect


@patch("dissect.extfs.extfs.INode.open", return_value=BytesIO(b"\x00" * 16))
@patch("dissect.extfs.extfs.log", create=True, return_value=None)
@patch("dissect.extfs.extfs.ExtFS")
def test_infinite_loop_protection(ExtFS: ExtFS, log: Logger, *args) -> None:
    ExtFS.sb.s_inodes_count = 69
    ExtFS._dirtype = c_ext.ext2_dir_entry_2
    inode = INode(ExtFS, 1, filetype=stat.S_IFDIR)
    inode._size = 16
    for _ in inode.iterdir():
        pass
    assert call.critical("Zero-length directory entry in %s (offset 0x%x)", inode, 0) in log.mock_calls
