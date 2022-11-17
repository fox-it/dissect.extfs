import datetime
import gzip
import stat

import pytest

from dissect.extfs import extfs


def test_ext4(ext4_simple):
    e = extfs.ExtFS(ext4_simple)

    assert e.type == extfs.EXT4
    assert e.block_count == 2048
    assert e.groups_count == 1
    assert e.groups_offset == 2048
    assert e._group_desc_size == 64
    assert str(e.uuid) == "ab98e08e-e2da-4bc9-bfc6-1ac5eafb1001"
    assert e.last_mount == "/tmp/mnt"

    root = e.root
    assert root.size == 1024
    assert root.filetype == stat.S_IFDIR
    assert root.filename == "/"
    assert sorted(root.dirlist().keys()) == [".", "..", "lost+found", "test_file", "xattr_cap"]

    inode = e.get("test_file")
    assert inode.size == 26
    assert inode.filetype == stat.S_IFREG
    assert inode.filename == "test_file"
    assert inode.open().read() == b"dissect test file in ext4\n"

    assert inode.atime == datetime.datetime(2018, 5, 29, 8, 57, 58, tzinfo=datetime.timezone.utc)
    assert inode.atime_ns == 1527584278000000000

    assert e.journal
    assert len(list(e.journal.commits())) == 2


def test_xattr(ext4_simple):
    e = extfs.ExtFS(ext4_simple)

    inode = e.get("xattr_cap")

    xattrs = inode.xattr
    assert len(xattrs) == 2
    assert xattrs[0].name == "security.selinux"
    assert xattrs[0].value == b"unconfined_u:object_r:unlabeled_t:s0\x00"
    assert xattrs[1].name == "security.capability"
    assert xattrs[1].value == b"\x01\x00\x00\x02\x00\x04@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


@pytest.mark.parametrize(
    "image_file",
    [
        ("tests/data/ext4_symlink_test1.bin.gz"),
        ("tests/data/ext4_symlink_test2.bin.gz"),
        ("tests/data/ext4_symlink_test3.bin.gz"),
    ],
)
def test_symlinks(image_file):

    path = "/path/to/dir/with/file.ext"
    expect = b"resolved!\n"

    def resolve(node):
        while node.filetype == stat.S_IFLNK:
            node = node.link_inode
        return node

    with gzip.open(image_file, "rb") as disk:
        assert resolve(extfs.ExtFS(disk).get(path)).open().read() == expect
