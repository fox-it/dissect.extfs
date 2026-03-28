from __future__ import annotations

import datetime
import stat
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO
from unittest.mock import MagicMock, call, patch

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


def test_symlinks(ext4_symlink_bin: BinaryIO) -> None:
    path = "/path/to/dir/with/file.ext"

    extfs = ExtFS(ext4_symlink_bin)
    assert extfs.get(path).link == "../../../../other/path/source/to/my/file.ext"


@patch("dissect.extfs.extfs.INode.open", return_value=BytesIO(b"\x00" * 16))
@patch("dissect.extfs.extfs.log", create=True, return_value=None)
@patch("dissect.extfs.extfs.ExtFS")
def test_infinite_loop_protection(ExtFS: ExtFS, log: Logger, *args) -> None:
    ExtFS.sb.s_inodes_count = 69
    ExtFS._dirtype = c_ext.ext2_dir_entry_2
    inode = INode(ExtFS, 1, filetype=stat.S_IFDIR)
    inode.size = 16
    for _ in inode.iterdir():
        pass
    assert call.critical("Zero-length directory entry in %s (offset 0x%x)", inode, 0) in log.mock_calls


def test_encrypted_inodes(ext4_bin: BinaryIO) -> None:
    ext4 = ExtFS(ext4_bin)
    # To pass the sanity check of valid inode numbers
    ext4.sb.s_inodes_count = 69 * 100000

    inode_buf = bytes.fromhex(
        "c04100000010000030d2b16730d2b16730d2b16700000000000002001000000080080800080000000af3010004000000000000000000000001000000a20209000000000000000000000000000000000000000000000000000000000000000000000000009683a8a8af0209000000000000000000000000000000000000000000200000000824067b08e0707208e0707230d2b16708e070720000000000000000000002ea0109340000000000280000000000000063000000000000000000000000000000000000000000000000000000000000000000000002010402000000001747e659400c2e395be66eaef68d7ddc584d0af27ac5994c76ec2bc44ddc7441"
    )
    inode_content = bytes.fromhex(
        "6d4002000c0001022e0000006c4002000c0002022e2e00006e40020018001001a04f3bc0c3bcbe03c592aa53d8e9a93c6f40020018001001c559d36dd8fd68184ce492917cd932ec7040020028002001c33e8de54b7f678cd37ea5cedae7c5026b8486e1d59870d8ccf329ef0bd29f8171400200900f100150f9fb45eafc69f6dac004b2cb9ff09e000000"
    )
    decryptor = MagicMock()
    ext4._get_inode_decryptor = MagicMock(return_value=decryptor)

    inode = INode(ext4, 69, "encrypted")
    inode.inode = c_ext.ext4_inode(inode_buf)
    assert inode.is_encrypted
    assert inode.filetype == stat.S_IFDIR
    inode.open = MagicMock(return_value=BytesIO(inode_content))

    inode.listdir()
    # Decrypt filename should have been invoked for an encrypted inode
    assert sorted(decryptor.decrypt_filename.call_args_list) == [
        call(b"."),
        call(b".."),
        call(b"P\xf9\xfbE\xea\xfci\xf6\xda\xc0\x04\xb2\xcb\x9f\xf0\x9e"),
        call(b"\xa0O;\xc0\xc3\xbc\xbe\x03\xc5\x92\xaaS\xd8\xe9\xa9<"),
        call(
            b"\xc3>\x8d\xe5K\x7fg\x8c\xd3~\xa5\xce\xda\xe7\xc5\x02k\x84\x86\xe1\xd5\x98p\xd8\xcc\xf3)\xef\x0b\xd2\x9f\x81"
        ),
        call(b"\xc5Y\xd3m\xd8\xfdh\x18L\xe4\x92\x91|\xd92\xec"),
    ]
    # Open decrypt should not be used for directories
    decryptor.open_decrypt.assert_not_called()

    encrypted_file_inode = INode(ext4, 42, "encrypted_file")
    encrypted_file_inode.inode = c_ext.ext4_inode(
        bytes.fromhex(
            "808100005c00000030d2b16730d2b16730d2b16700000000000001001000000080080800030000000af30100040000000000000000000000010000001b0403000000000000000000000000000000000000000000000000000000000000000000000000004d29f15f3c02090000000000000000000000000000000000000000002000000008e0707208e0707208e0707230d2b16708e070720000000000000000000002ea0109340000000000280000000000000063000000000000000000000000000000000000000000000000000000000000000000000002010402000000001747e659400c2e395be66eaef68d7ddc86ff04b1a52eb83649ea8cdab4ec827f"
        )
    )

    assert inode.is_encrypted
    assert encrypted_file_inode.filetype == stat.S_IFREG
    encrypted_file_inode.open()
    decryptor.open_decrypt.assert_called_once()
