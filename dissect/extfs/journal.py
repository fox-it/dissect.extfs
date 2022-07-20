import datetime
import io

from dissect.util.stream import RangeStream

from dissect.extfs.c_jdb2 import c_jdb2
from dissect.extfs.exceptions import Error


class JDB2:
    def __init__(self, fh):
        self.fh = fh

        sb = c_jdb2.journal_superblock(self.fh)
        self.sb = sb

        if sb.s_header.h_magic != c_jdb2.JBD2_MAGIC_NUMBER:
            raise Error("Not a valid JDB2 journal (magic mismatch)")

        self.block_size = sb.s_blocksize
        self._blocktag = c_jdb2.journal_block_tag
        if sb.s_feature_incompat & c_jdb2.JBD2_FEATURE_INCOMPAT_CSUM_V3:
            self._blocktag = c_jdb2.journal_block_tag3

    def read_block(self, block, count=1):
        offset = block * self.block_size
        self.fh.seek(offset)
        return self.fh.read(self.block_size * count)

    def commits(self):
        cur_seq = None

        for block in self.commits_all():
            if not cur_seq:
                cur_seq = block.sequence

            if block.sequence == cur_seq:
                cur_seq += 1
                yield block

    def commits_all(self):
        desc_buf = {}

        for block in self.walk():
            if isinstance(block, DescriptorBlock):
                if block.sequence not in desc_buf:
                    desc_buf[block.sequence] = []

                desc_buf[block.sequence].append(block)
            elif isinstance(block, CommitBlock):
                block.descriptors = desc_buf.get(block.sequence, [])

                if block.sequence in desc_buf:
                    del desc_buf[block.sequence]

                yield block

    def walk(self):
        block_num = self.sb.s_first

        while block_num < self.sb.s_maxlen - 1:
            offset = block_num * self.block_size
            self.fh.seek(offset)

            header = c_jdb2.journal_header(self.fh)
            if header.h_magic != c_jdb2.JBD2_MAGIC_NUMBER:
                block_num += 1
                continue

            if header.h_blocktype == c_jdb2.JBD2_DESCRIPTOR_BLOCK:
                yield DescriptorBlock(self, header, block_num)
            elif header.h_blocktype == c_jdb2.JBD2_COMMIT_BLOCK:
                self.fh.seek(offset)
                yield CommitBlock(self, c_jdb2.commit_header(self.fh), block_num)
            elif header.h_blocktype == c_jdb2.JBD2_REVOKE_BLOCK:
                pass

            block_num += 1


class DescriptorBlock:
    def __init__(self, jdb2, header, block):
        self.jdb2 = jdb2
        self.header = header
        self.journal_block = block

        self.sequence = self.header.h_sequence

    def tags(self):
        self.jdb2.fh.seek((self.journal_block * self.jdb2.block_size) + c_jdb2.journal_header.size)

        block_count = 1
        while True:
            tag = self.jdb2._blocktag(self.jdb2.fh)
            yield DescriptorBlockTag(self, tag, self.journal_block + block_count)

            if tag.t_flags & c_jdb2.JBD2_FLAG_LAST_TAG:
                break

            if not tag.t_flags & c_jdb2.JBD2_FLAG_SAME_UUID:
                self.jdb2.fh.seek(16, io.SEEK_CUR)
            block_count += 1

    def __repr__(self):
        return f"<descriptor_block sequence={self.sequence} journal_block={self.journal_block}>"


class DescriptorBlockTag:
    def __init__(self, descriptor, tag, journal_block):
        self.descriptor = descriptor
        self.tag = tag
        self.journal_block = journal_block

        self.block = (self.tag.t_blocknr_high << 32) | self.tag.t_blocknr

    def open(self):
        block_size = self.descriptor.jdb2.block_size
        return RangeStream(self.descriptor.jdb2.fh, self.journal_block * block_size, block_size)

    def __repr__(self):
        return f"<block_tag block={self.block} journal_block={self.journal_block} flags=0x{self.tag.t_flags:x}>"


class CommitBlock:
    def __init__(self, jdb2, header, journal_block, descriptors=None):
        self.jdb2 = jdb2
        self.header = header
        self.journal_block = journal_block
        self.descriptors = descriptors if descriptors else []

        self.sequence = self.header.h_sequence
        self.ts = datetime.datetime.utcfromtimestamp(self.header.h_commit_sec)
        self.ts += datetime.timedelta(microseconds=self.header.h_commit_nsec // 1000)

    def __repr__(self):
        return (
            f"<commit sequence={self.sequence} journal_block={self.journal_block} "
            f"ts={self.ts} num_descriptors={len(self.descriptors)}>"
        )
