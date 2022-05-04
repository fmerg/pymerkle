"""Provides high-level encryption interface for Merkle-trees
"""

from abc import ABCMeta, abstractmethod
import os
import json
import mmap
import contextlib
from tqdm import tqdm

from pymerkle.exceptions import UndecodableRecord

abspath = os.path.abspath


class Encryptor(object, metaclass=ABCMeta):
    """High-level encryption interface for Merkle-trees
    """

    @abstractmethod
    def update(self, record):
        """
        """

    def encrypt_record(self, record):
        """Updates the Merkle-tree by storing the checksum of the provided record
        into a newly-created leaf.

        :param record: Record whose checksum is to be stored into a new leaf
        :type record: str or bytes

        :raises UndecodableRecord: if the tree does not accept arbitrary bytes
            and the provided record is out of its configured encoding type
        """
        try:
            self.update(record=record)
        except UndecodableRecord:
            raise

    def encrypt_file_content(self, filepath):
        """Encrypts the provided file as a single new leaf into the Merkle-tree.

        Updates the Merkle-tree with *one* newly-created leaf storing the
        checksum of the provided file's content.

        :param filepath: Relative path of the file under encryption with
                respect to the current working directory
        :type filepath: str

        :raises UndecodableRecord: if the tree does not accept arbitrary bytes
            and the provided files contains sequences out of the tree's
            configured encoding type
        """
        with open(abspath(filepath), mode='r') as f:
            with contextlib.closing(
                mmap.mmap(
                    f.fileno(),
                    0,
                    access=mmap.ACCESS_READ
                )
            ) as buff:
                try:
                    self.update(record=buff.read())
                except UndecodableRecord:
                    raise

    def encrypt_file_per_log(self, filepath):
        """Per log encryption of the provided file into the Merkle-tree.

        Successively updates the tree with each line of the provided
        file in respective order

        :param filepath: Relative path of the file under enryption with
            respect to the current working directory
        :type filepath: str

        :raises UndecodableRecord: if the tree does not accept arbitrary bytes
            and the provided files contains sequences out of the tree's
            configured encoding type
        """
        absolute_filepath = abspath(filepath)
        with open(absolute_filepath, mode='r') as f:
            buffer = mmap.mmap(
                f.fileno(),
                0,
                access=mmap.ACCESS_READ
            )

        # Extract logs
        records = []
        readline = buffer.readline
        append = records.append
        if not self.raw_bytes:
            # Check that no line of the provided file is outside
            # the tree's encoding type and discard otherwise
            encoding = self.encoding
            while 1:
                record = readline()
                if not record:
                    break
                try:
                    record = record.decode(encoding)
                except UnicodeDecodeError as err:
                    raise UndecodableRecord(err)
                append(record)
        else:
            # No need to check anything, just load all lines
            while 1:
                record = readline()
                if not record:
                    break
                append(record)

        # Perform line by line encryption
        tqdm.write('')
        update = self.update
        for record in tqdm(records, desc='Encrypting file per log', total=len(records)):
            update(record=record)
        tqdm.write('Encryption complete\n')
