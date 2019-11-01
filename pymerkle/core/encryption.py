"""
Provides high-level encryption interface for Merkle-trees
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
    """
    High-level encryption interface for Merkle-trees
    """

    @abstractmethod
    def update(self, record):
        """
        """

    def encryptRecord(self, record):
        """
        Updates the Merkle-tree by storing the checksum of the provided record
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


    def encryptFileContent(self, file_path):
        """
        Encrypts the provided file as a single new leaf into the Merkle-tree.

        Updates the Merkle-tree with *one* newly-created leaf storing the
        checksum of the provided file's content.

        :param file_path: Relative path of the file under encryption with
                respect to the current working directory
        :type file_path: str

        :raises UndecodableRecord: if the tree does not accept arbitrary bytes
            and the provided files contains sequences out of the tree's
            configured encoding type
        """
        with open(abspath(file_path), mode='r') as __file:
            with contextlib.closing(
                mmap.mmap(
                    __file.fileno(),
                    0,
                    access=mmap.ACCESS_READ
                )
            ) as __buffer:
                try:
                    self.update(record=__buffer.read())
                except UndecodableRecord:
                    raise


    def encryptFilePerLog(self, file_path):
        """
        Per log encryption of the provided file into the Merkle-tree.

        Successively updates the tree with each line of the provided
        file in respective order

        :param file_path: Relative path of the file under enryption with
            respect to the current working directory
        :type file_path: str

        :raises UndecodableRecord: if the tree does not accept arbitrary bytes
            and the provided files contains sequences out of the tree's
            configured encoding type
        """
        absolute_file_path = abspath(file_path)
        with open(absolute_file_path, mode='r') as __file:
            buffer = mmap.mmap(
                __file.fileno(),
                0,
                access=mmap.ACCESS_READ
            )

        # Extract logs
        records = []
        readline = buffer.readline
        append = records.append
        if not self.raw_bytes:
            # ~ Check that no line of the provided file is outside
            # ~ the tree's encoding type and discard otherwise
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
            # ~ No need to check anything, just load all lines
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


    def encryptJSON(self, object, sort_keys=False, indent=0):
        """
        Encrypts the provided JSON entity as a single new leaf into the
        Merkle-tree.

        Updates tree with *one* newly-created leaf storing the checksum of the
        provided object's stringification.

        :param object: JSON entity under encryption
        :type objec: dict
        :param sort_keys: [optional] Defaults to *False*. If *True*, then
            the object's keys are alphabetically sorted before its
            stringification.
        :type sort_keys: bool
        :param indent: [optional] Defaults to 0. Specifies key indentation
            upon stringification of the provided JSON.
        :type indent: int
        """
        self.update(
            record=json.dumps(object, sort_keys=sort_keys, indent=indent))


    def encryptJSONFromFile(self, file_path, sort_keys=False, indent=0):
        """
        Encrypts the object from within the provided *.json* file as a
        single new leaf into the Merkle-tree.

        Updates the tree with *one* newly-created leaf storing the checksum of
        the provided JSON's stringification.

        :param file_path: Relative path of a *.json* file with respect to the
            current working directory
        :type file_path: str
        :param sort_keys: [optional] Defaults to *False*. If *True*, then
            the object's keys are alphabetically sorted before its
            stringification
        :type sort_keys: bool
        :param indent: [optional] Defaults to 0. Specifies key indentation
                upon stringification of the object under encryption
        :type indent: sint

        :raises JSONDecodeError: if the specified file could not be deserialized
        """
        try:
            with open(abspath(file_path), 'rb') as __file:
                object = json.load(__file)
        except json.JSONDecodeError:
            raise
        record = json.dumps(object, sort_keys=sort_keys, indent=indent)
        self.update(record=record)
