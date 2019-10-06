"""
Provides high-level encryption interface for Merkle-trees
"""

from abc import ABCMeta, abstractmethod
import os
import json
import mmap
import contextlib
from tqdm import tqdm

from pymerkle.exceptions import (LeafConstructionError, NoChildException,
    EmptyTreeException, NoPathException, InvalidProofRequest,
    NoSubtreeException, NoPrincipalSubroots, InvalidTypes,
    InvalidComparison, WrongJSONFormat, UndecodableRecord,
    UnsupportedEncoding, UnsupportedHashType)

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
        Updates the Merkle-tree by storing the digest of the provided record
        into a newly-created leaf, restrucuring the tree appropriately and
        recalculating all necessary interior hashes

        :param record: the record whose digest is to be stored into a new leaf
        :type record: str or bytes
        :returns: ``True`` if the provided record was successfully encrypted
        :rtype: bool

        :raises UndecodableRecord: if the tree does not accept arbitrary bytes
            and the provided record is out of its configured encoding type
        """
        try:
            self.update(record=record)
        except UndecodableRecord:
            raise
        return True


    def encryptFileContent(self, file_path):
        """
        Encrypts the provided file as a single new leaf into the Merkle-tree

        It updates the Merkle-tree with *one* newly-created leaf (cf. doc of
        the ``.update()`` method) storing the digest of the provided
        file's content

        :param file_path: relative path of the file under encryption with
                respect to the current working directory
        :type file_path: str
        :returns: ``True`` if the provided file was successfully encrypted
        :rtype: bool

        :raises UndecodableRecord: if the tree does not accept arbitrary bytes
            and the provided files contains sequences is out of the tree's
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
                return True


    def encryptFilePerLog(self, file_path):
        """
        Per log encryption of the provided file into the Merkle-tree

        It successively updates the Merkle-tree (cf. doc of the ``.update()``
        method) with each line of the provided file in the respective order

        :param file_path: relative path of the file under enryption with
            respect to the current working directory
        :type file_path: str
        :returns: ``True`` if the provided file was successfully encrypted
        :rtype: bool

        :raises UndecodableRecord: if the tree does not accept arbitrary bytes
            and the provided files contains sequences is out of the tree's
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
        return True


    def encryptObject(self, object, sort_keys=False, indent=0):
        """
        Encrypts the provided object as a single new leaf into the Merkle-tree

        It updates (cf. doc of the ``.update()`` method) the Merkle-tree with
        *one* newly-created leaf storing the digest of the provided object's
        stringification

        :param object: the JSON entity under encryption
        :type objec: dict
        :param sort_keys: [optional] Defaults to ``False``. If ``True``, then
            the object's keys get alphabetically sorted before its
            stringification.
        :type sort_keys: bool
        :param indent: [optional] Defaults to ``0``. Specifies key indentation
            upon stringification of the provided object.
        :type indent: int
        """
        self.update(
            record=json.dumps(object, sort_keys=sort_keys, indent=indent))


    def encryptObjectFromFile(self, file_path, sort_keys=False, indent=0):
        """
        Encrypts the object from within the provided ``.json`` file as a
        single new leaf into the Merkle-tree

        The Merkle-tree gets updated with *one* newly-created leaf (cf. doc of
        the ``.update()`` method) storing the digest of the stringification of
        the object loaded from within the provided file

        :param file_path: relative path of a ``.json`` file with respect to the
            current working directory, containing *one* JSON entity
        :type file_path: str
        :param sort_keys: [optional] Defaults to ``False``. If ``True``, then
            the object's keys get alphabetically sorted before its stringification
        :type sort_keys: bool
        :param indent: [optional] Defaults to ``0``. Specifies key indentation
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


    def encryptFilePerObject(self, file_path, sort_keys=False, indent=0):
        """
        Encrypts per object the data of the provided ``.json``
        file into the Merkle-tree

        It successively updates the Merkle-tree (cf. doc of the ``.update()``
        method) with each newly created leaf storing the digest of the
        respective JSON entity in the list loaded from the provided file

        :param file_path: relative path of a ``.json`` file with respect to the
            current working directory, containing a *list* of JSON entities
        :type file_path: str
        :param sort_keys: [optional] Defaults to ``False``. If ``True``, then
            the all objects' keys get alphabetically sorted before stringification
        :type sort_keys: bool
        :param indent: [optional] Defaults to ``0``. Specifies uniform key
            indentation upon stringification of objects
        :type indent: int

        :raises JSONDecodeError: if the specified file could not be deserialized
        :raises WrongJSONFormat: if the JSON object loaded from within the
            provided file is not a list
        """
        try:
            with open(abspath(file_path), 'rb') as __file:
                objects = json.load(__file)
        except json.JSONDecodeError:
            raise

        if type(objects) is not list:
            raise WrongJSONFormat

        update = self.update
        dumps = json.dumps
        for object in objects:
            record = dumps(object, sort_keys=sort_keys, indent=indent)
            update(record=record)
