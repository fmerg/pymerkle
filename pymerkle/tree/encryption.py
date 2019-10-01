"""
Provides the encryption interface for Merkle-trees
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

class Encryptor(object, metaclass=ABCMeta):
    """
    Encryption interface for Merkle-trees
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

        :param record: the record whose hash is to be stored into a new leaf
        :type record: str or bytes
        :returns: ``0`` if the provided ``record`` was successfully encrypted,
                ``1`` othewise
        :rtype: int

        .. note:: Value ``1`` indicates that ``UndecodableRecord``
            has been implicitely raised
        """
        try:
            self.update(record=record)
        except UndecodableRecord:
            return 1
        return 0


    def encryptFileContent(self, file_path):
        """
        Encrypts the provided file as a single new leaf into the Merkle-tree

        It updates the Merkle-tree with *one* newly-created leaf (cf. doc of
        the ``.update()`` method) storing the digest of the provided
        file's content

        :param file_path: relative path of the file under encryption with
                respect to the current working directory
        :type file_path: str
        :returns: ``0`` if the provided file was successfully encrypted,
            ``1`` othewise
        :rtype: int

        .. note:: Value ``1`` means that ``UndecodableRecord``
            has been implicitely raised
        """
        with open(os.path.abspath(file_path), mode='r') as _file:
            with contextlib.closing(
                mmap.mmap(
                    _file.fileno(),
                    0,
                    access=mmap.ACCESS_READ
                )
            ) as _buffer:
                try:
                    self.update(record=_buffer.read())
                except UndecodableRecord:
                    return 1
                return 0


    def encryptFilePerLog(self, file_path):
        """
        Per log encryption of the provided file into the Merkle-tree

        It successively updates the Merkle-tree (cf. doc of the ``.update()``
        method) with each line of the provided file in the respective order

        :param file_path: relative path of the file under enryption with
            respect to the current working directory
        :type file_path: str
        :returns: ``0`` if the provided file was successfully encrypted,
                ``1`` othewise
        :rtype: int

        .. note:: value ``1`` means that some line of the provided file is
            undecodable under the Merkle-tree's encoding type (that is,
            a ``UnicodeDecodeError`` has been implicitely raised)
        """
        absolute_file_path = os.path.abspath(file_path)
        with open(absolute_file_path, mode='r') as _file:
            buffer = mmap.mmap(
                _file.fileno(),
                0,
                access=mmap.ACCESS_READ
            )

        # Extract logs
        records = []
        readline = buffer.readline
        append = records.append
        while 1:
            record = readline()
            if not record:
                break
            try:
                record = record.decode(self.encoding)
            except UnicodeDecodeError:
                return 1
            append(record)

        # Perform line by line encryption
        tqdm.write('')
        update = self.update
        for record in tqdm(records, desc='Encrypting log file', total=len(records)):
            update(record=record)
        tqdm.write('Encryption complete\n')
        return 0


    def encryptObject(self, object, sort_keys=False, indent=0):
        """
        Encrypts the provided object as a single new leaf into the Merkle-tree

        It updates (cf. doc of the ``.update()`` method) the Merkle-tree with
        *one* newly-created leaf storing the digest of the provided object's
        stringification

        :param object: the JSON entity under encryption
        :type objec: dict
        :param sort_keys: [optional] Defaults to ``False``. If ``True``, then
            the object's keys get alphabetically sorted before its stringification.
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
            the object's keys get alphabetically sortedcbefore its stringification
        :type sort_keys: bool
        :param indent: [optional] Defaults to ``0``. Specifies key indentation
                upon stringification of the object under encryption
        :type indent: sint

        :raises JSONDecodeError: if the specified file could not be deserialized
        """
        with open(os.path.abspath(file_path), 'rb') as _file:
            object = json.load(_file)
        self.update(
            record=json.dumps(object, sort_keys=sort_keys, indent=indent))


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
        with open(os.path.abspath(file_path), 'rb') as _file:
            objects = json.load(_file)

        if type(objects) is not list:
            raise WrongJSONFormat

        update = self.update
        for _object in objects:
            update(record=json.dumps(_object, sort_keys=sort_keys, indent=indent))
