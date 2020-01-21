try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import hashlib
import json
import logging
import zipfile

from pygments import highlight, lexers, formatters

logger = logging.getLogger('koodous-api')

try:
    from androguard.core.bytecodes.apk import APK
except ImportError:
    APK = None


def sha256(filepath):
    """
        Function to calculate sha256 of a file in disk
        Params:
            - filepath (str): Path where the file is stored
        Return:
            - sha256 hash calculated
    """
    fd = open(filepath, 'rb')
    hasher_256 = hashlib.sha256()
    chunk = fd.read(1024)
    while chunk:
        hasher_256.update(chunk)
        chunk = fd.read(1024)

    fd.close()
    return hasher_256.hexdigest()


def unpack(filepath, dst):
    """
        Function to generate a file from uncompressed file of an APK.
        Params:
            - filepath (str): Path where the APK is stored
            - dst (str): Path where the file generated will be saved.
        Return:
            - True is all was done.
            - False in case of error.
    """

    to_ret = True

    with open(filepath, 'rb') as fd:
        content = fd.read()

    try:
        zipped = zipfile.ZipFile(filename)
        for name in zipped.namelist():
            content += ' ' + zipped.read(name)

    except:
        to_ret = False

    with open(dst, 'wb') as fd:
        fd.write(content)

    return to_ret


def is_apk_file(filepath):
    """
        Function to check if a file is an APK
        Params:
            - filepath (str): Path where is the file to check
        Return:
            True (bool) if the file is an APK
            False (bool) otherwise
    """
    try:
        zip = zipfile.ZipFile(open(filepath))
        for i in zip.namelist():
            if i == 'AndroidManifest.xml':
                return True

        return False
    except:
        return False


def is_apk(content):
    """
        Function to check if a content is an APK
        Params:
            - content (str): Binary data of the file to check
        Return:
            True (bool) if the file is an APK
            False (bool) otherwise
    """
    try:
        zip = zipfile.ZipFile(StringIO.StringIO(content))
        for i in zip.namelist():
            if i == 'AndroidManifest.xml':
                return True

        return False
    except:
        return False


def pygmentize(output, lexer=lexers.JsonLexer()):
    """
    Pygmentize any string for pretty terminal printing.

    :param lexer: a lexer from `pygments.lexers`
    :param output: the string to print
    :return: the pygmentized string
    """

    return highlight(unicode(output, 'UTF-8'), lexer,
                     formatters.TerminalFormatter())


def pygmentize_json(obj, sort_keys=True, indent=4):
    """
    Pretty print a JSON string from a dictionary

    :param indent: indentation spaces
    :param sort_keys: whether to sort the keys
    :param obj: a dict to build the JSON output string from
    :return: a pygmentized string
    """
    return pygmentize(json.dumps(obj, sort_keys=sort_keys, indent=indent))


def is_apk(filepath):
    """
    Check whether filepath is pointing to a readable, valid APK file.

    Requires androguard. If androguard is not installed, fallsback to
    returning always `True`.

    :param filepath: path to file
    :return: `True` if the path is pointing to a readable, valid APK file
    """
    if not APK:
        return True

    try:
        APK(filepath)
        return True
    except Exception as ex:
        logger.warning('File %s does not seem a valid APK file', filepath)

    return False