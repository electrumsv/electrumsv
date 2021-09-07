from hashlib import sha256
import os
import pickle
from typing import cast

from bitcoinx import CheckPoint, Headers, Network

from .logs import logs


logger = logs.get_logger("app_state")


def hash_headerfile(file_path: str) -> bytes:
    sha256_hash = sha256()
    hf = open(file_path, "rb")
    try:
        while True:
            headers_chunk = hf.read(65536)
            if not headers_chunk:
                break
            sha256_hash.update(headers_chunk)
    finally:
        hf.close()
    return sha256_hash.digest()


def write_cached_headers(headers: Headers) -> None:
    file_path = headers._storage.filename
    headerfile_hash = hash_headerfile(file_path)

    chaindata_filename = file_path +".chain_data"
    if os.path.exists(chaindata_filename):
        with open(chaindata_filename, "rb") as f:
            expected_headerfile_hash = f.read(32)
        if headerfile_hash == expected_headerfile_hash:
            logger.debug("header file is unchanged; skipping write")
            return

    with open(chaindata_filename, "wb") as f:
        f.write(headerfile_hash)
        pickle.dump(headers, f)


def read_cached_headers(coin: Network, file_path: str, checkpoint: CheckPoint) -> Headers:
    chaindata_filename = file_path +".chain_data"
    if os.path.exists(chaindata_filename):
        logger.debug("cached chain data file found")
        headerfile_hash = hash_headerfile(file_path)

        with open(chaindata_filename, "rb") as f:
            expected_headerfile_hash = f.read(32)
            if expected_headerfile_hash == headerfile_hash:
                logger.debug("cached chain data file matches: %s", headerfile_hash.hex())
                headers = cast(Headers, pickle.load(f))
                headers.common_setup(coin, file_path, checkpoint)
                return headers

            logger.debug("cached chain data file does not match: %s", headerfile_hash.hex())
    else:
        logger.debug("cached chain data file not found")

    return cast(Headers, Headers.from_file(coin, file_path, checkpoint))

