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
                for chain in headers._chains:
                    try:
                        chain.tip.version
                    except AttributeError:
                        # NOTE(rt12) It appears there is some bug in pickle.load where the
                        #     `chain.tip` object becomes a broken `attrs` object where the
                        #     attributes are missing. This data works for the same deterministic
                        #     Python version and dependency installation, just not on my computer.
                        #     This is very likely a bug in pickle that is trigged by my arch.
                        logger.error("Error deserialising chain tip header (chain first height: "
                            "%d); forceably replacing it as a workaround", chain.first_height)
                        header_index = chain._header_indices[-1]
                        chain.tip = headers.network.deserialized_header(
                            headers._storage[header_index], -1)
                        prev_header, prev_chain = headers.lookup(chain.tip.prev_hash)
                        chain.tip.height = prev_header.height + 1
                    else:
                        # Validate that the tip deserialised well enough to have the right height.
                        prev_header, prev_chain = headers.lookup(chain.tip.prev_hash)
                        assert chain.tip.height == prev_header.height + 1
                return headers

            logger.debug("cached chain data file does not match: %s", headerfile_hash.hex())
    else:
        logger.debug("cached chain data file not found")

    return cast(Headers, Headers(coin, file_path, checkpoint))

