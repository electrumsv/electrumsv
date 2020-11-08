import pytest

from electrumsv.constants import ScriptType
from electrumsv.script import AccumulatorMultiSigOutput
from electrumsv.transaction import create_script_sig, NO_SIGNATURE

from bitcoinx import PrivateKey


private_keys_hex = [
    'c9fd5a124cf87d7c7ca99c1059ce8c6331ee158d2b9fadfbf5dd5a2fb430e6b1',
    'a133efcbef68a8951ed76f95c59c06a013a59531dde0c39c1d10e9a10ca15319',
    'd64fa9448233475d32c1cd6d7a74c2e76814845666231aae3ae8ce008cc21aac',
]

signatures_hex = [
    '3045022100a76b71256b29303c6c0b68864f1b57e2e42e7bf619ec79549f0fd9efc1da438602205a288879c589bc'
    'c1c873439bc354377de6fd24cb287fcc79c25997642bf41ee8',
    '30440220774e912b64b9ecc212edcd2d2f10003ddae023e28f18e20acb606354c67331ea0220626e6bd8a4036f3c'
    '14972aed332a3dab4015f0566aa7727f22aee1f247649b5c',
    '3045022100d745a1ff57007960002b864daee0bd090d4c17e28900c81ed74e46e78e98ebf102205de658ef4d1cc7'
    '45d6e39a076a7c9ab80ae2ab027f815d62eb0e0f0b5c9094c6',
]

signing_masks_of2 = tuple((i, j) for i in range(2) for j in range(2))
accumulator_scripts_of2 = {
    (0, 0): '0000',
    (0, 1): '4630440220774e912b64b9ecc212edcd2d2f10003ddae023e28f18e20acb606354c67331ea0220626e6b'
    'd8a4036f3c14972aed332a3dab4015f0566aa7727f22aee1f247649b5c2103ffb581fd5edab4eaec5d10a221bf5d'
    '8e0afad4b5098e75a776a1cb7aa80db4665100',
    (1, 0): '00473045022100a76b71256b29303c6c0b68864f1b57e2e42e7bf619ec79549f0fd9efc1da438602205a'
    '288879c589bcc1c873439bc354377de6fd24cb287fcc79c25997642bf41ee82103bc8c8860fb814ae77fd256cff8'
    'c92260c9ec515ff33176148f1e288e868cc7bb51',
    (1, 1): '4630440220774e912b64b9ecc212edcd2d2f10003ddae023e28f18e20acb606354c67331ea0220626e6b'
    'd8a4036f3c14972aed332a3dab4015f0566aa7727f22aee1f247649b5c2103ffb581fd5edab4eaec5d10a221bf5d'
    '8e0afad4b5098e75a776a1cb7aa80db46651473045022100a76b71256b29303c6c0b68864f1b57e2e42e7bf619ec'
    '79549f0fd9efc1da438602205a288879c589bcc1c873439bc354377de6fd24cb287fcc79c25997642bf41ee82103'
    'bc8c8860fb814ae77fd256cff8c92260c9ec515ff33176148f1e288e868cc7bb51'
}

signing_masks_of3 = tuple((i, j, k) for i in range(2) for j in range(2) for k in range(2))
accumulator_scripts_of3 = {
    (0, 0, 0): '000000',
    (0, 0, 1): '473045022100d745a1ff57007960002b864daee0bd090d4c17e28900c81ed74e46e78e98ebf102205'
    'de658ef4d1cc745d6e39a076a7c9ab80ae2ab027f815d62eb0e0f0b5c9094c62102fb13404b8df4cae6f96447507'
    'ff66d9ec50e04cc39c8a9795b4cc2d57d6c1b56510000',
    (0, 1, 0): '004630440220774e912b64b9ecc212edcd2d2f10003ddae023e28f18e20acb606354c67331ea02206'
    '26e6bd8a4036f3c14972aed332a3dab4015f0566aa7727f22aee1f247649b5c2103ffb581fd5edab4eaec5d10a22'
    '1bf5d8e0afad4b5098e75a776a1cb7aa80db4665100',
    (0, 1, 1): '473045022100d745a1ff57007960002b864daee0bd090d4c17e28900c81ed74e46e78e98ebf102205'
    'de658ef4d1cc745d6e39a076a7c9ab80ae2ab027f815d62eb0e0f0b5c9094c62102fb13404b8df4cae6f96447507'
    'ff66d9ec50e04cc39c8a9795b4cc2d57d6c1b56514630440220774e912b64b9ecc212edcd2d2f10003ddae023e28'
    'f18e20acb606354c67331ea0220626e6bd8a4036f3c14972aed332a3dab4015f0566aa7727f22aee1f247649b5c2'
    '103ffb581fd5edab4eaec5d10a221bf5d8e0afad4b5098e75a776a1cb7aa80db4665100',
    (1, 0, 0): '0000473045022100a76b71256b29303c6c0b68864f1b57e2e42e7bf619ec79549f0fd9efc1da43860'
    '2205a288879c589bcc1c873439bc354377de6fd24cb287fcc79c25997642bf41ee82103bc8c8860fb814ae77fd25'
    '6cff8c92260c9ec515ff33176148f1e288e868cc7bb51',
    (1, 0, 1): '473045022100d745a1ff57007960002b864daee0bd090d4c17e28900c81ed74e46e78e98ebf102205'
    'de658ef4d1cc745d6e39a076a7c9ab80ae2ab027f815d62eb0e0f0b5c9094c62102fb13404b8df4cae6f96447507'
    'ff66d9ec50e04cc39c8a9795b4cc2d57d6c1b565100473045022100a76b71256b29303c6c0b68864f1b57e2e42e7'
    'bf619ec79549f0fd9efc1da438602205a288879c589bcc1c873439bc354377de6fd24cb287fcc79c25997642bf41'
    'ee82103bc8c8860fb814ae77fd256cff8c92260c9ec515ff33176148f1e288e868cc7bb51',
    (1, 1, 0): '004630440220774e912b64b9ecc212edcd2d2f10003ddae023e28f18e20acb606354c67331ea02206'
    '26e6bd8a4036f3c14972aed332a3dab4015f0566aa7727f22aee1f247649b5c2103ffb581fd5edab4eaec5d10a22'
    '1bf5d8e0afad4b5098e75a776a1cb7aa80db46651473045022100a76b71256b29303c6c0b68864f1b57e2e42e7bf'
    '619ec79549f0fd9efc1da438602205a288879c589bcc1c873439bc354377de6fd24cb287fcc79c25997642bf41ee'
    '82103bc8c8860fb814ae77fd256cff8c92260c9ec515ff33176148f1e288e868cc7bb51',
    (1, 1, 1): '473045022100d745a1ff57007960002b864daee0bd090d4c17e28900c81ed74e46e78e98ebf102205'
    'de658ef4d1cc745d6e39a076a7c9ab80ae2ab027f815d62eb0e0f0b5c9094c62102fb13404b8df4cae6f96447507'
    'ff66d9ec50e04cc39c8a9795b4cc2d57d6c1b56514630440220774e912b64b9ecc212edcd2d2f10003ddae023e28'
    'f18e20acb606354c67331ea0220626e6bd8a4036f3c14972aed332a3dab4015f0566aa7727f22aee1f247649b5c2'
    '103ffb581fd5edab4eaec5d10a221bf5d8e0afad4b5098e75a776a1cb7aa80db46651473045022100a76b71256b2'
    '9303c6c0b68864f1b57e2e42e7bf619ec79549f0fd9efc1da438602205a288879c589bcc1c873439bc354377de6f'
    'd24cb287fcc79c25997642bf41ee82103bc8c8860fb814ae77fd256cff8c92260c9ec515ff33176148f1e288e868'
    'cc7bb51',
}

@pytest.mark.parametrize("masks,scripts_hex", [
    (signing_masks_of2, accumulator_scripts_of2),
    (signing_masks_of3, accumulator_scripts_of3) ])
def test_accumulator_multisig_scriptsig_NofM(masks, scripts_hex):
    for mask in masks:
        pubkeys = []
        signatures = []
        for key_index in range(len(mask)):
            private_key = PrivateKey.from_hex(private_keys_hex[key_index])
            pubkeys.append(private_key.public_key)
            if mask[key_index]:
                signatures.append(bytes.fromhex(signatures_hex[key_index]))
            else:
                signatures.append(NO_SIGNATURE)
        script = create_script_sig(ScriptType.MULTISIG_ACCUMULATOR, sum(mask), pubkeys, signatures)
        assert scripts_hex[mask] == script.to_hex()


@pytest.mark.parametrize("m,script_hex", [
    (2, '006b6376a914e91d89f4b52fe2a04d1d225e14dbe868d824a92e88ad6c8b6b686376a914229683d879479f3b'
        '80c938045a68c1da1c02715f88ad6c8b6b686c52a2'),
    (3, '006b6376a914e91d89f4b52fe2a04d1d225e14dbe868d824a92e88ad6c8b6b686376a914229683d879479f3b'
        '80c938045a68c1da1c02715f88ad6c8b6b686376a914fa95306e6d18d4508f555bab2c22d124f4e009f588ad'
        '6c8b6b686c53a2')
])
def test_accumulator_multisig_scriptpubkey_ofM(m, script_hex):
    public_keys = []
    for i in range(m):
        public_keys.append(PrivateKey.from_hex(private_keys_hex[i]).public_key)
    output = AccumulatorMultiSigOutput(public_keys, m)
    assert output.to_script_bytes().hex() == script_hex

