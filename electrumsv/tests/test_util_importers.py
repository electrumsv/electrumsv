from typing import Sequence

from bitcoinx import hex_str_to_hash
import pytest

from electrumsv.util.importers import identify_label_import_format, LabelImport, LabelImportFormat


wallet_both_text = """{
    "keys": {
        "account_fingerprint": "b34634f4",
        "entries": [
            [
                "m/0/4",
                "TEST KEY LABEL 2"
            ],
            [
                "m/0/34",
                "TEST KEY LABEL"
            ]
        ]
    },
    "transactions": [
        [
            "44e14e2eef1482bc803d1a32d9348b4914922990dbb730fe70b8a40753aeea03",
            "Return funding to 'mainnet_cash'"
        ],
        [
            "eeb535883c1bb2ed39295788eb9aca03623c97fa45ca4473175ff1bdca95201c",
            "return funding"
        ],
        [
            "30ecc3ea39c0f4cc3af3f03486966f6b1ebb0f32466a541ab8c1f4bb4faf232c",
            "Funding for r125 testing"
        ],
        [
            "b95e3d34f4881ff722b9a5113235ff7f9e361e7f5fbb8178ced97b2ff2103977",
            "Return funding for issue 179/127"
        ],
        [
            "b3bac1b30c6b575846de11c10eedfaf56b288db1dd84624f0578194899e4557f",
            "Return funding"
        ],
        [
            "94a8b4fe299bd5fdcb3f086552906d49f7fc827f515e1057d6d3a321d63123b1",
            "Funding for test for issue 179/127"
        ],
        [
            "f9f7db3ce916f23afce8306ff2fcf46ff26e079bb224b1be38f8e3612a0556b5",
            "Return funding for r125"
        ],
        [
            "463b4fa28c834fc731b5133cbbe65476ba90630bdc3305fa4a566312839885c0",
            "Receive 1.3.0b5 funding"
        ],
        [
            "95703e3dd662fded40c8db1338db772817fac1f81d21f13104fc84b263c31ede",
            "Return funding"
        ],
        [
            "eb3aa368a8b5842e98abe2765ad1453ad8b187e880244a9ef84e21522749bae4",
            "Return 1.3.0b5 funding"
        ],
        [
            "6983eb9006dd10e5d1946daf1cb7980b0c18b009b9944d36d276a45d0fd7a4e9",
            "Funding for test"
        ]
    ]
}"""

wallet_keys_text = """{
    "keys": {
        "account_fingerprint": "b34634f4",
        "entries": [
            [
                "m/0/4",
                "TEST KEY LABEL 2"
            ],
            [
                "m/0/34",
                "TEST KEY LABEL"
            ]
        ]
    }
}"""

wallet_transactions_text = """{
    "transactions": [
        [
            "44e14e2eef1482bc803d1a32d9348b4914922990dbb730fe70b8a40753aeea03",
            "Return funding to 'mainnet_cash'"
        ],
        [
            "eeb535883c1bb2ed39295788eb9aca03623c97fa45ca4473175ff1bdca95201c",
            "return funding"
        ],
        [
            "30ecc3ea39c0f4cc3af3f03486966f6b1ebb0f32466a541ab8c1f4bb4faf232c",
            "Funding for r125 testing"
        ],
        [
            "b95e3d34f4881ff722b9a5113235ff7f9e361e7f5fbb8178ced97b2ff2103977",
            "Return funding for issue 179/127"
        ],
        [
            "b3bac1b30c6b575846de11c10eedfaf56b288db1dd84624f0578194899e4557f",
            "Return funding"
        ],
        [
            "94a8b4fe299bd5fdcb3f086552906d49f7fc827f515e1057d6d3a321d63123b1",
            "Funding for test for issue 179/127"
        ],
        [
            "f9f7db3ce916f23afce8306ff2fcf46ff26e079bb224b1be38f8e3612a0556b5",
            "Return funding for r125"
        ],
        [
            "463b4fa28c834fc731b5133cbbe65476ba90630bdc3305fa4a566312839885c0",
            "Receive 1.3.0b5 funding"
        ],
        [
            "95703e3dd662fded40c8db1338db772817fac1f81d21f13104fc84b263c31ede",
            "Return funding"
        ],
        [
            "eb3aa368a8b5842e98abe2765ad1453ad8b187e880244a9ef84e21522749bae4",
            "Return 1.3.0b5 funding"
        ],
        [
            "6983eb9006dd10e5d1946daf1cb7980b0c18b009b9944d36d276a45d0fd7a4e9",
            "Funding for test"
        ]
    ]
}"""

labelsync_text = """{"44e14e2eef1482bc803d1a32d9348b4914922990dbb730fe70b8a40753aeea03": "Return funding to 'mainnet_cash'", "95703e3dd662fded40c8db1338db772817fac1f81d21f13104fc84b263c31ede": "Return funding", "b3bac1b30c6b575846de11c10eedfaf56b288db1dd84624f0578194899e4557f": "Return funding", "94a8b4fe299bd5fdcb3f086552906d49f7fc827f515e1057d6d3a321d63123b1": "Funding for test for issue 179/127", "b95e3d34f4881ff722b9a5113235ff7f9e361e7f5fbb8178ced97b2ff2103977": "Return funding for issue 179/127", "30ecc3ea39c0f4cc3af3f03486966f6b1ebb0f32466a541ab8c1f4bb4faf232c": "Funding for r125 testing", "f9f7db3ce916f23afce8306ff2fcf46ff26e079bb224b1be38f8e3612a0556b5": "Return funding for r125"}""" # pylint: disable=line-too-long


@pytest.mark.parametrize("sample,import_type", [
    (wallet_both_text, LabelImportFormat.ACCOUNT),
    (wallet_transactions_text, LabelImportFormat.ACCOUNT),
    (wallet_keys_text, LabelImportFormat.ACCOUNT),
    (labelsync_text, LabelImportFormat.LABELSYNC),
    ("{}", LabelImportFormat.UNKNOWN),
    ("zdsdw", LabelImportFormat.UNKNOWN),
    ("", LabelImportFormat.UNKNOWN),
    ("\n", LabelImportFormat.UNKNOWN),
    ("\0", LabelImportFormat.UNKNOWN),
])
def test_label_import_format_identification(sample: str, import_type: LabelImportFormat) -> None:
    assert import_type == identify_label_import_format(sample)

class MockAccount:
    def get_keyinstance_ids(self) -> Sequence[int]:
        return []


def test_import_labelsync_format() -> None:
    account = MockAccount()
    results = LabelImport.parse_label_sync_json(account, labelsync_text)
    assert 7 == len(results.transaction_labels)

    tx_hash = hex_str_to_hash("44e14e2eef1482bc803d1a32d9348b4914922990dbb730fe70b8a40753aeea03")
    assert "Return funding to 'mainnet_cash'" == results.transaction_labels[tx_hash]
