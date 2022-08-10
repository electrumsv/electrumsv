import pytest

from electrumsv.standards.psbt import parse_psbt_bytes, PSBTIncompatibleError, PSBTInputMetadata, \
    PSBTOutputMetadata

empty_input_metadata = PSBTInputMetadata()
empty_output_metadata = PSBTOutputMetadata()

VECTOR_P2PKH_INPUT_EMPTY_OUTPUTS_BYTES = bytes.fromhex("70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000001030401000000000000") # pylint: disable=line-too-long

def test_psbt_one_p2pkh_input_empty_output_sections_empty() -> None:
    psbt_data = parse_psbt_bytes(VECTOR_P2PKH_INPUT_EMPTY_OUTPUTS_BYTES, {})
    assert psbt_data.transaction is not None
    assert len(psbt_data.transaction.inputs) == 1
    assert len(psbt_data.transaction.inputs[0].script_sig) == 0
    assert len(psbt_data.transaction.outputs) == 2
    assert len(psbt_data.input_metadata) == 1
    assert psbt_data.input_metadata[0].sighash == 1
    assert len(psbt_data.output_metadata) == 2              # What this vector focuses on.
    assert all(output_metadata == empty_output_metadata     # What this vector focuses on.
        for output_metadata in psbt_data.output_metadata)
    # assert not psbt_data.transaction.is_complete()

VECTOR_GLOBAL_UNSIGNED_NO_INPUTS_NO_OUTPUTS_BYTES = bytes.fromhex("70736274ff01000a0000000000000000000000") # pylint: disable=line-too-long

def test_psbt_global_unsigned_no_inputs_no_outputs() -> None:
    psbt_data = parse_psbt_bytes(VECTOR_GLOBAL_UNSIGNED_NO_INPUTS_NO_OUTPUTS_BYTES, {})
    assert psbt_data.psbt_version == 0
    assert psbt_data.transaction is not None
    assert len(psbt_data.transaction.inputs) == 0
    assert len(psbt_data.transaction.outputs) == 0
    assert len(psbt_data.input_metadata) == 0               # What this vector focuses on.
    assert len(psbt_data.output_metadata) == 0              # What this vector focuses on.
    assert len(psbt_data.parent_transactions) == 0

VECTOR_NO_INPUTS = bytes.fromhex("70736274ff01004c020000000002d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000000") # pylint: disable=line-too-long

def test_psbt_no_inputs() -> None:
    psbt_data = parse_psbt_bytes(VECTOR_NO_INPUTS, {})
    assert psbt_data.psbt_version == 0
    assert psbt_data.transaction is not None
    assert len(psbt_data.transaction.inputs) == 0
    assert len(psbt_data.transaction.outputs) == 2
    assert len(psbt_data.input_metadata) == 0               # What this vector focuses on.
    assert len(psbt_data.output_metadata) == 2
    assert all(output_metadata == empty_output_metadata
        for output_metadata in psbt_data.output_metadata)
    assert len(psbt_data.parent_transactions) == 0

VECTOR_X = bytes.fromhex("70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000220202dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01010304010000000104475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752af2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f000000800000008000000080220602dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d710d90c6a4f0000008000000080010000800001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8872202023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d2010103040100000001042200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903010547522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae2206023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7310d90c6a4f000000800000008003000080220603089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc10d90c6a4f00000080000000800200008000220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000") # pylint: disable=line-too-long

def test_pbst_incompatible_input_with_witness_utxo() -> None:
    XPUB_ARBITRARY = "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA" # pylint: disable=line-too-long
    xpub_by_fingerprint: dict[bytes, str] = { bytes.fromhex("d90c6a4f"): XPUB_ARBITRARY }
    with pytest.raises(PSBTIncompatibleError) as exception_value:
        parse_psbt_bytes(VECTOR_X, xpub_by_fingerprint)
    assert exception_value.value.args[0] == "Incompatible input key WITNESS_UTXO"

