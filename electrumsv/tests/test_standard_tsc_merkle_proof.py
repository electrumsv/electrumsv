import pytest

from bitcoinx import hex_str_to_hash

from electrumsv.standards.tsc_merkle_proof import ProofCountFlag, ProofTargetFlag, \
    ProofTransactionFlag, ProofTypeFlag, TSCMerkleNode, TSCMerkleNodeKind, TSCMerkleProof, \
    TSCMerkleProofError, verify_proof


def test_convert_to_binary() -> None:
    expected_hex = '000cef65a4611570303539143dabd6aa64dbd0f41ed89074406dc0e7cd251cf1efff69f17b44cfe9c2a23285168fe05084e1254daa5305311ed8cd95b19ea6b0ed7505008e66d81026ddb2dae0bd88082632790fc6921b299ca798088bef5325a607efb9004d104f378654a25e35dbd6a539505a1e3ddbba7f92420414387bb5b12fc1c10f00472581a20a043cee55edee1c65dd6677e09903f22992062d8fd4b8d55de7b060006fcc978b3f999a3dbb85a6ae55edc06dd9a30855a030b450206c3646dadbd8c000423ab0273c2572880cdc0030034c72ec300ec9dd7bbc7d3f948a9d41b3621e39'
    proof = TSCMerkleProof(
        0,
        transaction_index=12,
        transaction_hash=hex_str_to_hash('ffeff11c25cde7c06d407490d81ef4d0db64aad6ab3d14393530701561a465ef'),
        block_hash=hex_str_to_hash('75edb0a69eb195cdd81e310553aa4d25e18450e08f168532a2c2e9cf447bf169'),
        nodes=[
            TSCMerkleNode(TSCMerkleNodeKind.HASH, hex_str_to_hash(text)) for text in [
                'b9ef07a62553ef8b0898a79c291b92c60f7932260888bde0dab2dd2610d8668e',
                '0fc1c12fb1b57b38140442927fbadb3d1e5a5039a5d6db355ea25486374f104d',
                '60b0e75dd5b8d48f2d069229f20399e07766dd651ceeed55ee3c040aa2812547',
                'c0d8dbda46366c2050b430a05508a3d96dc0ed55aea685bb3d9a993f8b97cc6f',
                '391e62b3419d8a943f7dbc7bddc90e30ec724c033000dc0c8872253c27b03a42'
            ]
        ]
    )
    assert proof.to_bytes() == bytes.fromhex(expected_hex)

def test_reject_unrecognized_flags() -> None:
    proof = TSCMerkleProof(
        0xFF,
        transaction_index=0,
        transaction_hash=hex_str_to_hash('75edb0a69eb195cdd81e310553aa4d25e18450e08f168532a2c2e9cf447bf169'),
        merkle_root_bytes=hex_str_to_hash('cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe'),
        nodes=[
            TSCMerkleNode(TSCMerkleNodeKind.HASH, bytes.fromhex(text)) for text in [
            ]
        ]
    )
    with pytest.raises(TSCMerkleProofError) as e:
        proof.to_bytes()
    assert e.value.args[0] == "Unexpected flags e0"

def test_reject_tree_proof_type() -> None:
    proof = TSCMerkleProof(
        ProofTypeFlag.MERKLE_TREE,
        transaction_index=0,
        transaction_hash=hex_str_to_hash('75edb0a69eb195cdd81e310553aa4d25e18450e08f168532a2c2e9cf447bf169'),
        merkle_root_bytes=hex_str_to_hash('cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe'),
        nodes=[
            TSCMerkleNode(TSCMerkleNodeKind.HASH, bytes.fromhex(text)) for text in [
            ]
        ]
    )
    with pytest.raises(TSCMerkleProofError) as e:
        proof.to_bytes()
    assert e.value.args[0] == "Proofs can currently only be merkle branches"

def test_reject_composite_proofs_from_bytes() -> None:
    # Leading byte is 0x04 | 0x10 with the latter indicating that it is a composite proof
    expected_hex = '140069f17b44cfe9c2a23285168fe05084e1254daa5305311ed8cd95b19ea6b0ed75fecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafeca00'
    with pytest.raises(TSCMerkleProofError) as e:
        TSCMerkleProof.from_bytes(bytes.fromhex(expected_hex))
    assert e.value.args[0] == "Proofs can currently only be singular"

def test_reject_composite_proofs_to_bytes() -> None:
    proof = TSCMerkleProof(
        ProofCountFlag.MULTIPLE,
        transaction_index=0,
        transaction_hash=hex_str_to_hash('75edb0a69eb195cdd81e310553aa4d25e18450e08f168532a2c2e9cf447bf169'),
        merkle_root_bytes=hex_str_to_hash('cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe'),
        nodes=[
            TSCMerkleNode(TSCMerkleNodeKind.HASH, bytes.fromhex(text)) for text in [
            ]
        ]
    )
    with pytest.raises(TSCMerkleProofError) as e:
        proof.to_bytes()
    assert e.value.args[0] == "Proofs can currently only be singular"

def test_reject_invalid_merkle_root_from_bytes() -> None:
    expected_hex = '040069f17b44cfe9c2a23285168fe05084e1254daa5305311ed8cd95b19ea6b0ed75fecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafeca00'
    proof = TSCMerkleProof.from_bytes(bytes.fromhex(expected_hex))
    assert not verify_proof(proof)

def test_reject_invalid_merkle_root() -> None:
    proof = TSCMerkleProof(
        ProofTargetFlag.MERKLE_ROOT,
        transaction_index=0,
        transaction_hash=hex_str_to_hash('75edb0a69eb195cdd81e310553aa4d25e18450e08f168532a2c2e9cf447bf169'),
        merkle_root_bytes=hex_str_to_hash('cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe'),
        nodes=[
            TSCMerkleNode(TSCMerkleNodeKind.HASH, bytes.fromhex(text)) for text in [
            ]
        ]
    )
    assert not verify_proof(proof)

def test_accept_single_candidate_from_bytes() -> None:
    expected_hex = '040069f17b44cfe9c2a23285168fe05084e1254daa5305311ed8cd95b19ea6b0ed7569f17b44cfe9c2a23285168fe05084e1254daa5305311ed8cd95b19ea6b0ed7500'
    proof = TSCMerkleProof.from_bytes(bytes.fromhex(expected_hex))
    assert verify_proof(proof)

def test_accept_single_candidate() -> None:
    proof = TSCMerkleProof(
        ProofTargetFlag.MERKLE_ROOT,
        transaction_index=0,
        transaction_hash=hex_str_to_hash('75edb0a69eb195cdd81e310553aa4d25e18450e08f168532a2c2e9cf447bf169'),
        merkle_root_bytes=hex_str_to_hash('75edb0a69eb195cdd81e310553aa4d25e18450e08f168532a2c2e9cf447bf169'),
        nodes=[
            TSCMerkleNode(TSCMerkleNodeKind.HASH, bytes.fromhex(text)) for text in [
            ]
        ]
    )
    assert verify_proof(proof)

def test_accept_single_pair_where_transaction_is_on_the_left_from_bytes() -> None:
    expected_hex = '040069f17b44cfe9c2a23285168fe05084e1254daa5305311ed8cd95b19ea6b0ed75822f45f786ab6f17b52245bb4956e0a2016bd3613ba8115e97f3ef2ea6344ad00100fecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafeca'
    expected_bytes = bytes.fromhex(expected_hex)
    proof = TSCMerkleProof.from_bytes(expected_bytes)
    assert verify_proof(proof)
    assert proof.to_bytes() == expected_bytes

def test_accept_single_pair_where_transaction_is_on_the_left() -> None:
    expected_hex = '040069f17b44cfe9c2a23285168fe05084e1254daa5305311ed8cd95b19ea6b0ed75822f45f786ab6f17b52245bb4956e0a2016bd3613ba8115e97f3ef2ea6344ad00100fecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafeca'
    expected_bytes = bytes.fromhex(expected_hex)
    proof = TSCMerkleProof(
        ProofTargetFlag.MERKLE_ROOT,
        transaction_index=0,
        transaction_hash=hex_str_to_hash('75edb0a69eb195cdd81e310553aa4d25e18450e08f168532a2c2e9cf447bf169'),
        merkle_root_bytes=hex_str_to_hash('d04a34a62eeff3975e11a83b61d36b01a2e05649bb4522b5176fab86f7452f82'),
        nodes=[
            TSCMerkleNode(TSCMerkleNodeKind.HASH, hex_str_to_hash(text)) for text in [
              'cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe'
            ]
        ]
    )
    assert verify_proof(proof)
    assert proof.to_bytes() == expected_bytes

def test_accept_single_pair_where_transaction_is_on_the_right_from_bytes() -> None:
    expected_hex = '040169f17b44cfe9c2a23285168fe05084e1254daa5305311ed8cd95b19ea6b0ed752e89da4ddbcce991aa502edac9c7e9ec44a150c8b5290c4fefde8dd61df1d7510100fecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafeca'
    expected_bytes = bytes.fromhex(expected_hex)
    proof = TSCMerkleProof.from_bytes(expected_bytes)
    assert verify_proof(proof)
    assert proof.to_bytes() == expected_bytes

def test_accept_single_pair_where_transaction_is_on_the_right() -> None:
    expected_hex = '040169f17b44cfe9c2a23285168fe05084e1254daa5305311ed8cd95b19ea6b0ed752e89da4ddbcce991aa502edac9c7e9ec44a150c8b5290c4fefde8dd61df1d7510100fecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafeca'
    expected_bytes = bytes.fromhex(expected_hex)
    proof = TSCMerkleProof(
        ProofTargetFlag.MERKLE_ROOT,
        transaction_index=1,
        transaction_hash=hex_str_to_hash('75edb0a69eb195cdd81e310553aa4d25e18450e08f168532a2c2e9cf447bf169'),
        merkle_root_bytes=hex_str_to_hash('51d7f11dd68ddeef4f0c29b5c850a144ece9c7c9da2e50aa91e9ccdb4dda892e'),
        nodes=[
            TSCMerkleNode(TSCMerkleNodeKind.HASH, hex_str_to_hash(text)) for text in [
              'cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe'
            ]
        ]
    )
    assert verify_proof(proof)
    assert proof.to_bytes() == expected_bytes

def test_accept_last_element_of_uneven_tree_on_left_from_bytes() -> None:
    expected_hex = '040269f17b44cfe9c2a23285168fe05084e1254daa5305311ed8cd95b19ea6b0ed75a7b067a2cf49c96d83ab1cf216839a0e5915a191ad6f6174c4b0eb51bf859d6c030100fecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe0a00fecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe1a'
    expected_bytes = bytes.fromhex(expected_hex)
    proof = TSCMerkleProof.from_bytes(expected_bytes)
    assert verify_proof(proof)
    assert proof.to_bytes() == expected_bytes

def test_accept_last_element_of_uneven_tree_on_left() -> None:
    expected_hex = '040269f17b44cfe9c2a23285168fe05084e1254daa5305311ed8cd95b19ea6b0ed75a7b067a2cf49c96d83ab1cf216839a0e5915a191ad6f6174c4b0eb51bf859d6c030100fecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe0a00fecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe1a'
    expected_bytes = bytes.fromhex(expected_hex)
    proof = TSCMerkleProof(
        ProofTargetFlag.MERKLE_ROOT,
        transaction_index=2,
        transaction_hash=hex_str_to_hash('75edb0a69eb195cdd81e310553aa4d25e18450e08f168532a2c2e9cf447bf169'),
        merkle_root_bytes=hex_str_to_hash('6c9d85bf51ebb0c474616fad91a115590e9a8316f21cab836dc949cfa267b0a7'),
        nodes=[
            TSCMerkleNode(TSCMerkleNodeKind.HASH, hex_str_to_hash(text)) if text != "*" else TSCMerkleNode(TSCMerkleNodeKind.DUPLICATE) for text in [
                '*',
                '0afecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe',
                '1afecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe'
            ]
        ]
    )
    assert verify_proof(proof)
    assert proof.to_bytes() == expected_bytes

def test_reject_last_element_of_uneven_tree_on_right_from_bytes() -> None:
    expected_hex = '040369f17b44cfe9c2a23285168fe05084e1254daa5305311ed8cd95b19ea6b0ed75cad5788aa7733560334238c0fd23c4f10c46080b7165f296c96bbcdbff298ef5030100fecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe2a00fecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe3a'
    expected_bytes = bytes.fromhex(expected_hex)
    proof = TSCMerkleProof.from_bytes(expected_bytes)
    with pytest.raises(TSCMerkleProofError) as e:
        verify_proof(proof)
    assert e.value.args[0] == "Duplicate node cannot be on right"

def test_reject_last_element_of_uneven_tree_on_right() -> None:
    proof = TSCMerkleProof(
        ProofTargetFlag.MERKLE_ROOT,
        transaction_index=3,
        transaction_hash=hex_str_to_hash('75edb0a69eb195cdd81e310553aa4d25e18450e08f168532a2c2e9cf447bf169'),
        merkle_root_bytes=hex_str_to_hash('f58e29ffdbbc6bc996f265710b08460cf1c423fdc0384233603573a78a78d5ca'),
        nodes=[
            TSCMerkleNode(TSCMerkleNodeKind.HASH, hex_str_to_hash(text)) if text != "*" else TSCMerkleNode(TSCMerkleNodeKind.DUPLICATE) for text in [
                '*',
                '2afecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe',
                '3afecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe'
            ]
        ]
    )
    with pytest.raises(TSCMerkleProofError) as e:
        verify_proof(proof)
    assert e.value.args[0] == "Duplicate node cannot be on right"

def test_reject_invalid_header_with_explicit_header_target_type_from_bytes() -> None:
    expected_hex = '030cc00200000001080e8558d7af4763fef68042ef1e723d521948a0fb465237d5fb21fafb61f0580000000049483045022100fb4c94dc29cfa7423775443f8d8bb49b5814dcf709553345fcfad240efce22920220558569f97acd0d2b7bbe1954d570b9629ddf5491d9341867d7c41a8e6ee4ed2a41feffffff0200e1f505000000001976a914e296a740f5d9ecc22e0a74f9799f54ec44ee215a88ac80dc4a1f000000001976a914c993ce218b406cb71c60bad1f2be9469d91593cd88ac85020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005008e66d81026ddb2dae0bd88082632790fc6921b299ca798088bef5325a607efb9004d104f378654a25e35dbd6a539505a1e3ddbba7f92420414387bb5b12fc1c10f00472581a20a043cee55edee1c65dd6677e09903f22992062d8fd4b8d55de7b060006fcc978b3f999a3dbb85a6ae55edc06dd9a30855a030b450206c3646dadbd8c000423ab0273c2572880cdc0030034c72ec300ec9dd7bbc7d3f948a9d41b3621e39'
    expected_bytes = bytes.fromhex(expected_hex)
    proof = TSCMerkleProof.from_bytes(expected_bytes)
    assert not verify_proof(proof)

def test_reject_invalid_header_with_explicit_header_target_type() -> None:
    proof = TSCMerkleProof(
        ProofTransactionFlag.FULL_TRANSACTION | ProofTargetFlag.BLOCK_HEADER,
        transaction_index=12,
        transaction_bytes=bytes.fromhex("0200000001080e8558d7af4763fef68042ef1e723d521948a0fb465237d5fb21fafb61f0580000000049483045022100fb4c94dc29cfa7423775443f8d8bb49b5814dcf709553345fcfad240efce22920220558569f97acd0d2b7bbe1954d570b9629ddf5491d9341867d7c41a8e6ee4ed2a41feffffff0200e1f505000000001976a914e296a740f5d9ecc22e0a74f9799f54ec44ee215a88ac80dc4a1f000000001976a914c993ce218b406cb71c60bad1f2be9469d91593cd88ac85020000"),
        block_header_bytes=hex_str_to_hash('0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'),
        nodes=[
            TSCMerkleNode(TSCMerkleNodeKind.HASH, hex_str_to_hash(text)) if text != "*" else TSCMerkleNode(TSCMerkleNodeKind.DUPLICATE) for text in [
                'b9ef07a62553ef8b0898a79c291b92c60f7932260888bde0dab2dd2610d8668e',
                '0fc1c12fb1b57b38140442927fbadb3d1e5a5039a5d6db355ea25486374f104d',
                '60b0e75dd5b8d48f2d069229f20399e07766dd651ceeed55ee3c040aa2812547',
                'c0d8dbda46366c2050b430a05508a3d96dc0ed55aea685bb3d9a993f8b97cc6f',
                '391e62b3419d8a943f7dbc7bddc90e30ec724c033000dc0c8872253c27b03a42'
            ]
        ]
    )
    assert not verify_proof(proof)

def test_accept_valid_transaction_as_implicit_target_type_from_bytes() -> None:
    expected_merkle_root_hex = '96cbb75fd2ef98e4309eebc8a54d2386333d936ded2a0f3e06c23a91bb612f70'
    expected_merkle_root_bytes = hex_str_to_hash(expected_merkle_root_hex)

    expected_hex = '010cc00200000001080e8558d7af4763fef68042ef1e723d521948a0fb465237d5fb21fafb61f0580000000049483045022100fb4c94dc29cfa7423775443f8d8bb49b5814dcf709553345fcfad240efce22920220558569f97acd0d2b7bbe1954d570b9629ddf5491d9341867d7c41a8e6ee4ed2a41feffffff0200e1f505000000001976a914e296a740f5d9ecc22e0a74f9799f54ec44ee215a88ac80dc4a1f000000001976a914c993ce218b406cb71c60bad1f2be9469d91593cd88ac8502000069f17b44cfe9c2a23285168fe05084e1254daa5305311ed8cd95b19ea6b0ed7505008e66d81026ddb2dae0bd88082632790fc6921b299ca798088bef5325a607efb9004d104f378654a25e35dbd6a539505a1e3ddbba7f92420414387bb5b12fc1c10f00472581a20a043cee55edee1c65dd6677e09903f22992062d8fd4b8d55de7b060006fcc978b3f999a3dbb85a6ae55edc06dd9a30855a030b450206c3646dadbd8c000423ab0273c2572880cdc0030034c72ec300ec9dd7bbc7d3f948a9d41b3621e39'
    expected_bytes = bytes.fromhex(expected_hex)
    proof = TSCMerkleProof.from_bytes(expected_bytes)
    assert verify_proof(proof, expected_merkle_root_bytes)

def test_accept_valid_transaction_as_implicit_target_type() -> None:
    expected_merkle_root_hex = '96cbb75fd2ef98e4309eebc8a54d2386333d936ded2a0f3e06c23a91bb612f70'
    expected_merkle_root_bytes = hex_str_to_hash(expected_merkle_root_hex)

    expected_hex = '010cc00200000001080e8558d7af4763fef68042ef1e723d521948a0fb465237d5fb21fafb61f0580000000049483045022100fb4c94dc29cfa7423775443f8d8bb49b5814dcf709553345fcfad240efce22920220558569f97acd0d2b7bbe1954d570b9629ddf5491d9341867d7c41a8e6ee4ed2a41feffffff0200e1f505000000001976a914e296a740f5d9ecc22e0a74f9799f54ec44ee215a88ac80dc4a1f000000001976a914c993ce218b406cb71c60bad1f2be9469d91593cd88ac8502000069f17b44cfe9c2a23285168fe05084e1254daa5305311ed8cd95b19ea6b0ed7505008e66d81026ddb2dae0bd88082632790fc6921b299ca798088bef5325a607efb9004d104f378654a25e35dbd6a539505a1e3ddbba7f92420414387bb5b12fc1c10f00472581a20a043cee55edee1c65dd6677e09903f22992062d8fd4b8d55de7b060006fcc978b3f999a3dbb85a6ae55edc06dd9a30855a030b450206c3646dadbd8c000423ab0273c2572880cdc0030034c72ec300ec9dd7bbc7d3f948a9d41b3621e39'
    expected_bytes = bytes.fromhex(expected_hex)
    proof = TSCMerkleProof(
        ProofTransactionFlag.FULL_TRANSACTION,
        transaction_index=12,
        transaction_bytes=bytes.fromhex('0200000001080e8558d7af4763fef68042ef1e723d521948a0fb465237d5fb21fafb61f0580000000049483045022100fb4c94dc29cfa7423775443f8d8bb49b5814dcf709553345fcfad240efce22920220558569f97acd0d2b7bbe1954d570b9629ddf5491d9341867d7c41a8e6ee4ed2a41feffffff0200e1f505000000001976a914e296a740f5d9ecc22e0a74f9799f54ec44ee215a88ac80dc4a1f000000001976a914c993ce218b406cb71c60bad1f2be9469d91593cd88ac85020000'),
        block_hash=hex_str_to_hash('75edb0a69eb195cdd81e310553aa4d25e18450e08f168532a2c2e9cf447bf169'),
        nodes=[
            TSCMerkleNode(TSCMerkleNodeKind.HASH, hex_str_to_hash(text)) if text != "*" else TSCMerkleNode(TSCMerkleNodeKind.DUPLICATE) for text in [
                'b9ef07a62553ef8b0898a79c291b92c60f7932260888bde0dab2dd2610d8668e',
                '0fc1c12fb1b57b38140442927fbadb3d1e5a5039a5d6db355ea25486374f104d',
                '60b0e75dd5b8d48f2d069229f20399e07766dd651ceeed55ee3c040aa2812547',
                'c0d8dbda46366c2050b430a05508a3d96dc0ed55aea685bb3d9a993f8b97cc6f',
                '391e62b3419d8a943f7dbc7bddc90e30ec724c033000dc0c8872253c27b03a42'
            ]
        ]
    )
    assert verify_proof(proof, expected_merkle_root_bytes)
    assert proof.to_bytes() == expected_bytes

def test_reject_invalid_transaction_from_bytes() -> None:
    expected_merkle_root_hex = '96cbb75fd2ef98e4309eebc8a54d2386333d936ded2a0f3e06c23a91bb612f70'
    expected_merkle_root_bytes = hex_str_to_hash(expected_merkle_root_hex)

    expected_hex = '010c3c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000069f17b44cfe9c2a23285168fe05084e1254daa5305311ed8cd95b19ea6b0ed7505008e66d81026ddb2dae0bd88082632790fc6921b299ca798088bef5325a607efb9004d104f378654a25e35dbd6a539505a1e3ddbba7f92420414387bb5b12fc1c10f00472581a20a043cee55edee1c65dd6677e09903f22992062d8fd4b8d55de7b060006fcc978b3f999a3dbb85a6ae55edc06dd9a30855a030b450206c3646dadbd8c000423ab0273c2572880cdc0030034c72ec300ec9dd7bbc7d3f948a9d41b3621e39'
    expected_bytes = bytes.fromhex(expected_hex)
    proof = TSCMerkleProof.from_bytes(expected_bytes)
    assert not verify_proof(proof, expected_merkle_root_bytes)

def test_reject_invalid_transaction() -> None:
    expected_merkle_root_hex = '96cbb75fd2ef98e4309eebc8a54d2386333d936ded2a0f3e06c23a91bb612f70'
    expected_merkle_root_bytes = hex_str_to_hash(expected_merkle_root_hex)

    proof = TSCMerkleProof(
        ProofTransactionFlag.FULL_TRANSACTION,
        transaction_index=12,
        transaction_bytes=bytes.fromhex('000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'),
        block_hash=hex_str_to_hash('75edb0a69eb195cdd81e310553aa4d25e18450e08f168532a2c2e9cf447bf169'),
        nodes=[
            TSCMerkleNode(TSCMerkleNodeKind.HASH, hex_str_to_hash(text)) if text != "*" else TSCMerkleNode(TSCMerkleNodeKind.DUPLICATE) for text in [
                'b9ef07a62553ef8b0898a79c291b92c60f7932260888bde0dab2dd2610d8668e',
                '0fc1c12fb1b57b38140442927fbadb3d1e5a5039a5d6db355ea25486374f104d',
                '60b0e75dd5b8d48f2d069229f20399e07766dd651ceeed55ee3c040aa2812547',
                'c0d8dbda46366c2050b430a05508a3d96dc0ed55aea685bb3d9a993f8b97cc6f',
                '391e62b3419d8a943f7dbc7bddc90e30ec724c033000dc0c8872253c27b03a42'
            ]
        ]
    )
    assert not verify_proof(proof, expected_merkle_root_bytes)
