from technocore_did.state import (
    PublicState,
    load_state,
    propose_nonce,
    record_nonce,
    save_state,
)


def test_state_proposes_nonce_without_persisting_then_records_it(tmp_path):
    path = tmp_path / "state.json"
    state = PublicState.create("did:key:zexample", "mb-p-0123456789abcdef")
    save_state(path, state)

    loaded = load_state(path)
    nonce = propose_nonce(loaded, "lobby", 1_700_000_000_000)

    assert nonce == 1_700_000_000_000
    assert load_state(path).last_nonce_by_room == {}
    recorded = record_nonce(path, loaded, "lobby", nonce)
    assert recorded.last_nonce_by_room == {"lobby": nonce}
    assert load_state(path).last_nonce_by_room == {"lobby": nonce}


def test_state_write_leaves_no_temporary_file(tmp_path):
    path = tmp_path / "state.json"
    save_state(
        path,
        PublicState.create("did:key:zexample", "mb-p-0123456789abcdef"),
    )
    assert sorted(item.name for item in tmp_path.iterdir()) == ["state.json"]

