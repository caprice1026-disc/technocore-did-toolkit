import sys

import pytest

from technocore_did.identity import Identity
from technocore_did.keystore_windows import (
    create_keystore,
    load_identity,
    protect_seed,
    unprotect_seed,
)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI integration")
def test_dpapi_round_trip_does_not_embed_plaintext():
    seed = bytes(range(32))
    blob = protect_seed(seed)
    assert seed not in blob
    assert unprotect_seed(blob) == seed


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI integration")
def test_keystore_refuses_overwrite_and_loads_same_identity(tmp_path):
    path = tmp_path / "identity.dpapi"
    identity = Identity.from_seed(bytes(32))
    create_keystore(path, identity)
    assert load_identity(path).did == identity.did
    with pytest.raises(FileExistsError):
        create_keystore(path, identity)

