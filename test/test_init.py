import sigstore_tsp

def test_version() -> None:
    version = getattr(sigstore_tsp, "__version__", None)
    assert version is not None
    assert isinstance(version, str)
