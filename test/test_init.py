import rfc3161_client


def test_version() -> None:
    version = getattr(rfc3161_client, "__version__", None)
    assert version is not None
    assert isinstance(version, str)
