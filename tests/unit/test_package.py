import trustkit


def test_package_importable() -> None:
    assert trustkit.__version__ == "0.0.0"
