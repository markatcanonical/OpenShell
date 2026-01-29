"""Basic tests for the navigator package."""

import navigator


def test_version() -> None:
    """Test that version is defined."""
    assert navigator.__version__ == "0.1.0"
