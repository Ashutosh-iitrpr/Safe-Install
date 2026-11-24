"""A harmless package used to demonstrate a clean SafeInstall run."""

__version__ = "0.1.0"


def greet(name: str = "SafeInstall") -> str:
    """Return a deterministic greeting without performing side effects."""
    return f"Hello, {name}!"
