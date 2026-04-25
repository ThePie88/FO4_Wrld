"""Shared pytest config for the net/ test suite."""
import pytest


def pytest_collection_modifyitems(config, items):
    """Mark async test functions as asyncio for pytest-asyncio discovery."""
    for item in items:
        if item.get_closest_marker("asyncio") is None:
            # Heuristic: coroutines need the asyncio mark
            try:
                import inspect
                if inspect.iscoroutinefunction(item.function):
                    item.add_marker(pytest.mark.asyncio)
            except Exception:
                pass
