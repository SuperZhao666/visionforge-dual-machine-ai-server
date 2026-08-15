import pytest


@pytest.fixture(autouse=True)
def reset_rate_limiter_between_tests():
    from app.security import limiter

    limiter.reset()
    yield
    limiter.reset()
