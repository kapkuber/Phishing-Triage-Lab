from email import policy
from email.parser import BytesParser
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "synthetic_sample.eml"


@pytest.fixture
def synthetic_msg():
    with FIXTURE.open("rb") as f:
        return BytesParser(policy=policy.default).parse(f)
