"""Guard the Font Awesome icons used in the template.

Font Awesome 6 renamed several icons. A class that no longer exists renders as
an empty square instead of a glyph, which is invisible in the markup but
obvious on screen. This test keeps the template in step with the library.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = PROJECT_ROOT / "templates" / "index.html"

# The free tier of Font Awesome 6, as published on cdnjs.
FA_STYLESHEET = (
    "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
)

ICON_PATTERN = re.compile(r"fa-(?:solid|regular|brands) fa-([a-z0-9-]+)")


@pytest.fixture(scope="module")
def template() -> str:
    return TEMPLATE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def used_icons(template: str) -> set[str]:
    return set(ICON_PATTERN.findall(template))


@pytest.fixture(scope="module")
def available_icons() -> set[str]:
    try:
        from urllib.request import urlopen

        with urlopen(FA_STYLESHEET, timeout=20) as response:
            css = response.read().decode("utf-8", errors="ignore")
    except Exception:  # noqa: BLE001 - the test is skipped when offline
        pytest.skip("the Font Awesome stylesheet could not be downloaded")

    return set(re.findall(r"\.fa-([a-z0-9-]+):before", css))


def test_every_icon_exists(used_icons: set[str], available_icons: set[str]):
    missing = sorted(used_icons - available_icons)

    assert not missing, (
        f"these icons do not exist in Font Awesome 6 and render as empty boxes: {missing}"
    )


def test_the_template_uses_icons(template: str):
    assert ICON_PATTERN.findall(template), "the template should use icons"
