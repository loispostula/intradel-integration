"""Verify cookie validation uses the credential that will be stored."""

from unittest.mock import AsyncMock, patch

import pytest
from aiohttp import ClientSession, web
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import (
    async_create_clientsession,
    async_get_clientsession,
)
from pytest_aiohttp import AiohttpServer

from custom_components.intradel.config_flow import InvalidAuth, validate_authentication

from .const import SAMPLE_DATA


@pytest.mark.usefixtures("socket_enabled")
@pytest.mark.parametrize(
    ("cached", "supplied", "accepted"),
    [("stale", "valid", True), ("valid", "stale", False)],
)
async def test_cached_cookie_cannot_override_input(
    hass: HomeAssistant,
    aiohttp_server: AiohttpServer,
    cached: str,
    supplied: str,
    accepted: bool,
) -> None:
    """A cached cookie must neither accept bad input nor reject valid input."""
    received = []

    async def data(request: web.Request) -> web.Response:
        received.append(request.cookies.get("PHPSESSID"))
        return web.Response(text=request.cookies.get("PHPSESSID", ""))

    app = web.Application()
    app.router.add_get("/", data)
    server = await aiohttp_server(app)
    url = server.make_url("/")
    shared_session = async_get_clientsession(hass)
    shared_session.cookie_jar.update_cookies({"PHPSESSID": cached})

    async def fetch(session: ClientSession, *, cookie: str) -> list:
        async with session.get(url, headers={"Cookie": cookie}) as response:
            if await response.text() != "valid":
                raise ValueError("login/password seems incorrect")
            return SAMPLE_DATA

    with (
        patch(
            "custom_components.intradel.config_flow.async_create_clientsession",
            wraps=async_create_clientsession,
        ),
        patch("custom_components.intradel.config_flow.get_data", side_effect=fetch),
    ):
        if accepted:
            await validate_authentication(hass, f"PHPSESSID={supplied}")
        else:
            with pytest.raises(InvalidAuth):
                await validate_authentication(hass, f"PHPSESSID={supplied}")

    assert received == [supplied]
    assert shared_session.cookie_jar.filter_cookies(url)["PHPSESSID"].value == cached
    assert not shared_session.closed


@pytest.mark.parametrize("error", [None, ValueError("rejected", "private HTML"), TimeoutError()])
async def test_validation_detaches_session(
    hass: HomeAssistant, error: Exception | None, caplog: pytest.LogCaptureFixture
) -> None:
    """One-shot sessions detach on success, authentication failure and timeout."""
    with (
        patch("custom_components.intradel.config_flow.async_create_clientsession") as create,
        patch(
            "custom_components.intradel.config_flow.get_data",
            new_callable=AsyncMock,
            return_value=SAMPLE_DATA,
            side_effect=error,
        ),
    ):
        if error is None:
            await validate_authentication(hass, "PHPSESSID=valid")
        else:
            expected = InvalidAuth if isinstance(error, ValueError) else TimeoutError
            with pytest.raises(expected):
                await validate_authentication(hass, "PHPSESSID=valid")
        create.assert_called_once_with(hass, auto_cleanup=False)
        create.return_value.detach.assert_called_once_with()
        create.return_value.close.assert_not_called()

    assert "private HTML" not in caplog.text
