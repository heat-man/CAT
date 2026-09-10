from __future__ import annotations

from http import HTTPStatus
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from cat_app import server


ROOT = Path(__file__).resolve().parents[1]


class CursorAssetTests(unittest.TestCase):
    def test_exact_cursor_route_and_query_use_supplied_sprite(self) -> None:
        for path in ("/asset/cat_cursor.png", "/asset/cat_cursor.png?cache=test"):
            with self.subTest(path=path):
                handler = SimpleNamespace(
                    path=path,
                    _serve_static=mock.Mock(),
                    _error=mock.Mock(),
                )
                server.CATRequestHandler.do_GET(handler)
                handler._serve_static.assert_called_once_with(ROOT / "images" / "cat_cursor.png")
                handler._error.assert_not_called()

    def test_cursor_sprite_is_not_a_carousel_photo(self) -> None:
        self.assertNotIn("/asset/cat_cursor.png", server.CAT_IMAGE_ASSETS)
        self.assertNotIn(ROOT / "images" / "cat_cursor.png", server.CAT_IMAGE_ASSETS.values())

    def test_sprite_is_served_as_png_without_cache(self) -> None:
        handler = SimpleNamespace(_send_bytes=mock.Mock(), _error=mock.Mock())
        sprite = ROOT / "images" / "cat_cursor.png"
        payload = sprite.read_bytes()
        self.assertTrue(payload.startswith(b"\x89PNG\r\n\x1a\n"))
        server.CATRequestHandler._serve_static(handler, sprite)
        handler._send_bytes.assert_called_once_with(
            payload,
            status=HTTPStatus.OK,
            content_type="image/png",
            extra_headers={"Cache-Control": "no-store"},
        )
        handler._error.assert_not_called()

    def test_missing_sprite_returns_not_found(self) -> None:
        handler = SimpleNamespace(
            path="/asset/cat_cursor.png",
            _send_bytes=mock.Mock(),
            _error=mock.Mock(),
        )
        handler._serve_static = lambda path: server.CATRequestHandler._serve_static(handler, path)
        with tempfile.TemporaryDirectory(prefix="cat-cursor-test-") as temp_dir:
            with mock.patch.object(server, "CAT_IMAGE_ROOT", Path(temp_dir)):
                server.CATRequestHandler.do_GET(handler)
        handler._send_bytes.assert_not_called()
        self.assertEqual(handler._error.call_args.args[0], HTTPStatus.NOT_FOUND)

    def test_unlisted_paths_and_windows_metadata_are_not_served(self) -> None:
        for path in (
            "/images/cat_cursor.png",
            "/asset/cat_cursor.png:Zone.Identifier",
            "/asset/cat_cursor.png%3AZone.Identifier",
            "/asset/cat_cursor.png/anything",
            "/asset/../images/cat_cursor.png",
            "/asset/%2e%2e/images/cat_cursor.png",
            "/asset/CAT_CURSOR.PNG",
        ):
            with self.subTest(path=path):
                handler = SimpleNamespace(
                    path=path,
                    _serve_static=mock.Mock(),
                    _error=mock.Mock(),
                )
                server.CATRequestHandler.do_GET(handler)
                handler._serve_static.assert_not_called()
                self.assertEqual(handler._error.call_args.args[0], HTTPStatus.NOT_FOUND)


if __name__ == "__main__":
    unittest.main()
