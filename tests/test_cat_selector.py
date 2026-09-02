from __future__ import annotations

import threading
import unittest
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.error import HTTPError
from urllib.request import urlopen

from cat_app import server


ROOT = Path(__file__).resolve().parents[1]
CAT_NAMES = (
    "cat.jpg",
    "cat_down.jpg",
    "cat_dress.jpg",
    "cat_sleep.jpg",
    "cat_sleep2.jpg",
)


class _CatSelectorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.elements: dict[str, dict[str, str | None]] = {}
        self.empty_state_hidden = False

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        values = dict(attrs)
        element_id = values.get("id")
        if element_id:
            self.elements[element_id] = values
        classes = set((values.get("class") or "").split())
        if "empty-state" in classes and values.get("aria-hidden") == "true":
            self.empty_state_hidden = True


class CatSelectorTests(unittest.TestCase):
    def test_selector_controls_are_accessible(self) -> None:
        parser = _CatSelectorParser()
        parser.feed((ROOT / "static" / "index.html").read_text(encoding="utf-8"))

        self.assertFalse(parser.empty_state_hidden)
        image = parser.elements["mainCatImage"]
        self.assertEqual(image.get("src"), "/asset/cat.jpg")
        self.assertTrue(image.get("alt"))
        for element_id in ("previousCatButton", "nextCatButton"):
            button = parser.elements[element_id]
            self.assertEqual(button.get("type"), "button")
            self.assertTrue(button.get("aria-label"))
            self.assertEqual(button.get("aria-controls"), "mainCatImage")
        self.assertNotIn("catImagePosition", parser.elements)
        self.assertNotIn("5개 중", (ROOT / "static" / "index.html").read_text(encoding="utf-8"))

    def test_selector_uses_only_the_five_allowed_images_and_persists_id(self) -> None:
        app = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        image_list = app.split("const CAT_IMAGES = Object.freeze([", 1)[1].split(
            "]);",
            1,
        )[0]

        for name in CAT_NAMES:
            self.assertIn(f'id: "{name}"', image_list)
            self.assertIn(f'src: "/asset/{name}"', image_list)
        self.assertEqual(image_list.count("id:"), len(CAT_NAMES))
        self.assertEqual(image_list.count("src:"), len(CAT_NAMES))
        self.assertIn('readPreference("cat.main_image")', app)
        self.assertIn('writePreference("cat.main_image"', app)
        self.assertIn("item.id === preferredId", app)
        self.assertIn('previousCatButton?.addEventListener("click"', app)
        self.assertIn('nextCatButton?.addEventListener("click"', app)
        self.assertIn(") % CAT_IMAGES.length", app)

    def test_selector_styles_keep_mixed_aspect_ratio_photos_visible(self) -> None:
        styles = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")

        image_styles = styles.split(".cat-selector img", 1)[1].split("}", 1)[0]
        button_styles = styles.split(".cat-selector-button {", 1)[1].split("}", 1)[0]
        focus_styles = styles.split(
            ".cat-selector-button:focus-visible",
            1,
        )[1].split("}", 1)[0]
        self.assertIn("object-fit: contain", image_styles)
        self.assertIn("width: 46px", button_styles)
        self.assertIn("min-height: 46px", button_styles)
        self.assertIn("outline: 3px solid var(--focus)", focus_styles)
        self.assertIn("0 0 0 2px #fff", focus_styles)

    def test_server_asset_allowlist_points_to_existing_image_files(self) -> None:
        expected = {f"/asset/{name}" for name in CAT_NAMES}

        self.assertEqual(set(server.CAT_IMAGE_ASSETS), expected)
        for path in server.CAT_IMAGE_ASSETS.values():
            self.assertTrue(path.is_file(), path)
            self.assertEqual(path.parent, ROOT / "images")

    def test_cat_images_have_no_private_metadata_or_trailing_media(self) -> None:
        forbidden_signatures = (
            b"Exif\x00\x00",
            b"http://ns.adobe.com/xap/",
            b"MotionPhoto",
            b"video/mp4",
            b"PhotoEditor_Re_Edit_Data",
            b"storage/emulated",
            b"data/sec/photoeditor",
        )
        for name in CAT_NAMES:
            with self.subTest(name=name):
                payload = (ROOT / "images" / name).read_bytes()
                self.assertTrue(payload.startswith(b"\xff\xd8"))
                self.assertTrue(payload.endswith(b"\xff\xd9"))
                self.assertEqual(payload.rfind(b"\xff\xd9"), len(payload) - 2)
                for signature in forbidden_signatures:
                    self.assertNotIn(signature, payload)

    def test_server_routes_only_allowlisted_cat_assets(self) -> None:
        for name in CAT_NAMES:
            handler = SimpleNamespace(
                path=f"/asset/{name}?cache=test",
                _serve_static=mock.Mock(),
                _error=mock.Mock(),
            )
            server.CATRequestHandler.do_GET(handler)
            handler._serve_static.assert_called_once_with(ROOT / "images" / name)
            handler._error.assert_not_called()

        handler = SimpleNamespace(
            path="/asset/../README.md",
            _serve_static=mock.Mock(),
            _error=mock.Mock(),
        )
        server.CATRequestHandler.do_GET(handler)
        handler._serve_static.assert_not_called()
        handler._error.assert_called_once()

    def test_http_server_serves_every_cat_image_and_rejects_unknown_paths(self) -> None:
        httpd = server.CATHTTPServer(
            ("127.0.0.1", 0),
            server.CATRequestHandler,
        )
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            with mock.patch.object(server.CATRequestHandler, "log_message"):
                for name in CAT_NAMES:
                    with urlopen(f"{base_url}/asset/{name}", timeout=2) as response:
                        self.assertEqual(response.status, 200)
                        self.assertEqual(
                            response.headers.get_content_type(),
                            "image/jpeg",
                        )
                        self.assertEqual(
                            response.read(),
                            (ROOT / "images" / name).read_bytes(),
                        )
                with self.assertRaises(HTTPError) as raised:
                    urlopen(
                        f"{base_url}/asset/%2e%2e/README.md",
                        timeout=2,
                    )
                self.assertEqual(raised.exception.code, 404)
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(2)
        self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
