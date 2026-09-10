from __future__ import annotations

import json
import re
import shutil
import subprocess
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
    "cat_staring.jpg",
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
        self.assertEqual(image.get("src"), "/asset/cat_staring.jpg")
        self.assertTrue(image.get("alt"))
        for element_id in ("previousCatButton", "nextCatButton"):
            button = parser.elements[element_id]
            self.assertEqual(button.get("type"), "button")
            self.assertTrue(button.get("aria-label"))
            self.assertEqual(button.get("aria-controls"), "mainCatImage")
        self.assertNotIn("catImagePosition", parser.elements)
        self.assertNotIn("5개 중", (ROOT / "static" / "index.html").read_text(encoding="utf-8"))

    def test_selector_uses_only_allowed_images_and_persists_id(self) -> None:
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

    def _run_cat_selector(
        self,
        preferences: dict[str, str],
        *,
        actions: tuple[str | int, ...] = (),
        storage_unavailable: bool = False,
    ) -> dict:
        program = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('static/app.js', 'utf8');
const {preferences, actions, storageUnavailable} = JSON.parse(fs.readFileSync(0, 'utf8'));
const image = {};
const storage = {
  getItem: key => { if (storageUnavailable) throw Error('Storage unavailable'); return preferences[key] || ''; },
  setItem: (key, value) => { if (storageUnavailable) throw Error('Storage unavailable'); preferences[key] = value; },
  removeItem: key => { if (storageUnavailable) throw Error('Storage unavailable'); delete preferences[key]; },
};
const sandbox = {mainCatImage: image, window: {localStorage: storage}};
vm.createContext(sandbox);
vm.runInContext(source.slice(source.indexOf('const CAT_IMAGES ='), source.indexOf('let lastReport ='))
  + '\nlet currentCatImageIndex = 0;\n'
  + source.slice(source.indexOf('function readPreference('), source.indexOf('function readAnalysisHistory('))
  + source.slice(source.indexOf('function initializeCatSelector('), source.indexOf('function initializeCatCursor(')), sandbox);
vm.runInContext('initializeCatSelector()', sandbox);
const snapshots = [image.src];
for (const action of actions) {
  vm.runInContext(action === 'reload' ? 'initializeCatSelector()' : `selectCatImage(${Number(action)})`, sandbox);
  snapshots.push(image.src);
}
process.stdout.write(JSON.stringify({src: image.src, preferences, snapshots}));
"""
        result = subprocess.run(
            ["node", "-e", program],
            input=json.dumps({
                "preferences": preferences,
                "actions": actions,
                "storageUnavailable": storage_unavailable,
            }),
            capture_output=True, text=True, check=True, cwd=ROOT, timeout=10,
        )
        return json.loads(result.stdout)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for preference migration tests")
    def test_new_default_replaces_all_pre_migration_choices_once(self) -> None:
        cases = [
            {},
            {"cat.main_image": "cat.jpg"},
            {"cat.main_image": "cat_sleep.jpg"},
            {"cat.main_image": "cat_sleep2.jpg"},
            {"cat.main_image": "cat_sleep2.jpg", "cat.main_image_staring_default_v1": "done"},
            {"cat.main_image": "cat_dress.jpg", "cat.main_image_staring_default_v1": "done"},
            {"cat.main_image": "cat.jpg", "cat.main_image_staring_default_v1": "done"},
        ]
        for preferences in cases:
            with self.subTest(preferences=preferences):
                data = self._run_cat_selector(preferences)
                self.assertEqual(data["src"], "/asset/cat_staring.jpg")
                self.assertEqual(data["preferences"]["cat.main_image"], "cat_staring.jpg")
                self.assertEqual(data["preferences"]["cat.main_image_staring_default_v2"], "done")

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for preference migration tests")
    def test_completed_migration_preserves_later_valid_choices(self) -> None:
        for name in CAT_NAMES:
            preferences = {"cat.main_image": name, "cat.main_image_staring_default_v2": "done"}
            with self.subTest(name=name):
                data = self._run_cat_selector(preferences)
                self.assertEqual(data["src"], f"/asset/{name}")
                self.assertEqual(data["preferences"], preferences)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for preference migration tests")
    def test_post_migration_invalid_choice_falls_back_to_staring(self) -> None:
        for preferred_id in ("", "unknown.jpg", "https://example.invalid/cat.jpg"):
            with self.subTest(preferred_id=preferred_id):
                data = self._run_cat_selector({
                    "cat.main_image": preferred_id,
                    "cat.main_image_staring_default_v2": "done",
                })
                self.assertEqual(data["src"], "/asset/cat_staring.jpg")

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for preference migration tests")
    def test_carousel_choice_survives_reload_after_default_reset(self) -> None:
        data = self._run_cat_selector({"cat.main_image": "cat_sleep2.jpg"}, actions=(-1, "reload"))
        self.assertEqual(data["snapshots"], [
            "/asset/cat_staring.jpg", "/asset/cat_sleep2.jpg", "/asset/cat_sleep2.jpg",
        ])
        self.assertEqual(data["preferences"]["cat.main_image"], "cat_sleep2.jpg")

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for preference migration tests")
    def test_unavailable_storage_keeps_default_and_carousel_usable(self) -> None:
        data = self._run_cat_selector({}, actions=(1,), storage_unavailable=True)
        self.assertEqual(data["snapshots"], ["/asset/cat_staring.jpg", "/asset/cat.jpg"])
        self.assertEqual(data["preferences"], {})

    def test_cursor_clips_sprite_inside_larger_noninteractive_viewport(self) -> None:
        parser = _CatSelectorParser()
        parser.feed((ROOT / "static" / "index.html").read_text(encoding="utf-8"))
        wrapper = parser.elements["catCursor"]
        image = parser.elements["catCursorImage"]
        self.assertEqual(wrapper.get("aria-hidden"), "true")
        self.assertIn("hidden", wrapper)
        self.assertNotIn("src", wrapper)
        self.assertEqual(image.get("src"), "/asset/cat_cursor.png")
        self.assertEqual(image.get("alt"), "")
        self.assertEqual(image.get("draggable"), "false")

        styles = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")
        cursor_styles = styles.split(".cat-cursor {", 1)[1].split("}", 1)[0]
        self.assertIn("overflow: hidden", cursor_styles)
        self.assertIn("pointer-events: none", cursor_styles)
        self.assertIn("position: fixed", cursor_styles)
        width = re.search(r"(?<![\w-])width:\s*(\d+(?:\.\d+)?)px", cursor_styles)
        self.assertIsNotNone(width)
        self.assertGreaterEqual(float(width.group(1)), 80)

    def test_cursor_sprite_uses_left_half_until_pressed(self) -> None:
        styles = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")
        image_styles = styles.split(".cat-cursor img {", 1)[1].split("}", 1)[0]
        pressed_styles = styles.split(".cat-cursor.is-pressed img {", 1)[1].split("}", 1)[0]
        self.assertIn("width: 200%", image_styles)
        self.assertIn("left: 0", image_styles)
        self.assertNotIn("transform:", image_styles)
        self.assertIn("transform: translateX(-50%)", pressed_styles)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for pointer behavior tests")
    def test_cursor_press_release_and_native_pointer_fallback(self) -> None:
        program = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync('static/app.js', 'utf8');
function emitter(object = {}) {
  const handlers = {};
  return Object.assign(object, {addEventListener: (name, fn) => { handlers[name] = fn; },
    emit: (name, event = {}) => handlers[name]?.(event)});
}
const classes = new Set();
const pointer = emitter({matches: true});
const motion = emitter({matches: false});
const image = emitter({complete: false, naturalWidth: 0});
const cursorClasses = new Set();
const cursor = {hidden: true, style: {}, querySelector: () => image,
  classList: {remove: key => cursorClasses.delete(key), toggle: (key, enabled) => {
    if (enabled) cursorClasses.add(key); else cursorClasses.delete(key);
  }}};
const body = {append: image => { image.parentElement = body; }};
body.append(cursor);
const root = emitter({classList: {add: key => classes.add(key), remove: key => classes.delete(key)}});
const document = emitter({querySelector: selector => selector === '#catCursorImage' ? image : cursor, documentElement: root, body, hidden: false});
const pending = new Map();
let nextFrame = 0;
const window = emitter({matchMedia: query => query.includes('reduced-motion') ? motion : pointer,
  requestAnimationFrame: callback => { pending.set(++nextFrame, callback); return nextFrame; },
  cancelAnimationFrame: id => pending.delete(id)});
const sandbox = {document, window};
vm.createContext(sandbox);
vm.runInContext(source.slice(source.indexOf('function initializeCatCursor('), source.indexOf('function resolveAnalysisPayload(')), sandbox);
vm.runInContext('initializeCatCursor()', sandbox);
const move = (pointerType = 'mouse', x = 10, target = {}, buttons = 0) => document.emit('pointermove', {pointerType, clientX: x, clientY: 20, target, buttons});
const press = (pointerType = 'mouse') => document.emit('pointerdown', {pointerType, clientX: 30, clientY: 20, buttons: 1});
const release = (buttons = 0) => document.emit('pointerup', {pointerType: 'mouse', clientX: 30, clientY: 20, buttons});
const flush = () => { for (const callback of pending.values()) callback(); pending.clear(); };
const isNative = () => { assert.equal(cursor.hidden, true); assert.equal(classes.size, 0); assert.equal(cursorClasses.size, 0); };
move(); flush(); isNative(); // A failed or pending image must never remove the native pointer.
press(); flush(); isNative();
image.emit('load'); move(); flush(); isNative(); // An empty image is not ready.
image.naturalWidth = 651; image.emit('load');
move(); move('mouse', 30); assert.equal(pending.size, 1); flush();
assert.equal(cursor.hidden, false); assert.equal(classes.size, 1);
assert.ok(cursor.style.transform.includes('30px'));
assert.equal(cursorClasses.has('is-pressed'), false);
press(); assert.equal(cursorClasses.has('is-pressed'), true); flush();
move('mouse', 40, {}, 1); flush(); assert.equal(cursorClasses.has('is-pressed'), true);
release(); assert.equal(cursorClasses.has('is-pressed'), false); flush();
press(); release(); flush(); assert.equal(cursorClasses.has('is-pressed'), false); // Fast clicks cannot stick.
press(); release(2); flush(); assert.equal(cursorClasses.has('is-pressed'), true); // Another button remains held.
move(); flush(); assert.equal(cursorClasses.has('is-pressed'), false); // Recover if release occurred outside the window.
press(); flush(); document.emit('pointercancel'); isNative();
press(); flush(); document.emit('lostpointercapture'); isNative();
press(); flush(); window.emit('blur'); isNative();
press('touch'); flush(); isNative();
move(); flush();
root.emit('pointerleave'); isNative();
move(); flush(); window.emit('blur'); isNative();
move('touch'); flush(); isNative();
motion.matches = true; move(); flush(); isNative();
motion.matches = false;
pointer.matches = false; move(); flush(); isNative();
pointer.matches = true;
move(); flush(); document.emit('keydown', {key: 'Tab'}); isNative();
move(); flush(); window.emit('beforeprint'); isNative();
const dialog = {append: image => { image.parentElement = dialog; }};
move('mouse', 40, {closest: () => dialog}); flush(); assert.equal(cursor.parentElement, dialog);
document.emit('close'); isNative();
move(); flush(); assert.equal(cursor.parentElement, body);
image.emit('error'); isNative();
move(); flush(); isNative();
"""
        subprocess.run(["node", "-e", program], capture_output=True, text=True, check=True, cwd=ROOT, timeout=10)

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
