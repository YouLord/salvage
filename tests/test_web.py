"""Веб-пульт: автономная страница и безопасный адрес по умолчанию.

Пульт не должен тянуть внешние ресурсы (иначе без интернета он «ломается»,
а заодно стучится наружу) и не должен по умолчанию слушать всю сеть.
"""
from __future__ import annotations

import re
import unittest

from salvage import web


class TestWebSelfContained(unittest.TestCase):
    def _pages(self) -> dict[str, str]:
        return {"index": web.index_page(), "page": web.page("t", "<p>x</p>")}

    def test_no_external_resources(self) -> None:
        for name, html in self._pages().items():
            external = re.findall(r'(?:src|href)\s*=\s*["\']\s*https?://', html, re.I)
            self.assertEqual(external, [], f"{name}: внешние ресурсы")
            self.assertNotRegex(html, r"(?i)<script[^>]+src=", f"{name}: внешний script")
            self.assertNotRegex(html, r"(?i)<link[^>]+href=", f"{name}: внешний link")
            self.assertNotIn("@import", html, f"{name}: CSS @import")

    def test_styles_are_inline(self) -> None:
        html = web.page("t", "<p>x</p>")
        self.assertIn("<style>", html)
        self.assertIn("</style>", html)

    def test_default_host_is_loopback(self) -> None:
        args = web.build_parser().parse_args([])
        self.assertEqual(args.host, "127.0.0.1",
                         "по умолчанию пульт не должен слушать всю сеть")

    def test_open_host_only_when_explicit(self) -> None:
        args = web.build_parser().parse_args(["--host", "0.0.0.0"])
        self.assertEqual(args.host, "0.0.0.0", "0.0.0.0 разрешён, но только явно")
        self.assertEqual(web.build_parser().parse_args([]).port, 8741)


class TestWebServes(unittest.TestCase):
    """Живой запрос к пульту: страница отдаётся и в ней есть форма скана."""

    def test_index_over_http(self) -> None:
        import threading
        import urllib.request
        from http.server import ThreadingHTTPServer

        srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        try:
            port = srv.server_address[1]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
                self.assertEqual(r.status, 200)
                body = r.read().decode("utf-8")
            self.assertIn("<form", body)
            self.assertIn("salvage", body)
            self.assertNotIn("http://cdn", body)
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
