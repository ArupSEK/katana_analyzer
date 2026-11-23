import csv
import tempfile
import unittest
from pathlib import Path

from katana_analyzer import analyze, classify, csv_safe


class ClassifierTests(unittest.TestCase):
    def test_dynamic_extensions(self):
        for suffix in ("action", "do", "jsp", "jspx", "ashx", "php", "aspx", "asmx", "svc", "jsf", "faces", "cgi", "pl", "cfm"):
            with self.subTest(suffix=suffix):
                self.assertIn("dynamic_endpoints", classify("/portal/page." + suffix, ()))

    def test_parameter_candidates(self):
        tags = classify("/v1/detail", ("id", "url", "redirect"))
        self.assertTrue({"idor", "sqli", "ssrf", "redirect", "parameters"}.issubset(tags))

    def test_directory_names_do_not_create_fake_vulnerabilities(self):
        self.assertNotIn("idor", classify("/articles/overview", ()))

    def test_csv_formula_guard(self):
        self.assertEqual(csv_safe("=1+1"), "'=1+1")
        self.assertEqual(csv_safe("  @foo"), "'  @foo")


class EndToEndTests(unittest.TestCase):
    def test_exports_and_html_escaping(self):
        urls = "\n".join([
            "https://example.test/admin/users/edit.action?id=12&token=SECRET_DO_NOT_INCLUDE",
            "https://example.test/admin/users/edit.action?token=ANOTHER_SECRET&id=13",
            "https://example.test/api/v1/users/123",
            "https://example.test/upload/file.do",
            "https://example.test/a%3Cscript%3E.js",
            "https://example.test/search.php?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "https://example.test/assets/style.css",
            "",
        ])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            input_file = root / "devdolphin_katana"
            input_file.write_text(urls, encoding="utf-8")
            output = root / "output"
            stats = analyze(input_file, output)
            self.assertEqual(stats["unique_urls"], 7)
            self.assertEqual(stats["endpoint_signatures"], 6)
            self.assertTrue((output / "categories" / "dynamic_endpoints.txt").exists())
            self.assertIn(".action", (output / "categories" / "dynamic_endpoints.txt").read_text())
            self.assertIn("example.test", (output / "url_tree.txt").read_text())
            result = (output / "url_explorer.html").read_text()
            self.assertNotIn("SECRET_DO_NOT_INCLUDE", result)
            self.assertNotIn("ANOTHER_SECRET", result)
            self.assertNotIn("alert(1)", result)
            self.assertIn("id, token", result)
            self.assertIn('id="category"', result)
            with (output / "url_inventory.csv").open(newline="") as file:
                rows = list(csv.DictReader(file))
            self.assertEqual(len(rows), 6)


if __name__ == "__main__":
    unittest.main()
