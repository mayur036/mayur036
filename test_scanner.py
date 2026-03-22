import json
import unittest

import anthropic_scanner as scanner


class ScannerTests(unittest.TestCase):
    def test_mask_key_obscures_body(self):
        original = "sk-ant-api03-abcdefghijklmnop"
        masked = scanner.mask_key(original)
        self.assertTrue(masked.startswith("sk-ant-"))
        self.assertTrue(masked.endswith(original[-4:]))
        self.assertNotIn("api03", masked)
        self.assertEqual(len(masked), len(original))

    def test_regex_detection(self):
        content = "const key = 'sk-ant-api03-abcdefghijklmnop';"
        findings = list(scanner.find_in_text(content, "repo", "file.js"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["detection_type"], "regex")
        self.assertTrue(findings[0]["masked_key"].startswith("sk-ant-"))

    def test_keyword_detection_without_key(self):
        content = "const anthropicClient = new Client(api_key);"
        findings = list(scanner.find_in_text(content, "repo", "file.js"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["detection_type"], "keyword")
        self.assertIsNone(findings[0]["masked_key"])

    def test_results_serializable(self):
        # Ensure scan result structure is JSON serializable even with no repositories.
        empty_results = {
            "owner": "example",
            "scanned_repositories": 0,
            "findings": [],
            "generated_at": "2024-01-01T00:00:00Z",
            "advice": "Rotate keys",
        }
        json.dumps(empty_results)  # Should not raise


if __name__ == "__main__":
    unittest.main()
