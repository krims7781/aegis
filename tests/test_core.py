"""
Tests for Aegis core components.
Run with: pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from core.aho_corasick import AhoCorasick
from core.scrubber import Scrubber
from core.vault import Vault


# ---------------------------------------------------------------------------
# Aho-Corasick tests
# ---------------------------------------------------------------------------
class TestAhoCorasick:

    def test_single_pattern(self):
        ac = AhoCorasick()
        ac.add_pattern("hello")
        ac.build()
        results = ac.search("say hello world")
        assert any(p == "hello" for _, p in results)

    def test_multiple_patterns(self):
        ac = AhoCorasick()
        for word in ["he", "she", "his", "hers"]:
            ac.add_pattern(word)
        ac.build()
        text = "ushers"
        matches = [p for _, p in ac.search(text)]
        assert "she" in matches
        assert "he" in matches
        assert "hers" in matches

    def test_no_match(self):
        ac = AhoCorasick()
        ac.add_pattern("xyz")
        ac.build()
        assert ac.search("hello world") == []

    def test_overlapping_patterns(self):
        ac = AhoCorasick()
        ac.add_pattern("ab")
        ac.add_pattern("abc")
        ac.build()
        results = ac.search("xabcy")
        patterns = [p for _, p in results]
        assert "ab" in patterns
        assert "abc" in patterns

    def test_empty_text(self):
        ac = AhoCorasick()
        ac.add_pattern("test")
        ac.build()
        assert ac.search("") == []

    def test_linear_time_large_input(self):
        """Smoke test: 100k character input should complete instantly."""
        import time
        ac = AhoCorasick()
        for word in ["secret", "password", "token", "key"]:
            ac.add_pattern(word)
        ac.build()
        text = "x" * 50000 + "password" + "x" * 50000
        t0 = time.perf_counter()
        results = ac.search(text)
        elapsed = time.perf_counter() - t0
        assert elapsed < 1.0   # must finish in under 1 second
        assert any(p == "password" for _, p in results)


# ---------------------------------------------------------------------------
# Scrubber tests
# ---------------------------------------------------------------------------
class TestScrubber:

    def setup_method(self):
        self.scrubber = Scrubber()

    def test_email_redaction(self):
        result = self.scrubber.scrub("Contact me at john.doe@example.com please")
        assert "john.doe@example.com" not in result.sanitized
        assert "[EMAIL]" in result.sanitized
        assert result.regex_matches >= 1

    def test_phone_redaction(self):
        result = self.scrubber.scrub("Call me at +91-9876543210")
        assert "9876543210" not in result.sanitized

    def test_credit_card_redaction(self):
        result = self.scrubber.scrub("My card is 4111 1111 1111 1111")
        assert "4111" not in result.sanitized
        assert "[CREDIT_CARD]" in result.sanitized

    def test_jwt_redaction(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123XYZ"
        result = self.scrubber.scrub(f"Token: {jwt}")
        assert jwt not in result.sanitized

    def test_openai_key_redaction(self):
        key = "sk-" + "a" * 48
        result = self.scrubber.scrub(f"My API key is {key}")
        assert key not in result.sanitized

    def test_no_pii(self):
        text = "The quick brown fox jumps over the lazy dog."
        result = self.scrubber.scrub(text)
        assert result.sanitized == text
        assert result.regex_matches == 0

    def test_multiple_pii_types(self):
        text = "Email: a@b.com, Phone: 9876543210, Card: 4111-1111-1111-1111"
        result = self.scrubber.scrub(text)
        assert "a@b.com" not in result.sanitized
        assert result.regex_matches >= 2

    def test_processing_time_sub_8ms(self):
        """Key performance requirement: scrubbing must be < 8ms."""
        import time
        # Warm up
        self.scrubber.scrub("warmup")
        text = "Send invoice to alice@company.com, phone 9876543210. " * 20
        times = []
        for _ in range(10):
            result = self.scrubber.scrub(text)
            times.append(result.processing_ms)
        avg = sum(times) / len(times)
        assert avg < 8.0, f"Average scrub time {avg:.2f}ms exceeds 8ms threshold"

    def test_keyword_layer(self):
        scrubber = Scrubber(extra_keywords=["project_x", "codename"])
        result = scrubber.scrub("This is about project_x launch")
        assert "[KEYWORD]" in result.sanitized


# ---------------------------------------------------------------------------
# Vault tests
# ---------------------------------------------------------------------------
class TestVault:

    def setup_method(self):
        self.vault = Vault()
        self.vault.clear()

    def test_store_and_restore(self):
        token = self.vault.store("john@acme.com", "EMAIL")
        assert token.startswith("__TK_")
        assert self.vault.restore(token) == "john@acme.com"

    def test_idempotent_store(self):
        t1 = self.vault.store("john@acme.com", "EMAIL")
        t2 = self.vault.store("john@acme.com", "EMAIL")
        assert t1 == t2

    def test_reconstruct(self):
        token = self.vault.store("secret_value", "API_KEY")
        text = f"The value is {token} in the response."
        reconstructed = self.vault.reconstruct(text)
        assert "secret_value" in reconstructed
        assert token not in reconstructed

    def test_restore_unknown_token(self):
        assert self.vault.restore("__TK_UNKNOWN__") is None

    def test_stats(self):
        self.vault.store("a@b.com", "EMAIL")
        self.vault.store("9876543210", "PHONE")
        stats = self.vault.stats()
        assert stats["stored_mappings"] >= 2
