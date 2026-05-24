"""Unit tests for the AI assistant core module."""

import unittest
from browser.core.assistant import (
    AssistantConfig,
    AssistantMessage,
    AssistantSessionState,
    build_context,
    build_custom_prompt,
    build_preset_prompt,
    clamp_text,
    check_config,
    transcript_to_gemini_contents,
)


class TestClampText(unittest.TestCase):
    def test_no_truncation(self):
        self.assertEqual(clamp_text("hello", 100), "hello")

    def test_truncation_adds_marker(self):
        result = clamp_text("x" * 100, 20)
        self.assertIn("truncated", result)
        self.assertTrue(len(result) > 20)

    def test_exact_length(self):
        text = "abcde"
        self.assertEqual(clamp_text(text, 5), text)


class TestBuildContext(unittest.TestCase):
    def setUp(self):
        self.config = AssistantConfig(selection_max_chars=500, page_text_max_chars=1000)

    def test_url_and_title(self):
        session = AssistantSessionState(
            attached_url="http://example.com",
            attached_title="Example Page",
        )
        ctx = build_context(session, self.config)
        self.assertIn("http://example.com", ctx)
        self.assertIn("Example Page", ctx)

    def test_selection_clipped(self):
        session = AssistantSessionState(
            attached_selection="a" * 600,
        )
        ctx = build_context(session, self.config)
        self.assertIn("truncated", ctx)

    def test_page_text_clipped(self):
        session = AssistantSessionState(
            attached_page_text="b" * 1200,
        )
        ctx = build_context(session, self.config)
        self.assertIn("truncated", ctx)

    def test_empty_context(self):
        session = AssistantSessionState()
        ctx = build_context(session, self.config)
        self.assertEqual(ctx.strip(), "")


class TestPresetPrompts(unittest.TestCase):
    def setUp(self):
        self.config = AssistantConfig()
        self.session = AssistantSessionState(
            attached_url="http://example.com",
            attached_title="Test",
            attached_page_text="The quick brown fox jumps over the lazy dog.",
        )

    def test_summarize_prompt(self):
        prompt = build_preset_prompt("summarize", self.session, self.config)
        self.assertIsNotNone(prompt)
        self.assertIn("Summarize", prompt)
        self.assertIn("quick brown fox", prompt)

    def test_what_is_this_prompt(self):
        prompt = build_preset_prompt("what-is-this", self.session, self.config)
        self.assertIsNotNone(prompt)
        self.assertIn("describe", prompt.lower())

    def test_unknown_preset(self):
        prompt = build_preset_prompt("nonexistent", self.session, self.config)
        self.assertIsNone(prompt)

    def test_empty_context_no_prompt(self):
        empty = AssistantSessionState()
        prompt = build_preset_prompt("summarize", empty, self.config)
        self.assertIsNone(prompt)


class TestCustomPrompt(unittest.TestCase):
    def setUp(self):
        self.config = AssistantConfig()
        self.session = AssistantSessionState(
            attached_url="http://example.com",
            attached_title="Test",
        )

    def test_with_context(self):
        prompt = build_custom_prompt("What is this?", self.session, self.config)
        self.assertIn("Context:", prompt)
        self.assertIn("What is this?", prompt)

    def test_without_context(self):
        empty = AssistantSessionState()
        prompt = build_custom_prompt("Hello", empty, self.config)
        self.assertEqual(prompt, "User question: Hello")


class TestTranscriptToGemini(unittest.TestCase):
    def test_conversion(self):
        session = AssistantSessionState()
        session.messages = [
            AssistantMessage(role="user", content="Hello"),
            AssistantMessage(role="assistant", content="Hi there!"),
        ]
        contents = transcript_to_gemini_contents(session)
        self.assertEqual(len(contents), 2)
        self.assertEqual(contents[0]["role"], "user")
        self.assertEqual(contents[0]["parts"][0]["text"], "Hello")
        self.assertEqual(contents[1]["role"], "model")
        self.assertEqual(contents[1]["parts"][0]["text"], "Hi there!")

    def test_empty_transcript(self):
        session = AssistantSessionState()
        contents = transcript_to_gemini_contents(session)
        self.assertEqual(contents, [])


class TestSessionState(unittest.TestCase):
    def test_has_context(self):
        session = AssistantSessionState()
        self.assertFalse(session.has_context)
        session.attached_url = "http://test.com"
        self.assertTrue(session.has_context)

    def test_streaming_text(self):
        session = AssistantSessionState()
        session.pending_accumulated = "streaming text"
        self.assertEqual(session.streaming_text(), "streaming text")

    def test_in_flight_toggle(self):
        session = AssistantSessionState()
        self.assertFalse(session.in_flight)
        session.in_flight = True
        self.assertTrue(session.in_flight)


class TestAssistantConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = AssistantConfig()
        self.assertEqual(cfg.model, "gemini-2.5-flash")
        self.assertTrue(cfg.stream)
        self.assertEqual(cfg.temperature, 0.3)

    def test_custom(self):
        cfg = AssistantConfig(
            model="custom-model",
            temperature=0.7,
            max_output_tokens=500,
        )
        self.assertEqual(cfg.model, "custom-model")
        self.assertEqual(cfg.temperature, 0.7)
        self.assertEqual(cfg.max_output_tokens, 500)


import os


class TestCheckConfig(unittest.TestCase):
    def setUp(self):
        self._orig = {
            "GOOGLE_GENAI_USE_VERTEXAI": os.environ.pop("GOOGLE_GENAI_USE_VERTEXAI", None),
            "GOOGLE_CLOUD_PROJECT": os.environ.pop("GOOGLE_CLOUD_PROJECT", None),
        }

    def tearDown(self):
        for k, v in self._orig.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)

    def test_missing_vertex_flag(self):
        os.environ.pop("GOOGLE_GENAI_USE_VERTEXAI", None)
        err = check_config()
        self.assertIn("GOOGLE_GENAI_USE_VERTEXAI", err)

    def test_missing_project(self):
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "true"
        os.environ.pop("GOOGLE_CLOUD_PROJECT", None)
        err = check_config()
        self.assertIn("GOOGLE_CLOUD_PROJECT", err)

    def test_valid_config(self):
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "true"
        os.environ["GOOGLE_CLOUD_PROJECT"] = "test-project"
        err = check_config()
        self.assertIsNone(err)


if __name__ == "__main__":
    unittest.main()
