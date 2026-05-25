"""Unit tests for the AI assistant core module."""

import os
import unittest
from types import SimpleNamespace

from browser.core.assistant import (
    AssistantConfig,
    AssistantMessage,
    AssistantSessionState,
    build_context,
    build_custom_prompt,
    build_custom_request,
    build_general_prompt,
    build_page_hybrid_prompt,
    build_preset_display_text,
    build_preset_prompt,
    build_preset_request,
    check_config,
    clamp_text,
    classify_request_mode,
    has_freshness_cue,
    render_assistant_message_html,
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
        self.assertEqual(clamp_text("abcde", 5), "abcde")


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
        session = AssistantSessionState(attached_selection="a" * 600)
        ctx = build_context(session, self.config)
        self.assertIn("truncated", ctx)

    def test_selection_marked_as_primary_focus(self):
        session = AssistantSessionState(
            attached_selection="Super Retina XDR",
            attached_page_text="iPhone display details",
        )
        ctx = build_context(session, self.config)
        self.assertIn("Selected text (primary focus)", ctx)
        self.assertIn("Supporting page text", ctx)

    def test_page_text_clipped(self):
        session = AssistantSessionState(attached_page_text="b" * 1200)
        ctx = build_context(session, self.config)
        self.assertIn("truncated", ctx)

    def test_empty_context(self):
        self.assertEqual(build_context(AssistantSessionState(), self.config).strip(), "")


class TestClassification(unittest.TestCase):
    def test_general_prompt_routes_to_general_grounded(self):
        session = AssistantSessionState(
            attached_url="http://example.com",
            attached_title="Example",
            attached_page_text="Page text",
        )
        self.assertEqual(classify_request_mode("write a python script", session), "general-grounded")

    def test_selection_followup_routes_to_page_hybrid(self):
        session = AssistantSessionState(
            attached_selection="Super Retina XDR",
            attached_page_text="Display details",
        )
        self.assertEqual(classify_request_mode("what does this mean?", session), "page-hybrid")

    def test_selection_does_not_hijack_general_prompt(self):
        session = AssistantSessionState(
            attached_selection="Super Retina XDR",
            attached_page_text="Display details",
        )
        self.assertEqual(classify_request_mode("explain quantum mechanics", session), "general-grounded")

    def test_page_reference_routes_to_page_hybrid(self):
        session = AssistantSessionState(attached_page_text="Page text")
        self.assertEqual(classify_request_mode("What is on this page?", session), "page-hybrid")

    def test_freshness_detected(self):
        self.assertTrue(has_freshness_cue("what is the latest bitcoin price"))


class TestPromptBuilders(unittest.TestCase):
    def setUp(self):
        self.config = AssistantConfig()
        self.session = AssistantSessionState(
            attached_url="http://example.com",
            attached_title="Test",
            attached_page_text="The quick brown fox jumps over the lazy dog.",
        )

    def test_general_prompt_does_not_force_page_scope(self):
        prompt = build_general_prompt("write a python script")
        self.assertIn("do not refuse", prompt.lower())
        self.assertNotIn("Context:", prompt)

    def test_page_hybrid_prompt_uses_context(self):
        prompt = build_page_hybrid_prompt("What is on this page?", self.session, self.config)
        self.assertIn("Context:", prompt)
        self.assertIn("grounded web knowledge", prompt)

    def test_build_custom_prompt_general(self):
        prompt = build_custom_prompt("write a python script", self.session, self.config)
        self.assertIn("do not refuse", prompt.lower())
        self.assertNotIn("Context:", prompt)

    def test_build_custom_prompt_page_hybrid(self):
        self.session.attached_selection = "Super Retina XDR"
        prompt = build_custom_prompt("what does this mean?", self.session, self.config)
        self.assertIn("Context:", prompt)
        self.assertIn("selected text", prompt.lower())

    def test_summarize_prompt(self):
        prompt = build_preset_prompt("summarize", self.session, self.config)
        self.assertIsNotNone(prompt)
        self.assertIn("Summarize", prompt)
        self.assertIn("quick brown fox", prompt)

    def test_explain_prompt_mentions_grounding(self):
        self.session.attached_selection = "Super Retina XDR"
        prompt = build_preset_prompt("explain", self.session, self.config)
        self.assertIsNotNone(prompt)
        self.assertIn("grounded web knowledge", prompt)

    def test_unknown_preset(self):
        self.assertIsNone(build_preset_prompt("nonexistent", self.session, self.config))

    def test_empty_context_no_preset_prompt(self):
        self.assertIsNone(build_preset_prompt("summarize", AssistantSessionState(), self.config))


class TestRequestBuilders(unittest.TestCase):
    def setUp(self):
        self.config = AssistantConfig(stream=True)
        self.session = AssistantSessionState(
            attached_url="http://example.com",
            attached_title="Test",
            attached_page_text="Useful page text",
        )

    def test_general_request_uses_grounding(self):
        request = build_custom_request("who is the president of usa", self.session, self.config)
        self.assertEqual(request.mode, "general-grounded")
        self.assertTrue(request.use_grounding)
        self.assertFalse(request.stream)

    def test_page_request_uses_grounding(self):
        self.session.attached_selection = "Super Retina XDR"
        request = build_custom_request("what does this mean?", self.session, self.config)
        self.assertEqual(request.mode, "page-hybrid")
        self.assertTrue(request.use_grounding)

    def test_summarize_request_stays_page_summary(self):
        request = build_preset_request("summarize", self.session, self.config)
        self.assertIsNotNone(request)
        self.assertEqual(request.mode, "page-summary")
        self.assertFalse(request.use_grounding)
        self.assertTrue(request.stream)

    def test_explain_request_is_hybrid(self):
        request = build_preset_request("explain", self.session, self.config)
        self.assertIsNotNone(request)
        self.assertEqual(request.mode, "page-hybrid")
        self.assertTrue(request.use_grounding)
        self.assertFalse(request.stream)


class TestRendering(unittest.TestCase):
    def test_safe_html_escaping(self):
        rendered = render_assistant_message_html("<b>unsafe</b>\nline 2")
        self.assertIn("&lt;b&gt;unsafe&lt;/b&gt;", rendered)
        self.assertIn("line 2", rendered)

    def test_inline_citations_with_dict_metadata(self):
        metadata = {
            "grounding_supports": [
                {
                    "segment": {"end_index": 5},
                    "grounding_chunk_indices": [0],
                }
            ],
            "grounding_chunks": [
                {
                    "web": {
                        "uri": "https://example.com/source",
                        "title": "Source Title",
                    }
                }
            ],
        }
        rendered = render_assistant_message_html("Hello world", metadata)
        self.assertIn("https://example.com/source", rendered)
        self.assertIn("[1]", rendered)

    def test_inline_citations_with_object_metadata(self):
        metadata = SimpleNamespace(
            grounding_supports=[
                SimpleNamespace(
                    segment=SimpleNamespace(end_index=11),
                    grounding_chunk_indices=[0],
                )
            ],
            grounding_chunks=[
                SimpleNamespace(
                    web=SimpleNamespace(
                        uri="https://example.com/obj",
                        title="Object Source",
                    )
                )
            ],
            search_entry_point=SimpleNamespace(rendered_content="<div>Search chip</div>"),
        )
        rendered = render_assistant_message_html("Hello world!", metadata)
        self.assertIn("https://example.com/obj", rendered)
        self.assertIn("Search chip", rendered)


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

    def test_model_content_takes_precedence(self):
        session = AssistantSessionState()
        session.messages = [
            AssistantMessage(
                role="user",
                content="Explain selection",
                model_content="Context:\n...\n\nUser question: Explain selection",
            ),
        ]
        contents = transcript_to_gemini_contents(session)
        self.assertEqual(contents[0]["parts"][0]["text"], "Context:\n...\n\nUser question: Explain selection")

    def test_empty_transcript(self):
        self.assertEqual(transcript_to_gemini_contents(AssistantSessionState()), [])


class TestPresetDisplayText(unittest.TestCase):
    def test_selection_label(self):
        self.assertEqual(build_preset_display_text("explain", has_selection=True), "Explain selection")

    def test_page_label(self):
        self.assertEqual(build_preset_display_text("summarize", has_selection=False), "Summarize page")


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
        cfg = AssistantConfig(model="custom-model", temperature=0.7, max_output_tokens=500)
        self.assertEqual(cfg.model, "custom-model")
        self.assertEqual(cfg.temperature, 0.7)
        self.assertEqual(cfg.max_output_tokens, 500)


class TestCheckConfig(unittest.TestCase):
    def setUp(self):
        self._orig = {
            "GOOGLE_GENAI_USE_VERTEXAI": os.environ.pop("GOOGLE_GENAI_USE_VERTEXAI", None),
            "GOOGLE_CLOUD_PROJECT": os.environ.pop("GOOGLE_CLOUD_PROJECT", None),
        }

    def tearDown(self):
        for key, value in self._orig.items():
            if value is not None:
                os.environ[key] = value
            else:
                os.environ.pop(key, None)

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
        self.assertIsNone(check_config())


if __name__ == "__main__":
    unittest.main()
