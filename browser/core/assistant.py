"""Hybrid page-aware and general AI assistant using Gemini on Vertex AI."""

import html
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional


_PAGE_REFERENCE_PHRASES = (
    "this page",
    "this text",
    "selected text",
    "selection",
    "selected",
    "highlighted text",
    "highlighted",
    "on this site",
    "on this page",
    "on the page",
    "from this page",
    "from the page",
    "here",
    "above",
    "below",
)

_SELECTION_FOLLOWUP_PHRASES = (
    "what is this",
    "what does this mean",
    "what does it mean",
    "what is it",
    "explain this",
    "explain it",
    "summarize this",
    "summarize it",
    "why is this",
    "why is it",
    "tell me more about this",
)

_FRESHNESS_CUES = (
    "latest",
    "current",
    "today",
    "now",
    "recent",
    "newest",
    "this week",
    "this month",
    "this year",
)

_GENERAL_TASK_PREFIXES = (
    "write ",
    "create ",
    "generate ",
    "make ",
    "draft ",
    "help me ",
    "build ",
    "code ",
)

_SYSTEM_INSTRUCTION = (
    "You are WaterCat Assistant, a helpful assistant built into the WaterCat Browser. "
    "You can answer both questions about the current page and general questions that are unrelated to it. "
    "When page context is relevant, use it first. "
    "If selected text is provided, treat it as the primary focus and use the rest of the page as supporting context. "
    "If the question is unrelated to the current page, answer it normally instead of refusing. "
    "When grounded web results are available, use them to improve factual accuracy. "
    "Never claim you saw content that was not sent to you as context or grounding data. "
    "Keep answers concise and well-structured. Use Markdown formatting. "
    "Use a friendly, helpful tone."
)

_SUMMARIZE_PRESET_PROMPTS = {
    False: (
        "Summarize the following page content in 3-5 concise bullet points. "
        "Focus on the main ideas and key facts:\n\n{context}"
    ),
    True: (
        "Summarize the selected text in 3-5 concise bullet points. "
        "Use the surrounding page context only to clarify what the selection refers to:\n\n{context}"
    ),
}

_EXPLAIN_PRESET_PROMPTS = {
    False: (
        "Explain this page in simple terms. Use the page context first. "
        "If the page context is incomplete, use grounded web knowledge to fill in the missing facts:\n\n{context}"
    ),
    True: (
        "Explain the selected text in simple terms. Use the surrounding page context first to identify what it refers to. "
        "If the page context is incomplete, use grounded web knowledge to complete the explanation:\n\n{context}"
    ),
}

_WHAT_IS_THIS_PRESET_PROMPTS = {
    False: (
        "Describe what this page is about in one paragraph. Use the page context first. "
        "If the page context is incomplete, use grounded web knowledge only to complete the answer:\n\n{context}"
    ),
    True: (
        "Describe what the selected text refers to on this page in one paragraph. "
        "Use the selected text and surrounding page context first. "
        "If the page context is incomplete, use grounded web knowledge to complete the answer:\n\n{context}"
    ),
}

_PRESET_DISPLAY_LABELS = {
    "summarize": ("Summarize selection", "Summarize page"),
    "explain": ("Explain selection", "Explain page"),
    "what-is-this": ("What is this selection?", "What is this page?"),
}


@dataclass
class AssistantMessage:
    role: str
    content: str
    model_content: str = ""
    rendered_html: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class AssistantSessionState:
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    messages: list[AssistantMessage] = field(default_factory=list)
    attached_url: str = ""
    attached_title: str = ""
    attached_page_text: str = ""
    attached_selection: str = ""
    in_flight: bool = False
    cancelled: bool = False
    pending_accumulated: str = ""
    last_error: str = ""

    @property
    def has_context(self) -> bool:
        return bool(self.attached_url or self.attached_selection or self.attached_page_text)

    def streaming_text(self) -> str:
        return self.pending_accumulated


@dataclass
class AssistantConfig:
    enabled: bool = True
    model: str = "gemini-2.5-flash"
    stream: bool = True
    temperature: float = 0.3
    max_output_tokens: int = 1200
    selection_max_chars: int = 8000
    page_text_max_chars: int = 24000


@dataclass(frozen=True)
class AssistantRequest:
    display_content: str
    model_content: str
    mode: str
    use_grounding: bool = False
    stream: bool = False


@dataclass
class AssistantResponse:
    text: str
    rendered_html: str = ""
    grounded: bool = False


def clamp_text(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    truncated = text[:max_chars]
    return truncated + "\n\n[... content truncated, showing first {:,} of {:,} characters ...]".format(
        max_chars, len(text)
    )


def build_context(session: AssistantSessionState, config: AssistantConfig) -> str:
    parts = []
    if session.attached_selection:
        clipped = clamp_text(session.attached_selection, config.selection_max_chars)
        parts.append("Selected text (primary focus):\n```\n{}\n```".format(clipped))
    if session.attached_title:
        parts.append("Page title: {}".format(session.attached_title))
    if session.attached_url:
        parts.append("Page URL: {}".format(session.attached_url))
    if session.attached_page_text:
        clipped = clamp_text(session.attached_page_text, config.page_text_max_chars)
        label = "Supporting page text" if session.attached_selection else "Page text"
        parts.append("{}:\n```\n{}\n```".format(label, clipped))
    return "\n".join(parts)


def build_preset_display_text(preset: str, has_selection: bool = False) -> str:
    labels = _PRESET_DISPLAY_LABELS.get(preset)
    if labels is None:
        return preset.replace("-", " ").strip().title() or "Assistant action"
    return labels[0] if has_selection else labels[1]


def _normalized_prompt(user_prompt: str) -> str:
    return " ".join((user_prompt or "").strip().lower().split())


def _has_page_reference(user_prompt: str, session: AssistantSessionState) -> bool:
    normalized = _normalized_prompt(user_prompt)
    if not normalized:
        return False
    if any(phrase in normalized for phrase in _PAGE_REFERENCE_PHRASES):
        return True
    if session.attached_selection and any(phrase in normalized for phrase in _SELECTION_FOLLOWUP_PHRASES):
        return True
    if session.attached_selection and normalized in {
        "explain",
        "summarize",
        "describe",
        "what is this",
        "what does this mean",
    }:
        return True
    return False


def has_freshness_cue(user_prompt: str) -> bool:
    normalized = _normalized_prompt(user_prompt)
    return any(phrase in normalized for phrase in _FRESHNESS_CUES)


def classify_request_mode(user_prompt: str, session: AssistantSessionState) -> str:
    normalized = _normalized_prompt(user_prompt)
    if not normalized:
        return "general-grounded"
    if _has_page_reference(user_prompt, session):
        return "page-hybrid"
    if any(normalized.startswith(prefix) for prefix in _GENERAL_TASK_PREFIXES):
        return "general-grounded"
    if has_freshness_cue(user_prompt):
        return "general-grounded"
    return "general-grounded"


def build_general_prompt(user_prompt: str) -> str:
    return (
        "Answer the user's question directly. The question may be unrelated to the current webpage, "
        "so do not refuse merely because it is not about the page. "
        "Use grounded web knowledge when available for factual or current information.\n\n"
        "User question: {}"
    ).format(user_prompt)


def build_page_hybrid_prompt(user_prompt: str, session: AssistantSessionState, config: AssistantConfig) -> str:
    ctx = build_context(session, config)
    if not ctx.strip():
        return build_general_prompt(user_prompt)
    if session.attached_selection:
        preamble = (
            "Answer the user's question about the selected text or current page. "
            "Use the selected text and surrounding page context first. "
            "If the page context is incomplete, use grounded web knowledge to fill in missing facts."
        )
    else:
        preamble = (
            "Answer the user's question about the current page. "
            "Use the page context first. "
            "If the page context is incomplete, use grounded web knowledge to fill in missing facts."
        )
    return "{}\n\nContext:\n{}\n\nUser question: {}".format(preamble, ctx, user_prompt)


def build_custom_prompt(user_prompt: str, session: AssistantSessionState, config: AssistantConfig) -> str:
    if classify_request_mode(user_prompt, session) == "page-hybrid":
        return build_page_hybrid_prompt(user_prompt, session, config)
    return build_general_prompt(user_prompt)


def build_preset_prompt(preset: str, session: AssistantSessionState, config: AssistantConfig) -> str | None:
    ctx = build_context(session, config)
    if not ctx.strip():
        return None

    has_selection = bool(session.attached_selection)
    if preset == "summarize":
        template = _SUMMARIZE_PRESET_PROMPTS[has_selection]
    elif preset == "explain":
        template = _EXPLAIN_PRESET_PROMPTS[has_selection]
    elif preset == "what-is-this":
        template = _WHAT_IS_THIS_PRESET_PROMPTS[has_selection]
    else:
        return None

    return template.format(context=ctx)


def build_custom_request(user_prompt: str, session: AssistantSessionState, config: AssistantConfig) -> AssistantRequest:
    mode = classify_request_mode(user_prompt, session)
    if mode == "page-hybrid":
        return AssistantRequest(
            display_content=user_prompt,
            model_content=build_page_hybrid_prompt(user_prompt, session, config),
            mode=mode,
            use_grounding=True,
            stream=False,
        )
    return AssistantRequest(
        display_content=user_prompt,
        model_content=build_general_prompt(user_prompt),
        mode=mode,
        use_grounding=True,
        stream=False,
    )


def build_preset_request(preset: str, session: AssistantSessionState, config: AssistantConfig) -> AssistantRequest | None:
    prompt = build_preset_prompt(preset, session, config)
    if prompt is None:
        return None

    has_selection = bool(session.attached_selection)
    if preset == "summarize":
        return AssistantRequest(
            display_content=build_preset_display_text(preset, has_selection),
            model_content=prompt,
            mode="page-summary",
            use_grounding=False,
            stream=config.stream,
        )

    return AssistantRequest(
        display_content=build_preset_display_text(preset, has_selection),
        model_content=prompt,
        mode="page-hybrid",
        use_grounding=True,
        stream=False,
    )


def transcript_to_gemini_contents(session: AssistantSessionState) -> list[dict[str, Any]]:
    parts = []
    for msg in session.messages:
        role = "user" if msg.role == "user" else "model"
        parts.append({"role": role, "parts": [{"text": msg.model_content or msg.content}]})
    return parts


def _get_value(obj: Any, *names: str) -> Any:
    if obj is None:
        return None
    if isinstance(obj, dict):
        for name in names:
            if name in obj:
                return obj[name]
        return None
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return None


def _apply_inline_formatting(text: str) -> str:
    text = re.sub(r"`([^`\n]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*\n]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*([^*\n]+)\*", r"<em>\1</em>", text)
    return text


def _plain_text_to_html(text: str) -> str:
    normalized = (text or "").replace("\r\n", "\n").strip()
    if not normalized:
        return "<p></p>"

    blocks = []
    for paragraph in re.split(r"\n\s*\n", normalized):
        lines = [line.rstrip() for line in paragraph.splitlines() if line.strip()]
        if not lines:
            continue

        if all(re.match(r"^\s*[-*]\s+", line) for line in lines):
            items = "".join(
                "<li>{}</li>".format(_apply_inline_formatting(html.escape(re.sub(r"^\s*[-*]\s+", "", line))))
                for line in lines
            )
            blocks.append("<ul>{}</ul>".format(items))
            continue

        if all(re.match(r"^\s*\d+\.\s+", line) for line in lines):
            items = "".join(
                "<li>{}</li>".format(_apply_inline_formatting(html.escape(re.sub(r"^\s*\d+\.\s+", "", line))))
                for line in lines
            )
            blocks.append("<ol>{}</ol>".format(items))
            continue

        body = "<br>".join(_apply_inline_formatting(html.escape(line)) for line in lines)
        blocks.append("<p>{}</p>".format(body))

    return "".join(blocks) or "<p></p>"


def _citation_anchor(number: int, uri: str, title: str) -> str:
    safe_uri = html.escape(uri, quote=True)
    safe_title = html.escape(title or uri)
    return (
        "<a href=\"{}\" title=\"{}\" "
        "style=\"color:#1d4ed8;text-decoration:none;font-weight:600;margin-left:2px\">[{}]</a>"
    ).format(safe_uri, safe_title, number)


def _insert_citation_tokens(text: str, grounding_metadata: Any) -> tuple[str, dict[str, str]]:
    supports = _get_value(grounding_metadata, "grounding_supports", "groundingSupports") or []
    chunks = _get_value(grounding_metadata, "grounding_chunks", "groundingChunks") or []
    if not supports or not chunks:
        return text, {}

    token_map: dict[str, str] = {}
    tokenized_text = text

    def _chunk_anchor(chunk_index: int) -> str | None:
        if chunk_index < 0 or chunk_index >= len(chunks):
            return None
        web_chunk = _get_value(chunks[chunk_index], "web")
        uri = _get_value(web_chunk, "uri")
        if not uri:
            return None
        title = _get_value(web_chunk, "title") or uri
        return _citation_anchor(chunk_index + 1, uri, title)

    indexed_supports = []
    for support in supports:
        segment = _get_value(support, "segment")
        end_index = _get_value(segment, "end_index", "endIndex")
        indices = _get_value(support, "grounding_chunk_indices", "groundingChunkIndices") or []
        if isinstance(end_index, int) and indices:
            indexed_supports.append((end_index, list(dict.fromkeys(indices))))

    for seq, (end_index, chunk_indices) in enumerate(sorted(indexed_supports, reverse=True)):
        anchors = [_chunk_anchor(index) for index in chunk_indices]
        anchors = [anchor for anchor in anchors if anchor]
        if not anchors:
            continue
        token = "__WC_CITATION_{}__".format(seq)
        token_map[token] = "".join(anchors)
        tokenized_text = tokenized_text[:end_index] + token + tokenized_text[end_index:]

    return tokenized_text, token_map


def render_assistant_message_html(text: str, grounding_metadata: Any = None) -> str:
    tokenized_text, token_map = _insert_citation_tokens(text or "", grounding_metadata)
    rendered = _plain_text_to_html(tokenized_text)
    for token, replacement in token_map.items():
        rendered = rendered.replace(token, replacement)

    search_entry = _get_value(grounding_metadata, "search_entry_point", "searchEntryPoint")
    search_entry_html = _get_value(search_entry, "rendered_content", "renderedContent") or ""
    if search_entry_html:
        rendered += (
            "<div style='margin-top:10px;padding-top:10px;border-top:1px solid rgba(148,163,184,.35)'>"
            "{}"
            "</div>"
        ).format(search_entry_html)
    return rendered


def check_config() -> str | None:
    import os

    use_vertex = os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "").strip().lower() in {"1", "true", "yes"}
    if not use_vertex:
        return "GOOGLE_GENAI_USE_VERTEXAI must be set to true"
    project = os.getenv("GOOGLE_CLOUD_PROJECT", "").strip()
    if not project:
        return "GOOGLE_CLOUD_PROJECT is not set"
    return None


class GeminiAssistantClient:
    def __init__(self, config: AssistantConfig):
        self.config = config
        self._client = None
        self._types = None
        self._setup_error: Optional[str] = None
        self._supports_grounding = False
        self._try_setup()

    def _try_setup(self) -> None:
        if not self.config.enabled:
            self._setup_error = "AI assistant is disabled"
            return
        err = check_config()
        if err:
            self._setup_error = err
            return
        try:
            from google import genai
            from google.genai import types
            import os

            project = os.getenv("GOOGLE_CLOUD_PROJECT", "")
            location = os.getenv("GOOGLE_CLOUD_LOCATION", "global")
            client_kwargs = {
                "vertexai": True,
                "project": project,
                "location": location,
            }
            if hasattr(types, "HttpOptions"):
                client_kwargs["http_options"] = types.HttpOptions(api_version="v1")
            self._client = genai.Client(**client_kwargs)
            self._types = types
            self._supports_grounding = all(
                hasattr(types, attr) for attr in ("GenerateContentConfig", "GoogleSearch", "Tool")
            )
            self._setup_error = None
        except ImportError:
            self._setup_error = "google-genai SDK is not installed. Run: pip install google-genai"
        except Exception as e:
            self._setup_error = "Failed to initialize Gemini client: {}".format(e)

    @property
    def is_ready(self) -> bool:
        return self._client is not None and self._setup_error is None

    @property
    def setup_error(self) -> Optional[str]:
        return self._setup_error

    def _build_generate_config(self, use_grounding: bool) -> Any:
        if self._types is None:
            return {
                "system_instruction": _SYSTEM_INSTRUCTION,
                "temperature": self.config.temperature,
                "max_output_tokens": self.config.max_output_tokens,
            }

        config_kwargs = {
            "system_instruction": _SYSTEM_INSTRUCTION,
            "temperature": self.config.temperature,
            "max_output_tokens": self.config.max_output_tokens,
        }
        if use_grounding and self._supports_grounding:
            config_kwargs["tools"] = [self._types.Tool(google_search=self._types.GoogleSearch())]
        return self._types.GenerateContentConfig(**config_kwargs)

    def generate_stream(self, session: AssistantSessionState, request: AssistantRequest):
        if not self.is_ready:
            yield "[Error] {}".format(self._setup_error or "Client not ready")
            return

        try:
            contents = transcript_to_gemini_contents(session)
            response = self._client.models.generate_content_stream(
                model=self.config.model,
                contents=contents,
                config=self._build_generate_config(use_grounding=False),
            )
            for chunk in response:
                if session.cancelled:
                    return
                if chunk.text:
                    yield chunk.text
        except Exception as e:
            yield "[Error] {}".format(e)

    def generate_response(self, session: AssistantSessionState, request: AssistantRequest) -> AssistantResponse:
        if not self.is_ready:
            return AssistantResponse(text="[Error] {}".format(self._setup_error or "Client not ready"))

        try:
            contents = transcript_to_gemini_contents(session)
            use_grounding = request.use_grounding and self._supports_grounding
            response = self._client.models.generate_content(
                model=self.config.model,
                contents=contents,
                config=self._build_generate_config(use_grounding=use_grounding),
            )
            text = (getattr(response, "text", None) or "").strip()
            candidate = (getattr(response, "candidates", None) or [None])[0]
            grounding_metadata = _get_value(candidate, "grounding_metadata", "groundingMetadata")
            rendered_html = render_assistant_message_html(text, grounding_metadata)
            return AssistantResponse(
                text=text,
                rendered_html=rendered_html,
                grounded=bool(grounding_metadata),
            )
        except Exception as e:
            return AssistantResponse(text="[Error] {}".format(e))
