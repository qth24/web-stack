"""Page-aware AI assistant using Gemini on Vertex AI via google-genai SDK."""

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class AssistantMessage:
    role: str
    content: str
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


_SYSTEM_INSTRUCTION = (
    "You are WaterCat Assistant, a helpful browser assistant built into the WaterCat Browser. "
    "You answer questions about the current web page the user is viewing. "
    "Always use the provided page context first when answering. "
    "If the provided context is insufficient to answer, say so clearly. "
    "Never claim you saw content that was not sent to you as context. "
    "Keep answers concise and well-structured. Use Markdown formatting. "
    "Use a friendly, helpful tone."
)

_PRESET_PROMPTS = {
    "summarize": (
        "Summarize the following content in 3-5 concise bullet points. "
        "Focus on the main ideas and key facts:\n\n{context}"
    ),
    "explain": (
        "Explain the following text in simple terms. Break down complex ideas:\n\n{context}"
    ),
    "what-is-this": (
        "Based on the following content, describe what this page or text is about in one paragraph:\n\n{context}"
    ),
}


def clamp_text(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    truncated = text[:max_chars]
    return truncated + "\n\n[... content truncated, showing first {:,} of {:,} characters ...]".format(
        max_chars, len(text)
    )


def build_context(session: AssistantSessionState, config: AssistantConfig) -> str:
    parts = []
    if session.attached_url:
        parts.append("Page URL: {}".format(session.attached_url))
    if session.attached_title:
        parts.append("Page title: {}".format(session.attached_title))
    if session.attached_selection:
        clipped = clamp_text(session.attached_selection, config.selection_max_chars)
        parts.append("Selected text:\n```\n{}\n```".format(clipped))
    if session.attached_page_text:
        clipped = clamp_text(session.attached_page_text, config.page_text_max_chars)
        parts.append("Page text:\n```\n{}\n```".format(clipped))
    return "\n".join(parts)


def build_preset_prompt(preset: str, session: AssistantSessionState, config: AssistantConfig) -> str | None:
    template = _PRESET_PROMPTS.get(preset)
    if template is None:
        return None
    ctx = build_context(session, config)
    if not ctx.strip():
        return None
    return template.format(context=ctx)


def build_custom_prompt(user_prompt: str, session: AssistantSessionState, config: AssistantConfig) -> str:
    ctx = build_context(session, config)
    if ctx.strip():
        return "Context:\n{}\n\nUser question: {}".format(ctx, user_prompt)
    return "User question: {}".format(user_prompt)


def transcript_to_gemini_contents(session: AssistantSessionState) -> list[dict[str, Any]]:
    parts = []
    for msg in session.messages:
        role = "user" if msg.role == "user" else "model"
        parts.append({"role": role, "parts": [{"text": msg.content}]})
    return parts


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
        self._setup_error: Optional[str] = None
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
            import os

            project = os.getenv("GOOGLE_CLOUD_PROJECT", "")
            location = os.getenv("GOOGLE_CLOUD_LOCATION", "global")
            self._client = genai.Client(
                vertexai=True,
                project=project,
                location=location,
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

    def generate_stream(self, session: AssistantSessionState):
        if not self.is_ready:
            yield "[Error] {}".format(self._setup_error or "Client not ready")
            return

        try:
            contents = transcript_to_gemini_contents(session)
            generation_config = {
                "temperature": self.config.temperature,
                "max_output_tokens": self.config.max_output_tokens,
            }

            response = self._client.models.generate_content_stream(
                model=self.config.model,
                contents=contents,
                config={
                    "system_instruction": _SYSTEM_INSTRUCTION,
                    **generation_config,
                },
            )

            for chunk in response:
                if session.cancelled:
                    return
                if chunk.text:
                    yield chunk.text
        except Exception as e:
            yield "[Error] {}".format(e)
