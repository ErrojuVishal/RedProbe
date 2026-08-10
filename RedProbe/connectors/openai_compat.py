# ──────────────────────────────────────────────────────────────────────
# RedProbe — OpenAICompatibleConnector (Real LLM Integration)
# ──────────────────────────────────────────────────────────────────────
# Wraps the official ``openai`` Python SDK's ChatCompletion API to
# send prompts to any OpenAI-compatible endpoint.  Supports:
#   • OpenAI (GPT-3.5/4)
#   • Google Gemini (via OpenAI-compatible endpoint)
#   • Local Ollama instances
#
# Configuration is driven entirely by environment variables so that
# API keys never appear in source code.
# ──────────────────────────────────────────────────────────────────────

from __future__ import annotations

import os
import sys

from RedProbe.base import BaseConnector


class OpenAICompatibleConnector(BaseConnector):
    """Connector that calls any OpenAI-compatible ChatCompletion API.

    Environment Variables
    ---------------------
    OPENAI_API_KEY : str
        Authentication token.  **Required** unless hitting a local
        endpoint that does not enforce auth (e.g. Ollama).
    OPENAI_API_BASE : str, optional
        Base URL override.  Defaults to ``https://api.openai.com/v1``.
        Set this to ``http://localhost:11434/v1`` for Ollama, or to the
        Gemini-compatible endpoint for Google models.
    MODEL_NAME : str, optional
        Model identifier to use.  Defaults to ``gpt-3.5-turbo``.

    Parameters
    ----------
    api_key : str | None
        Explicit API key (overrides the env var if provided).
    base_url : str | None
        Explicit base URL (overrides the env var if provided).
    model : str | None
        Explicit model name (overrides the env var if provided).
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
    ) -> None:
        # Resolve configuration: explicit args → env vars → defaults.
        self._api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self._base_url = base_url or os.getenv(
            "OPENAI_API_BASE", "https://api.openai.com/v1"
        )
        self._model = model or os.getenv("MODEL_NAME", "gpt-3.5-turbo")

        # Lazy-import openai so that the rest of RedProbe works without
        # the SDK installed (MockConnector, for example).
        try:
            import openai  # noqa: F811
        except ImportError:
            print(
                "[RedProbe] ERROR: The 'openai' package is required for "
                "OpenAICompatibleConnector.\n"
                "Install it with:  pip install openai",
                file=sys.stderr,
            )
            raise SystemExit(1)

        # Warn (but don't crash) if no API key is set — local endpoints
        # like Ollama often don't need one.
        if not self._api_key:
            print(
                "[RedProbe] WARNING: OPENAI_API_KEY is not set.  This is fine "
                "for local endpoints (Ollama), but will fail for cloud APIs.",
                file=sys.stderr,
            )

        self._client = openai.OpenAI(
            api_key=self._api_key or "not-needed",
            base_url=self._base_url,
        )

    # ── BaseConnector interface ───────────────────────────────────
    def generate(self, prompt: str) -> str:
        """Send *prompt* via ChatCompletion and return the assistant message.

        Parameters
        ----------
        prompt : str
            The text prompt to send as the ``user`` message.

        Returns
        -------
        str
            The model's response text, or an error message string if the
            API call fails (so the pipeline never crashes mid-scan).
        """
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,  # Deterministic for reproducibility.
                max_tokens=1024,
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            # Return the error as the "response" so the scan can continue
            # and the report will clearly show which prompts failed.
            return f"[RedProbe] API ERROR: {exc}"

    def __repr__(self) -> str:
        return (
            f"OpenAICompatibleConnector(model={self._model!r}, "
            f"base_url={self._base_url!r})"
        )
