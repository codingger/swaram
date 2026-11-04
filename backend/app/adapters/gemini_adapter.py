"""Google Gemini API adapter using the official Google Gen AI SDK (`google-genai`).


Spending and rate limits:

- Per-instance spending cap (`max_calls`).

- Global shared daily budget across runs (default 100 RPD).

- RPM sliding window rate limiter (default 60 RPM).

- Safe handling of HTTP 429 rate limit exceptions with automatic fallback.

"""

from __future__ import annotations


import logging

import os

import time

from typing import Any


from google import genai

from google.genai import errors, types


from app.adapters.base import DeterministicAdapter


logger = logging.getLogger(__name__)


DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"

DEFAULT_DAILY_BUDGET = 100

DEFAULT_RPM_LIMIT = 60


def mask_secret(secret: str | None) -> str:

    """Safely mask API key for diagnostics and logs."""

    if not secret:

        return "<unset>"

    if len(secret) <= 8:

        return "***"

    return f"{secret[:4]}...{secret[-4:]}"


class GeminiQuotaTracker:

    """Thread-safe sliding window and daily quota tracking for Gemini API requests."""


    def __init__(

        self,

        daily_budget: int = DEFAULT_DAILY_BUDGET,

        rpm_limit: int = DEFAULT_RPM_LIMIT,

    ) -> None:

        self.daily_budget = int(os.getenv("GEMINI_DAILY_BUDGET", daily_budget))

        self.rpm_limit = int(os.getenv("GEMINI_MAX_RPM", rpm_limit))

        self.daily_calls_used = 0

        self.day_start = time.time()

        self.call_timestamps: list[float] = []

        self.cooldown_until: float = 0.0


    def _refresh_window(self) -> None:

        now = time.time()

        # Reset 24-hour daily budget window

        if now - self.day_start >= 86400:

            self.daily_calls_used = 0

            self.day_start = now

        # Prune calls older than 60 seconds

        cutoff = now - 60.0

        self.call_timestamps = [t for t in self.call_timestamps if t > cutoff]


    def can_call(self) -> tuple[bool, str | None]:

        """Check whether an API call is permitted within daily and RPM quotas."""

        now = time.time()

        if now < self.cooldown_until:

            return False, f"in cooldown after HTTP 429 until {self.cooldown_until:.1f}"


        self._refresh_window()

        if self.daily_calls_used >= self.daily_budget:

            return False, f"daily quota exhausted ({self.daily_calls_used}/{self.daily_budget} calls used)"


        if len(self.call_timestamps) >= self.rpm_limit:

            return False, f"RPM limit exceeded ({len(self.call_timestamps)}/{self.rpm_limit} calls in 60s)"


        return True, None


    def record_call(self) -> None:

        """Record a successful API invocation timestamp."""

        now = time.time()

        self._refresh_window()

        self.daily_calls_used += 1

        self.call_timestamps.append(now)


    def record_429(self, cooldown_seconds: float = 60.0) -> None:

        """Record an HTTP 429 rate limit hit, enforcing temporary cooldown."""

        self.cooldown_until = time.time() + cooldown_seconds


    def reset(self) -> None:

        """Reset quota counters (used in testing)."""

        self.daily_calls_used = 0

        self.day_start = time.time()

        self.call_timestamps.clear()

        self.cooldown_until = 0.0


    def status(self) -> dict[str, Any]:

        self._refresh_window()

        return {

            "daily_budget": self.daily_budget,

            "daily_calls_used": self.daily_calls_used,

            "daily_calls_remaining": max(0, self.daily_budget - self.daily_calls_used),

            "rpm_limit": self.rpm_limit,

            "current_rpm": len(self.call_timestamps),

            "in_cooldown": time.time() < self.cooldown_until,

        }


# Global shared quota tracker across runs

GLOBAL_QUOTA_TRACKER = GeminiQuotaTracker()


def get_quota_tracker() -> GeminiQuotaTracker:

    return GLOBAL_QUOTA_TRACKER


def reset_quota_tracker() -> None:

    GLOBAL_QUOTA_TRACKER.reset()


class GeminiAdapter:

    name = "gemini"


    def __init__(

        self,

        api_key: str | None = None,

        model: str | None = None,

        max_calls: int = 20,

        timeout: float | None = None,

        max_retries: int | None = None,

        client: Any | None = None,

        quota_tracker: GeminiQuotaTracker | None = None,

    ):

        self.api_key = api_key or os.getenv("GEMINI_API_KEY")

        if not self.api_key:

            raise ValueError(

                "GEMINI_API_KEY is not set; configure GEMINI_API_KEY in .env or use agent_backend='deterministic'"

            )

        self.model = model or os.getenv("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL

        self.calls_left = max_calls

        env_timeout = float(os.getenv("GEMINI_TIMEOUT", "15.0"))

        self.timeout = timeout if timeout is not None else env_timeout

        env_retries = int(os.getenv("GEMINI_MAX_RETRIES", "3"))

        self.max_retries = max_retries if max_retries is not None else env_retries

        self.quota_tracker = quota_tracker or GLOBAL_QUOTA_TRACKER

        self._fallback = DeterministicAdapter()

        self._client = client

        self.last_finish_reason: str | None = None

        self.last_was_truncated: bool = False


    def _get_client(self) -> genai.Client:

        if self._client is None:

            # types.HttpOptions expects timeout in milliseconds

            timeout_ms = int(self.timeout * 1000) if self.timeout < 1000 else int(self.timeout)

            retry_opts = types.HttpRetryOptions(

                attempts=self.max_retries,

                initial_delay=2.0,

                exp_base=2.0,

                http_status_codes=[408, 429, 500, 502, 503, 504],

            )

            self._client = genai.Client(

                api_key=self.api_key,

                http_options=types.HttpOptions(

                    timeout=timeout_ms,

                    retry_options=retry_opts,

                ),

            )

        return self._client


    def compose_message(self, sender_role: str, recipient_role: str, intent: str, topic: str) -> str:

        """Compose message text using Gemini, falling back to deterministic template on any failure."""

        fallback = self._fallback.compose_message(sender_role, recipient_role, intent, topic)

        if self.calls_left <= 0:

            return fallback


        prompt = (

            f"You are a {sender_role} agent in a synthetic workplace simulation. "

            f"Write one short sentence (max 25 words) to the {recipient_role} agent. "

            f"Intent: {intent}. Topic: {topic}. Reply with the sentence only."

        )

        return self.generate_response(

            prompt,

            max_tokens=80,

            temperature=0.7,

            fallback_text=fallback,

        )


    def generate_response(

        self,

        prompt: str,

        *,

        system_instruction: str | None = None,

        temperature: float | None = None,

        max_tokens: int | None = None,

        fallback_text: str | None = None,

        strict: bool = False,

    ) -> str:

        """General response-generation interface for agent reasoning, tool selection, and communication."""

        default_fallback = (

            fallback_text

            if fallback_text is not None

            else self._fallback.generate_response(prompt, system_instruction=system_instruction)

        )


        # 1. Check per-instance spending cap

        if self.calls_left <= 0:

            if strict:

                raise RuntimeError("Gemini spending cap reached: 0 calls left for this session")

            logger.info("Spending cap reached for Gemini adapter (0 calls left); using deterministic fallback")

            return default_fallback


        # 2. Check global daily and RPM quota limits

        allowed, reason = self.quota_tracker.can_call()

        if not allowed:

            if strict:

                raise RuntimeError(f"Gemini API call blocked by quota protection: {reason}")

            logger.warning("Gemini API call blocked by quota protection (%s); using fallback", reason)

            return default_fallback


        self.calls_left -= 1


        config_kwargs: dict[str, Any] = {}
        if system_instruction:
            config_kwargs["system_instruction"] = system_instruction

        # Determine effective token limit:
        # In Gemini thinking models (such as gemini-3.x and gemini-2.5), thinking tokens
        # and response tokens share the same max_output_tokens budget. Setting max_output_tokens
        # below 8192 prematurely cuts off the model during reasoning, triggering MAX_TOKENS truncation.
        effective_max = max_tokens
        if effective_max is not None and effective_max < 8192:
            effective_max = 8192
        elif effective_max is None:
            effective_max = 8192

        config_kwargs["max_output_tokens"] = effective_max

        # Configure thinking: for Gemini 3.x, use low thinking level for fast operations; for older models use budget
        if "3" in self.model:
            config_kwargs["thinking_config"] = types.ThinkingConfig(thinking_level="low")
        elif effective_max <= 150:
            config_kwargs["thinking_config"] = types.ThinkingConfig(thinking_budget=0)
            if temperature is not None:
                config_kwargs["temperature"] = temperature
        elif temperature is not None:
            config_kwargs["temperature"] = temperature

        config = types.GenerateContentConfig(**config_kwargs) if config_kwargs else None


        last_error = None

        last_code = None


        for attempt in range(1, self.max_retries + 1):

            try:

                client = self._get_client()

                resp = client.models.generate_content(

                    model=self.model,

                    contents=prompt,

                    config=config,

                )

                text = (resp.text or "").strip()

                candidate = resp.candidates[0] if (getattr(resp, "candidates", None) and len(resp.candidates) > 0) else None

                finish_reason = getattr(candidate, "finish_reason", None) if candidate else None

                fr_str = str(finish_reason).upper() if finish_reason else ""

                self.last_finish_reason = fr_str

                self.last_was_truncated = "MAX_TOKENS" in fr_str

                if self.last_was_truncated:

                    logger.warning("Gemini response was truncated due to token limit (finish_reason=%s)", fr_str)


                if not text:

                    if strict:

                        raise RuntimeError(f"Gemini returned empty or filtered response for model '{self.model}'")

                    logger.warning("Gemini returned empty or filtered response for model '%s'", self.model)

                    return default_fallback


                # Record successful call in quota tracker

                self.quota_tracker.record_call()

                return text

            except errors.APIError as err:

                last_code = getattr(err, "code", "unknown")

                err_msg = getattr(err, "message", None) or str(err)

                last_error = err_msg

                if last_code == 429 or "RESOURCE_EXHAUSTED" in str(err_msg):

                    logger.warning("Gemini HTTP 429 (Rate Limit / Quota Exceeded); triggering quota tracker cooldown: %s", err_msg)

                    self.quota_tracker.record_429()

                else:

                    logger.warning("Gemini APIError [%s] for model '%s' (attempt %d/%d): %s", last_code, self.model, attempt, self.max_retries, err_msg)


                # Transient errors retry with backoff

                if last_code in (504, 503, 502, 500, 408) and attempt < self.max_retries:

                    backoff = 2.0 * (2 ** (attempt - 1))

                    logger.info("Retrying transient %s error after %.1fs backoff...", last_code, backoff)

                    time.sleep(backoff)

                    continue


                if strict:

                    raise RuntimeError(f"Gemini APIError [{last_code}] for model '{self.model}': {err_msg}") from err

                return default_fallback

            except Exception as err:

                if strict and isinstance(err, RuntimeError):

                    raise

                err_str = str(err)

                last_error = err_str

                if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str:

                    logger.warning("Gemini HTTP 429 rate limit detected; cooling down")

                    self.quota_tracker.record_429()

                else:

                    logger.warning("Gemini request exception for model '%s' (attempt %d/%d): %s", self.model, attempt, self.max_retries, type(err).__name__)


                if attempt < self.max_retries and ("deadline" in err_str.lower() or "timeout" in err_str.lower() or "unavailable" in err_str.lower()):

                    backoff = 2.0 * (2 ** (attempt - 1))

                    logger.info("Retrying after %.1fs backoff on timeout/network exception: %s", backoff, err)

                    time.sleep(backoff)

                    continue


                if strict:

                    raise RuntimeError(f"Gemini request exception for model '{self.model}': {err}") from err

                return default_fallback


    def verify_connection(self) -> dict[str, Any]:

        """Verify real connection to Gemini API with current adapter configuration."""

        return self.check_connection(

            api_key=self.api_key,

            model=self.model,

            timeout=self.timeout,

            max_retries=self.max_retries,

            client=self._client,

        )


    @classmethod

    def check_connection(

        cls,

        api_key: str | None = None,

        model: str | None = None,

        timeout: float | None = None,

        max_retries: int | None = None,

        client: Any | None = None,

    ) -> dict[str, Any]:

        """Safe diagnostics method to test Gemini API connectivity without exposing secrets.


        Includes configurable timeout and exponential backoff retry for transient 504 / 503 errors.

        """

        key = api_key or os.getenv("GEMINI_API_KEY")

        selected_model = model or os.getenv("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL

        req_timeout = timeout if timeout is not None else float(os.getenv("GEMINI_TIMEOUT", "45.0"))

        retries = max_retries if max_retries is not None else int(os.getenv("GEMINI_MAX_RETRIES", "3"))


        if not key:

            return {

                "status": "error",

                "ok": False,

                "connected": False,

                "model": selected_model,

                "api_key_configured": False,

                "masked_key": None,

                "error": "GEMINI_API_KEY is not set in environment or .env file",

            }


        masked = mask_secret(key)

        timeout_ms = int(req_timeout * 1000) if req_timeout < 1000 else int(req_timeout)


        # Ultra-minimal prompt for connection test

        gen_config_kwargs: dict[str, Any] = {"max_output_tokens": 10}

        if "3" in selected_model:

            gen_config_kwargs["thinking_config"] = types.ThinkingConfig(thinking_level="low")


        last_code = None

        last_error = None


        for attempt in range(1, retries + 1):

            try:

                t0 = time.time()

                c = client or genai.Client(

                    api_key=key,

                    http_options=types.HttpOptions(

                        timeout=timeout_ms,

                        retry_options=types.HttpRetryOptions(

                            attempts=2,

                            initial_delay=2.0,

                            http_status_codes=[408, 429, 500, 502, 503, 504],

                        ),

                    ),

                )

                resp = c.models.generate_content(

                    model=selected_model,

                    contents="Ping",

                    config=types.GenerateContentConfig(**gen_config_kwargs),

                )

                elapsed_ms = int((time.time() - t0) * 1000)

                text = (resp.text or "").strip()

                return {

                    "status": "connected",

                    "ok": True,

                    "connected": True,

                    "model": selected_model,

                    "api_key_configured": True,

                    "masked_key": masked,

                    "response": text,

                    "latency_ms": elapsed_ms,

                    "attempts": attempt,

                }

            except errors.APIError as err:

                last_code = getattr(err, "code", "unknown")

                err_msg = getattr(err, "message", None) or str(err)

                last_error = err_msg.replace(key, masked)

                logger.warning("Gemini probe attempt %d/%d failed with code %s: %s", attempt, retries, last_code, last_error)

                if last_code in (504, 503, 408, 502, 500) and attempt < retries:

                    backoff = 2.0 * (2 ** (attempt - 1))

                    time.sleep(backoff)

            except Exception as err:

                last_error = str(err).replace(key, masked)

                logger.warning("Gemini probe attempt %d/%d exception: %s", attempt, retries, last_error)

                if attempt < retries:

                    backoff = 2.0 * (2 ** (attempt - 1))

                    time.sleep(backoff)


        return {

            "status": "error",

            "ok": False,

            "connected": False,

            "model": selected_model,

            "api_key_configured": True,

            "masked_key": masked,

            "error": f"APIError ({last_code}): {last_error}" if last_code else f"Error: {last_error}",

            "attempts": retries,

        }
