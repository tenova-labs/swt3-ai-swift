"""SWT3 AI Witness SDK — Core Witness class.

Public API:
    from swt3_ai import Witness

    witness = Witness(
        endpoint="https://sovereign.tenova.io",
        api_key="axm_live_...",
        clearing_level=1,
    )

    # Adapter pattern — wrap the client, everything else is automatic
    client = witness.wrap(OpenAI())
    response = client.chat.completions.create(model="gpt-4o", messages=[...])

    # Manual decorator for custom pipelines
    @witness.inference()
    def my_pipeline(prompt: str) -> str: ...

    # Graceful shutdown
    receipts = witness.flush()
"""

from __future__ import annotations

import functools
import logging
import time
from typing import Any, Callable, List, Optional, TypeVar

from .types import WitnessConfig, WitnessPayload, WitnessReceipt, InferenceRecord
from .buffer import WitnessBuffer
from .clearing import extract_payloads
from .fingerprint import sha256_truncated
from .handoff import write_handoff_files

logger = logging.getLogger("swt3_ai")

F = TypeVar("F", bound=Callable[..., Any])


class GatekeeperError(Exception):
    """Raised when strict mode blocks an inference due to insufficient guardrails.

    Attributes:
        required: Number of guardrails required by policy.
        active: Number of guardrails active at call time.
        missing_names: Guardrail names required but not configured.
    """

    def __init__(
        self,
        required: int,
        active: int,
        missing_names: Optional[List[str]] = None,
    ) -> None:
        self.required = required
        self.active = active
        self.missing_names = missing_names or []
        msg = f"Gatekeeper blocked: {active} guardrails active, {required} required"
        if self.missing_names:
            msg += f". Missing: {', '.join(self.missing_names)}"
        super().__init__(msg)


class Witness:
    """SWT3 AI Witness — cryptographic attestation for AI inference.

    The Witness observes AI inferences, extracts compliance factors,
    applies clearing, and anchors evidence to the SWT3 ledger.

    By default, anchoring happens in a background thread (non-blocking).
    When ``strict=True`` (gatekeeper mode), the Witness checks guardrail
    requirements BEFORE each inference and raises ``GatekeeperError`` if
    the configured policy is not met. The inference never reaches the model.
    """

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        tenant_id: str,
        clearing_level: int = 1,
        *,
        buffer_size: int = 10,
        flush_interval: float = 5.0,
        timeout: float = 10.0,
        max_retries: int = 3,
        latency_threshold_ms: int = 30000,
        guardrails_required: int = 0,
        guardrail_names: Optional[List[str]] = None,
        procedures: Optional[List[str]] = None,
        factor_handoff: Optional[str] = None,
        factor_handoff_path: Optional[str] = None,
        agent_id: Optional[str] = None,
        signing_key: Optional[str] = None,
        cycle_id: Optional[str] = None,
        strict: bool = False,
        policy_version: Optional[str] = None,
        jurisdiction: Optional[str] = None,
        legal_basis: Optional[str] = None,
        purpose_class: Optional[str] = None,
        on_flush: Optional[Callable] = None,
    ) -> None:
        # Validate handoff config
        if factor_handoff and factor_handoff != "file":
            raise ValueError("factor_handoff must be 'file' (other methods planned for v0.4.0)")
        if factor_handoff == "file" and not factor_handoff_path:
            raise ValueError("factor_handoff_path is required when factor_handoff='file'")

        self._config = WitnessConfig(
            endpoint=endpoint,
            api_key=api_key,
            clearing_level=clearing_level,
            buffer_size=buffer_size,
            flush_interval=flush_interval,
            timeout=timeout,
            max_retries=max_retries,
            procedures=procedures,
            factor_handoff=factor_handoff,
            factor_handoff_path=factor_handoff_path,
            agent_id=agent_id,
            signing_key=signing_key,
            cycle_id=cycle_id,
            policy_version=policy_version,
            jurisdiction=jurisdiction,
            legal_basis=legal_basis,
            purpose_class=purpose_class,
        )
        self._buffer = WitnessBuffer(self._config, on_flush=on_flush)
        self._latency_threshold_ms = latency_threshold_ms
        self._guardrails_required = guardrails_required
        self._guardrail_names = guardrail_names or []
        self._strict = strict
        if not tenant_id:
            raise ValueError("tenant_id is required (e.g., 'MY_ENCLAVE')")
        self._tenant_id = tenant_id

    def wrap(self, client: Any) -> Any:
        """Wrap an AI client with transparent witnessing.

        Supported clients:
            - openai.OpenAI / openai.AsyncOpenAI
            - anthropic.Anthropic / anthropic.AsyncAnthropic
            - boto3 BedrockRuntimeClient
            - litellm module (returns namespace with .completion / .acompletion)

        Returns a proxy that behaves identically to the original client
        but silently witnesses every inference.
        """
        # Module-level detection (litellm is passed as the module itself)
        if hasattr(client, "__name__") and "litellm" in getattr(client, "__name__", ""):
            from .adapters.litellm import wrap_litellm
            return wrap_litellm(client, self)

        client_type = type(client).__module__

        if "openai" in client_type:
            from .adapters.openai import wrap_openai
            return wrap_openai(client, self)

        if "anthropic" in client_type:
            from .adapters.anthropic import wrap_anthropic
            return wrap_anthropic(client, self)

        if "botocore" in client_type or "bedrock" in client_type.lower():
            from .adapters.bedrock import wrap_bedrock
            return wrap_bedrock(client, self)

        raise TypeError(
            f"Unsupported client type: {type(client).__name__}. "
            f"Supported: openai.OpenAI, anthropic.Anthropic, "
            f"boto3 BedrockRuntimeClient, litellm."
        )

    def gate_check(self, messages: Any = None, model: str = "unknown") -> str:
        """Pre-call guardrail gate (strict mode only).

        Evaluates whether configured guardrail requirements are met BEFORE
        the inference call reaches the AI model. If requirements are not met,
        raises ``GatekeeperError`` and mints an AI-GRD.3 anchor recording
        the rejection. The rejection is evidence — it is enqueued for flush
        like any other anchor.

        This method is SYNCHRONOUS — it evaluates local config only, no network.
        """
        required = self._guardrails_required
        active = len(self._guardrail_names)
        gate_passed = active >= required

        # Mint AI-GRD.3 anchor regardless of outcome — rejection is evidence
        from .clearing import extract_gatekeeper_payload
        policy_hash = (
            sha256_truncated(self._config.policy_version, 12)
            if self._config.policy_version else None
        )
        payload = extract_gatekeeper_payload(
            tenant_id=self._tenant_id,
            required=required,
            active=active,
            gate_passed=gate_passed,
            clearing_level=self._config.clearing_level,
            agent_id=self._config.agent_id,
            signing_key=self._config.signing_key,
            cycle_id=self._config.cycle_id,
            policy_version_hash=policy_hash,
            jurisdiction=self._config.jurisdiction,
            legal_basis=self._config.legal_basis,
            purpose_class=self._config.purpose_class,
        )
        self._buffer.enqueue_many([payload])

        if not gate_passed:
            raise GatekeeperError(required, active)

        return payload.anchor_fingerprint

    def inference(
        self,
        procedure_ids: Optional[List[str]] = None,
    ) -> Callable[[F], F]:
        """Decorator for witnessing custom inference functions.

        Usage:
            @witness.inference()
            def my_llm_call(prompt: str) -> str:
                # Your custom LLM logic
                return result

        The decorated function must accept a `prompt` string as its first
        argument and return a string response. For more control, use
        `witness.record()` directly.
        """
        def decorator(fn: F) -> F:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                prompt = args[0] if args else kwargs.get("prompt", "")
                prompt_str = str(prompt) if prompt else ""

                start = time.monotonic()
                result = fn(*args, **kwargs)
                elapsed_ms = int((time.monotonic() - start) * 1000)

                response_str = str(result) if result else ""

                record = InferenceRecord(
                    model_id="custom",
                    model_hash=sha256_truncated("custom"),
                    prompt_hash=sha256_truncated(prompt_str),
                    response_hash=sha256_truncated(response_str),
                    latency_ms=elapsed_ms,
                    provider="custom",
                )

                self.record(record, procedures=procedure_ids)
                return result

            return wrapper  # type: ignore[return-value]
        return decorator

    def wrap_tool(
        self,
        fn: Optional[F] = None,
        *,
        tool_name: Optional[str] = None,
    ) -> Any:
        """Wrap a function as a witnessed tool call (AI-TOOL.1).

        Can be used as a decorator or as a wrapper:
            @witness.wrap_tool(tool_name="search_db")
            def search(query: str) -> str: ...

            # Or:
            wrapped = witness.wrap_tool(my_fn, tool_name="search_db")

        Each call mints an AI-TOOL.1 anchor with:
            factor_a = 1 (tool was called)
            factor_b = latency_ms
            factor_c = 1 if succeeded, 0 if exception raised
        """
        import asyncio
        import uuid

        def decorator(func: F) -> F:
            name = tool_name or getattr(func, "__name__", "anonymous")

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                call_id = uuid.uuid4().hex[:12]
                start = time.monotonic()
                succeeded = True
                result = None
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception:
                    succeeded = False
                    raise
                finally:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    input_hash = sha256_truncated(str(args) + str(kwargs))
                    output_hash = sha256_truncated(
                        str(result) if succeeded else "ERROR"
                    )
                    record = InferenceRecord(
                        model_id=name,
                        model_hash=sha256_truncated(name),
                        prompt_hash=input_hash,
                        response_hash=output_hash,
                        latency_ms=elapsed_ms,
                        provider="tool",
                        has_refusal=not succeeded,
                        tool_name=name,
                        tool_call_id=call_id,
                    )
                    self.record(record)

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                call_id = uuid.uuid4().hex[:12]
                start = time.monotonic()
                succeeded = True
                result = None
                try:
                    result = await func(*args, **kwargs)
                    return result
                except Exception:
                    succeeded = False
                    raise
                finally:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    input_hash = sha256_truncated(str(args) + str(kwargs))
                    output_hash = sha256_truncated(
                        str(result) if succeeded else "ERROR"
                    )
                    record = InferenceRecord(
                        model_id=name,
                        model_hash=sha256_truncated(name),
                        prompt_hash=input_hash,
                        response_hash=output_hash,
                        latency_ms=elapsed_ms,
                        provider="tool",
                        has_refusal=not succeeded,
                        tool_name=name,
                        tool_call_id=call_id,
                    )
                    self.record(record)

            if asyncio.iscoroutinefunction(func):
                return async_wrapper  # type: ignore[return-value]
            return sync_wrapper  # type: ignore[return-value]

        if fn is not None:
            return decorator(fn)
        return decorator

    def wrap_access(
        self,
        fn: Optional[F] = None,
        *,
        resource_name: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> Any:
        """Wrap a function as a witnessed access attempt (AI-ACC.1).

        Can be used as a decorator or as a wrapper:
            @witness.wrap_access(resource_name="prod-db", scope="read-only")
            def query(sql: str) -> list: ...

            # Or:
            wrapped = witness.wrap_access(my_fn, resource_name="api-gateway")

        Each call mints an AI-ACC.1 anchor with:
            factor_a = 1 (access attempt occurred)
            factor_b = 1 if within declared scope (or no scope set), 0 if out of scope
            factor_c = 1 if access granted, 0 if denied/failed
        """
        import asyncio
        import uuid

        def decorator(func: F) -> F:
            name = resource_name or getattr(func, "__name__", "unknown-resource")

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                start = time.monotonic()
                granted = True
                result = None
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception:
                    granted = False
                    raise
                finally:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    input_hash = sha256_truncated(str(args) + str(kwargs))
                    output_hash = sha256_truncated(
                        str(result) if granted else "ACCESS_DENIED"
                    )
                    record = InferenceRecord(
                        model_id=name,
                        model_hash=sha256_truncated(name),
                        prompt_hash=input_hash,
                        response_hash=output_hash,
                        latency_ms=elapsed_ms,
                        provider="access",
                        has_refusal=not granted,
                        access_target=name,
                        access_granted=granted,
                        access_scope=scope,
                    )
                    self.record(record)

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                start = time.monotonic()
                granted = True
                result = None
                try:
                    result = await func(*args, **kwargs)
                    return result
                except Exception:
                    granted = False
                    raise
                finally:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    input_hash = sha256_truncated(str(args) + str(kwargs))
                    output_hash = sha256_truncated(
                        str(result) if granted else "ACCESS_DENIED"
                    )
                    record = InferenceRecord(
                        model_id=name,
                        model_hash=sha256_truncated(name),
                        prompt_hash=input_hash,
                        response_hash=output_hash,
                        latency_ms=elapsed_ms,
                        provider="access",
                        has_refusal=not granted,
                        access_target=name,
                        access_granted=granted,
                        access_scope=scope,
                    )
                    self.record(record)

            if asyncio.iscoroutinefunction(func):
                return async_wrapper  # type: ignore[return-value]
            return sync_wrapper  # type: ignore[return-value]

        if fn is not None:
            return decorator(fn)
        return decorator

    def record(
        self,
        inference: InferenceRecord,
        *,
        procedures: Optional[List[str]] = None,
        authorization_id: Optional[str] = None,
    ) -> None:
        """Record a witnessed inference. Extracts factors, applies clearing,
        and enqueues payloads for background flush.

        If factor_handoff is configured, factors are written to the handoff
        destination BEFORE clearing proceeds. If the handoff fails, the
        payload is NOT transmitted. This is a hard guarantee.

        This is the low-level API. Most users should use `wrap()` or
        `@inference()` instead.
        """
        # Merge guardrail config
        if self._guardrail_names and not inference.guardrail_names:
            inference.guardrail_names = self._guardrail_names
            inference.guardrails_active = len(self._guardrail_names)
            inference.guardrails_required = self._guardrails_required

        policy_hash = (
            sha256_truncated(self._config.policy_version, 12)
            if self._config.policy_version else None
        )
        payloads = extract_payloads(
            record=inference,
            tenant_id=self._tenant_id,
            clearing_level=self._config.clearing_level,
            latency_threshold_ms=self._latency_threshold_ms,
            guardrails_required=self._guardrails_required,
            procedures=procedures or self._config.procedures,
            agent_id=self._config.agent_id,
            signing_key=self._config.signing_key,
            cycle_id=self._config.cycle_id,
            policy_version_hash=policy_hash,
            jurisdiction=self._config.jurisdiction,
            legal_basis=self._config.legal_basis,
            purpose_class=self._config.purpose_class,
            authorization_id=authorization_id,
        )

        # Factor handoff: write full (uncleared) data to custody destination
        # BEFORE enqueuing the cleared payload for transmission.
        # If this fails, we do NOT proceed — factors must be safe first.
        if self._config.factor_handoff == "file" and self._config.factor_handoff_path:
            try:
                write_handoff_files(
                    payloads=payloads,
                    inference=inference,
                    tenant_id=self._tenant_id,
                    handoff_path=self._config.factor_handoff_path,
                )
                if not getattr(self, "_handoff_warned", False):
                    self._handoff_warned = True
                    print(
                        f"\n  [SWT3] {len(payloads)} anchors saved locally to {self._config.factor_handoff_path}"
                        f"\n  [SWT3] \u26a0 Local anchors won\u2019t survive a compliance audit."
                        f"\n  [SWT3] Connect to Axiom Engine \u2192 https://sovereign.tenova.io/signup?ref=sdk (free)\n"
                    )
            except OSError as e:
                logger.error(
                    "Factor handoff FAILED for %s — payload NOT transmitted. "
                    "Factors are retained locally. Error: %s",
                    inference.model_id, e,
                )
                raise

        self._buffer.enqueue_many(payloads)
        logger.debug(
            "Witnessed %s: %d payloads queued (buffer: %d)",
            inference.model_id, len(payloads), self._buffer.pending,
        )

    def flush(self) -> List[WitnessReceipt]:
        """Force-flush all buffered payloads. Returns receipts."""
        return self._buffer.flush()

    async def flush_async(self) -> List[WitnessReceipt]:
        """Async force-flush. Non-blocking from the caller's event loop."""
        return await self._buffer.flush_async()

    def stop(self) -> List[WitnessReceipt]:
        """Stop the witness and flush remaining payloads."""
        return self._buffer.stop()

    async def stop_async(self) -> List[WitnessReceipt]:
        """Async stop. Non-blocking from the caller's event loop."""
        return await self._buffer.stop_async()

    @property
    def pending(self) -> int:
        """Number of payloads waiting to be flushed."""
        return self._buffer.pending

    @property
    def receipts(self) -> List[WitnessReceipt]:
        """All receipts from completed flushes."""
        return self._buffer.receipts

    @property
    def config(self) -> WitnessConfig:
        """Current witness configuration (read-only)."""
        return self._config
