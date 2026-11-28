# IAO Cognitive Kernel — first implementation

**Status:** implemented on an isolated development branch; CI validation pending.

## Scope

`omega/cognitive_engine.py` adds a model-agnostic orchestration adapter with:
- bounded conversation input validation;
- a first-pass task outline in a strict JSON schema;
- a second-pass answer informed by the validated outline;
- fail-open degradation to a single answer pass when planning fails;
- explicit metadata describing plan validity, pass count and risk label;
- no storage or disclosure of private chain-of-thought.

The plan is model-generated advisory data. It is not executable, cannot call tools, cannot grant permissions and cannot alter authorization policy. The engine does not make the underlying model more capable than it is.

## Integration contract

The class implements both `chat(messages)` and `chat_with_metadata(messages)`, matching the model interface consumed by `OmegaService`. It is injected as:

```python
from omega.cognitive_engine import CognitiveEngine
from omega.llm_router import RouterModelAdapter

model = CognitiveEngine(RouterModelAdapter())
service = OmegaService(..., model_adapter=model)
```

The constructor defaults to two-pass planning. Set `planning_enabled=False` for a single-pass deployment or tests. The production service wrapper is wired in `omega/server.py` but remains OFF by default; enable it only with `IAO_COGNITIVE_ENGINE_ENABLED=1`. Set `IAO_COGNITIVE_PLANNING_ENABLED=false` to retain the adapter wrapper while using one model pass. No new provider, secret, paid service or deployment is activated by this module.

## Reproducible evaluation coverage

The cognitive-kernel tests include:
- valid structured plan → two-pass answer and metadata;
- malformed, oversized, and provider-failed planning → safe one-pass fallback;
- fenced JSON normalization and strict schema rejection;
- bounded input/output and rejection of invalid conversation shapes;
- preservation of service-supplied evidence context and provider identity metadata;
- adversarial plan text remaining explicitly advisory, with no tool or permission authority;
- opt-in runtime wiring and consent-/owner-scoped memory retrieval.

These are deterministic contract and resilience tests, not a benchmark of general intelligence. They do not establish factual accuracy, reasoning superiority, low hallucination rates, or consciousness. Before production, add a versioned representative task set with human-reviewed expected criteria, regression thresholds, latency/cost measurements for the actual provider configuration, and red-team review. Evaluation must not silently authorize tools or promote model-generated code.

## Limits and next gates

- This is model-assisted orchestration, not a trained foundation model or independent symbolic reasoner.
- Planning quality depends on the configured upstream model.
- The chat service can add existing user memories to model context only when the authenticated token has `memory.read`. Memory creation still requires explicit consent; retrieval is owner-scoped, limited to eight records / 8,000 characters, and marked as untrusted context rather than instructions. Without the scope, no memory is retrieved. This does not create a new memory store or automatic memory capture.
- Tool selection/execution, feedback-based learning, model evaluation benchmarks and provider-independent model training are not included.
- Production integration requires regression tests against the actual chat API, provider cost/latency measurement and explicit operator approval before enabling additional provider calls in a live deployment.
- This implementation makes no claim about consciousness or subjective feelings.
