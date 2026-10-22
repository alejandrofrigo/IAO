from typing import Protocol


class ModelAdapter(Protocol):
    def generate(self, prompt: str) -> str: ...


class DisabledModelAdapter:
    def generate(self, prompt: str) -> str:
        raise RuntimeError("MODEL_ADAPTER_DISABLED")
