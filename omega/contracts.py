from typing import Literal

from pydantic import BaseModel, Field

RiskClass = Literal["R0", "R1", "R2", "R3", "R4"]


class IntentContract(BaseModel):
    intent_id: str = Field(min_length=1, max_length=128)
    goal: str = Field(min_length=1, max_length=4000)
    allowed_capabilities: list[str]
    risk_class: RiskClass
    budget_seconds: int = Field(gt=0, le=86400)
    termination_condition: str = Field(min_length=1, max_length=1000)


class ToolContract(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    version: str = Field(min_length=1, max_length=32)
    side_effects: Literal["none", "read", "write", "external"]
    required_capabilities: list[str]
    timeout_seconds: int = Field(gt=0, le=300)
