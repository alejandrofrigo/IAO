from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    conversation_id: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=20000)


class ChatResponse(BaseModel):
    status: str
    conversation_id: str
    reply: str
    authority: str = "NON_AUTHORITATIVE_MODEL_OUTPUT"
