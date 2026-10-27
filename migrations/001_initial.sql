CREATE TABLE IF NOT EXISTS app_user (
  id UUID PRIMARY KEY,
  external_subject TEXT UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('active','disabled','pending')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS conversation (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES app_user(id),
  title TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL CHECK (status IN ('active','archived','deleted')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS task (
  id UUID PRIMARY KEY,
  conversation_id UUID REFERENCES conversation(id),
  state TEXT NOT NULL CHECK (state IN ('QUEUED','RUNNING','VERIFYING','COMPLETE','FAILED','BLOCKED','CANCELLED')),
  intent_json JSONB NOT NULL,
  checkpoint_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS message (
  id UUID PRIMARY KEY,
  conversation_id UUID NOT NULL REFERENCES conversation(id),
  role TEXT NOT NULL CHECK (role IN ('system','user','assistant','tool')),
  content TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tool_execution (
  id UUID PRIMARY KEY,
  task_id UUID NOT NULL REFERENCES task(id),
  tool_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('REQUESTED','AUTHORIZED','RUNNING','SUCCEEDED','FAILED','DENIED','TIMEOUT')),
  input_hash TEXT NOT NULL,
  output_hash TEXT,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS audit_event (
  id BIGSERIAL PRIMARY KEY,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor TEXT NOT NULL,
  event_type TEXT NOT NULL,
  subject TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  previous_hash TEXT NOT NULL,
  event_hash TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS user_memory (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES app_user(id),
  memory_key TEXT NOT NULL,
  value_json JSONB NOT NULL,
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('normal','restricted')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id, memory_key)
);
CREATE INDEX IF NOT EXISTS idx_message_conversation_created ON message(conversation_id, created_at);
CREATE INDEX IF NOT EXISTS idx_task_state_updated ON task(state, updated_at);
CREATE INDEX IF NOT EXISTS idx_audit_subject_time ON audit_event(subject, occurred_at);
