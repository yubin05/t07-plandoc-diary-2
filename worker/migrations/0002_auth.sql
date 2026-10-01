-- T07 인증 + 자료 소유권 + 5일 지표 추적

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_algo TEXT NOT NULL,       -- 'PBKDF2-SHA256'
  password_iterations INTEGER NOT NULL,
  password_salt TEXT NOT NULL,       -- base64, 계정마다 랜덤
  password_hash TEXT NOT NULL,       -- base64, 되돌릴 수 없음
  created_at TEXT NOT NULL
);

-- 세션은 서명이 필요없는 순수 조회형 토큰이라 별도 비밀키가 없다.
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,               -- 랜덤 토큰 자체가 PK
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

-- 기존 테이블에 소유자(user_id)를 추가해 자료를 계정별로 가른다
ALTER TABLE plans ADD COLUMN user_id TEXT;
ALTER TABLE tasks ADD COLUMN user_id TEXT;
ALTER TABLE execution_logs ADD COLUMN user_id TEXT;
ALTER TABLE plan_history ADD COLUMN user_id TEXT;
ALTER TABLE completion_events ADD COLUMN user_id TEXT;
ALTER TABLE reflections ADD COLUMN user_id TEXT;

CREATE INDEX idx_plans_user ON plans(user_id);
CREATE INDEX idx_tasks_user ON tasks(user_id);
CREATE INDEX idx_execlogs_user ON execution_logs(user_id);
CREATE INDEX idx_reflections_user ON reflections(user_id);

-- 5일 지표 추적: 1일차에 고정하는 설정(계정당 1행)
CREATE TABLE metric_config (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  question_text TEXT NOT NULL,
  metric_name TEXT NOT NULL,
  unit TEXT NOT NULL,
  calc_rule_text TEXT NOT NULL,
  missing_rule_text TEXT NOT NULL,
  duplicate_rule_text TEXT NOT NULL,
  outlier_rule_text TEXT NOT NULL,
  rounding_rule_text TEXT NOT NULL,
  week_start_text TEXT NOT NULL,
  planning_rule_text TEXT NOT NULL,  -- 현재 적용 중인 계획 규칙
  created_at TEXT NOT NULL
);

-- 날짜별 지표값 (같은 날 재기록은 upsert로 갱신 — 중복 처리 규칙과 일치)
CREATE TABLE daily_metrics (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  record_date TEXT NOT NULL,         -- Asia/Seoul YYYY-MM-DD
  metric_value REAL NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(user_id, record_date)
);

-- 계획 규칙 변경 기록 (2일차 뒤, 3일차 앞에 정확히 하나)
CREATE TABLE rule_changes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  changed_at TEXT NOT NULL,
  reason_text TEXT NOT NULL,
  new_planning_rule_text TEXT NOT NULL
);
