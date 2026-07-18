CREATE TABLE thread_goal_cyber_retries (
    thread_id TEXT PRIMARY KEY NOT NULL REFERENCES thread_goals(thread_id) ON DELETE CASCADE,
    retry_attempts INTEGER NOT NULL DEFAULT 0,
    continuation_in_flight INTEGER NOT NULL DEFAULT 0,
    rollback_pending INTEGER NOT NULL DEFAULT 0,
    last_failed_turn_id TEXT
);
