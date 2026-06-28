ALTER TABLE gateway_usage_events
    ADD COLUMN IF NOT EXISTS trace_id TEXT;

UPDATE gateway_usage_events
SET trace_id = request_id
WHERE trace_id IS NULL;

ALTER TABLE gateway_usage_events
    ALTER COLUMN trace_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS gateway_usage_trace_time_idx
    ON gateway_usage_events (tenant_id, trace_id, occurred_at DESC);
