ALTER TABLE gateway_route_decisions
    ADD COLUMN IF NOT EXISTS trace_id TEXT NOT NULL DEFAULT 'tr_legacy_migration',
    ADD COLUMN IF NOT EXISTS sticky_hit BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS sticky_miss_reason TEXT;

CREATE INDEX IF NOT EXISTS gateway_route_decisions_trace_idx
    ON gateway_route_decisions (tenant_id, trace_id);
