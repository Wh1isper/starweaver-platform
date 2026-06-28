ALTER TABLE gateway_model_targets
    ADD COLUMN IF NOT EXISTS pricing_sku_id TEXT REFERENCES gateway_pricing_skus (pricing_sku_id);

CREATE INDEX IF NOT EXISTS gateway_model_targets_pricing_sku_idx
    ON gateway_model_targets (tenant_id, pricing_sku_id)
    WHERE pricing_sku_id IS NOT NULL AND status != 'deleted';
