//! Redis-compatible route and runtime policy hot-state backend.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use fred::interfaces::{ClientLike, EventInterface, LuaInterface};
use fred::prelude::{
    Builder, Client, Config, Error as FredError, Expiration, HashesInterface, KeysInterface,
    TcpConfig,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::task::JoinHandle;

use crate::domain::RuntimeBudgetLeaseRecord;
use crate::hot_state::{
    EndpointDrainRecord, EndpointHealthRecord, EndpointHealthState, RouteHotState,
    StickyRouteRecord, endpoint_drain_key, endpoint_health_key, sticky_route_key,
};
use crate::storage::{InMemoryGatewayStore, RuntimePolicyRepository, RuntimeQuotaCounterDecision};

const SATURATING_ADJUST_COUNTER_LUA: &str = r"
local value = tonumber(redis.call('GET', KEYS[1]) or '0') + tonumber(ARGV[1])
if value <= 0 then
  redis.call('DEL', KEYS[1])
  return 0
end
redis.call('SET', KEYS[1], value)
return value
";

/// Redis-compatible route and runtime policy hot-state repository.
pub struct RedisRuntimePolicyRepository {
    client: Client,
    connection_task: JoinHandle<Result<(), FredError>>,
    available: Arc<AtomicBool>,
    local_loss_allowance_store: InMemoryGatewayStore,
}

impl RedisRuntimePolicyRepository {
    /// Connects a Redis-compatible hot-state backend from a URL.
    ///
    /// # Errors
    ///
    /// Returns the Redis client error when the URL is invalid or the initial
    /// connection cannot be established within the supplied timeout.
    pub async fn connect(redis_url: &str, connection_timeout: Duration) -> Result<Self, FredError> {
        let config = Config::from_url(redis_url)?;
        let client = Builder::from_config(config)
            .with_connection_config(|config| {
                config.connection_timeout = connection_timeout;
                config.tcp = TcpConfig {
                    nodelay: Some(true),
                    ..Default::default()
                };
            })
            .build()?;
        let available = Arc::new(AtomicBool::new(false));
        let error_available = Arc::clone(&available);
        client.on_error(move |_| {
            let available = Arc::clone(&error_available);
            async move {
                available.store(false, Ordering::Relaxed);
                Ok(())
            }
        });
        let reconnect_available = Arc::clone(&available);
        client.on_reconnect(move |_| {
            let available = Arc::clone(&reconnect_available);
            async move {
                available.store(true, Ordering::Relaxed);
                Ok(())
            }
        });
        let connection_task = tokio::time::timeout(connection_timeout, client.init())
            .await
            .map_err(|_| {
                FredError::new(
                    fred::prelude::ErrorKind::Timeout,
                    "timed out connecting Redis-compatible hot state",
                )
            })??;
        available.store(true, Ordering::Relaxed);
        Ok(Self {
            client,
            connection_task,
            available,
            local_loss_allowance_store: InMemoryGatewayStore::default(),
        })
    }

    fn mark_available(&self) {
        self.available.store(true, Ordering::Relaxed);
    }

    fn mark_unavailable(&self) {
        self.available.store(false, Ordering::Relaxed);
    }

    fn budget_lease_key(lease_id: &str) -> String {
        format!("gateway:runtime_policy:budget_lease:{lease_id}")
    }

    fn tenant_budget_lease_hash_key(tenant_id: &str) -> String {
        format!("gateway:runtime_policy:budget_leases:{tenant_id}")
    }

    fn ttl_until(expires_at: chrono::DateTime<chrono::Utc>) -> Option<Expiration> {
        let ttl_seconds = (expires_at - chrono::Utc::now()).num_seconds();
        (ttl_seconds > 0).then_some(Expiration::EX(ttl_seconds))
    }

    fn decode_json<T: DeserializeOwned>(payload: &str, label: &str) -> Result<T, FredError> {
        serde_json::from_str(payload).map_err(|error| {
            FredError::new(
                fred::prelude::ErrorKind::Unknown,
                format!("failed to decode {label}: {error}"),
            )
        })
    }

    fn encode_json<T: Serialize>(record: &T, label: &str) -> Result<String, FredError> {
        serde_json::to_string(record).map_err(|error| {
            FredError::new(
                fred::prelude::ErrorKind::Unknown,
                format!("failed to encode {label}: {error}"),
            )
        })
    }

    async fn read_json<T: DeserializeOwned>(
        &self,
        key: String,
        label: &str,
    ) -> Result<Option<T>, FredError> {
        let payload: Option<String> = self.client.get(key).await?;
        payload
            .as_deref()
            .map(|payload| Self::decode_json(payload, label))
            .transpose()
    }

    async fn write_expiring_json<T: Serialize + Sync>(
        &self,
        key: String,
        record: &T,
        expires_at: chrono::DateTime<chrono::Utc>,
        label: &str,
    ) -> Result<(), FredError> {
        let Some(ttl) = Self::ttl_until(expires_at) else {
            return Ok(());
        };
        let payload = Self::encode_json(record, label)?;
        self.client.set(key, payload, Some(ttl), None, false).await
    }

    async fn write_budget_lease(&self, record: &RuntimeBudgetLeaseRecord) -> Result<(), FredError> {
        let payload = Self::encode_json(record, "runtime budget lease")?;
        let lease_key = Self::budget_lease_key(&record.lease_id);
        let tenant_hash_key = Self::tenant_budget_lease_hash_key(&record.tenant_id);
        let _: () = self
            .client
            .set(lease_key, payload.clone(), None, None, false)
            .await?;
        let _: () = self
            .client
            .hset(tenant_hash_key, vec![(record.lease_id.clone(), payload)])
            .await?;
        Ok(())
    }

    async fn read_budget_lease(
        &self,
        lease_id: &str,
    ) -> Result<Option<RuntimeBudgetLeaseRecord>, FredError> {
        let payload: Option<String> = self.client.get(Self::budget_lease_key(lease_id)).await?;
        payload
            .as_deref()
            .map(|payload| Self::decode_json(payload, "runtime budget lease"))
            .transpose()
    }

    async fn read_tenant_budget_leases(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<RuntimeBudgetLeaseRecord>, FredError> {
        let payloads: Vec<String> = self
            .client
            .hvals(Self::tenant_budget_lease_hash_key(tenant_id))
            .await?;
        payloads
            .into_iter()
            .map(|payload| Self::decode_json(&payload, "runtime budget lease"))
            .collect()
    }
}

impl std::fmt::Debug for RedisRuntimePolicyRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisRuntimePolicyRepository")
            .field("available", &self.available.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Drop for RedisRuntimePolicyRepository {
    fn drop(&mut self) {
        self.connection_task.abort();
    }
}

#[async_trait]
impl RouteHotState for RedisRuntimePolicyRepository {
    async fn endpoint_health_state(
        &self,
        tenant_id: &str,
        provider_endpoint_id: &str,
        config_version: Option<i64>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> EndpointHealthState {
        self.read_json::<EndpointHealthRecord>(
            endpoint_health_key(tenant_id, provider_endpoint_id),
            "endpoint health hot state",
        )
        .await
        .map_or_else(
            |_| {
                self.mark_unavailable();
                EndpointHealthState::Unknown
            },
            |record| {
                self.mark_available();
                record
                    .filter(|record| record.is_fresh_for(config_version, now))
                    .map_or(EndpointHealthState::Unknown, |record| record.state)
            },
        )
    }

    async fn endpoint_is_drained(
        &self,
        tenant_id: &str,
        provider_endpoint_id: &str,
        config_version: Option<i64>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        self.read_json::<EndpointDrainRecord>(
            endpoint_drain_key(tenant_id, provider_endpoint_id),
            "endpoint drain hot state",
        )
        .await
        .map_or_else(
            |_| {
                self.mark_unavailable();
                false
            },
            |record| {
                self.mark_available();
                record.is_some_and(|record| record.is_fresh_for(config_version, now))
            },
        )
    }

    async fn sticky_route(
        &self,
        tenant_id: &str,
        project_id: Option<&str>,
        model_alias_id: &str,
        affinity_hash: &str,
        config_version: Option<i64>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<StickyRouteRecord> {
        self.read_json::<StickyRouteRecord>(
            sticky_route_key(tenant_id, project_id, model_alias_id, affinity_hash),
            "sticky route hot state",
        )
        .await
        .map_or_else(
            |_| {
                self.mark_unavailable();
                None
            },
            |record| {
                self.mark_available();
                record.filter(|record| record.is_fresh_for(config_version, now))
            },
        )
    }

    async fn set_endpoint_health(&self, record: EndpointHealthRecord) {
        match self
            .write_expiring_json(
                endpoint_health_key(&record.tenant_id, &record.provider_endpoint_id),
                &record,
                record.expires_at,
                "endpoint health hot state",
            )
            .await
        {
            Ok(()) => self.mark_available(),
            Err(_) => self.mark_unavailable(),
        }
    }

    async fn set_endpoint_drain(&self, record: EndpointDrainRecord) {
        match self
            .write_expiring_json(
                endpoint_drain_key(&record.tenant_id, &record.provider_endpoint_id),
                &record,
                record.expires_at,
                "endpoint drain hot state",
            )
            .await
        {
            Ok(()) => self.mark_available(),
            Err(_) => self.mark_unavailable(),
        }
    }

    async fn set_sticky_route(&self, record: StickyRouteRecord) {
        match self
            .write_expiring_json(
                sticky_route_key(
                    &record.tenant_id,
                    record.project_id.as_deref(),
                    &record.model_alias_id,
                    &record.affinity_hash,
                ),
                &record,
                record.expires_at,
                "sticky route hot state",
            )
            .await
        {
            Ok(()) => self.mark_available(),
            Err(_) => self.mark_unavailable(),
        }
    }
}

#[async_trait]
impl RuntimePolicyRepository for RedisRuntimePolicyRepository {
    async fn runtime_policy_hot_state_available(&self) -> bool {
        self.client.is_connected() && self.available.load(Ordering::Relaxed)
    }

    async fn increment_runtime_quota_counter(
        &self,
        key: String,
        increment: i64,
        limit: i64,
    ) -> RuntimeQuotaCounterDecision {
        self.client
            .incr_by::<i64, _>(key, increment)
            .await
            .map_or_else(
                |_| {
                    self.mark_unavailable();
                    RuntimeQuotaCounterDecision {
                        current: limit,
                        allowed: false,
                    }
                },
                |current| {
                    self.mark_available();
                    RuntimeQuotaCounterDecision {
                        current,
                        allowed: current <= limit,
                    }
                },
            )
    }

    async fn runtime_policy_counter(&self, key: &str) -> i64 {
        match self.client.get::<Option<String>, _>(key).await {
            Ok(Some(value)) => {
                self.mark_available();
                value.parse::<i64>().unwrap_or_default().max(0)
            }
            Ok(None) => {
                self.mark_available();
                0
            }
            Err(_) => {
                self.mark_unavailable();
                0
            }
        }
    }

    async fn adjust_runtime_policy_counter(&self, key: String, delta: i64) -> i64 {
        self.client
            .eval::<i64, _, _, _>(SATURATING_ADJUST_COUNTER_LUA, vec![key], vec![delta])
            .await
            .map_or_else(
                |_| {
                    self.mark_unavailable();
                    0
                },
                |value| {
                    self.mark_available();
                    value
                },
            )
    }

    async fn increment_runtime_policy_loss_allowance_counter(
        &self,
        key: String,
        increment: i64,
        limit: i64,
    ) -> RuntimeQuotaCounterDecision {
        self.local_loss_allowance_store
            .increment_runtime_policy_loss_allowance_counter(key, increment, limit)
            .await
    }

    async fn adjust_runtime_policy_loss_allowance_counter(&self, key: String, delta: i64) -> i64 {
        self.local_loss_allowance_store
            .adjust_runtime_policy_loss_allowance_counter(key, delta)
            .await
    }

    async fn runtime_policy_loss_allowance_counter(&self, key: &str) -> i64 {
        self.local_loss_allowance_store
            .runtime_policy_loss_allowance_counter(key)
            .await
    }

    async fn record_runtime_budget_lease(&self, record: RuntimeBudgetLeaseRecord) {
        match self.write_budget_lease(&record).await {
            Ok(()) => self.mark_available(),
            Err(_) => self.mark_unavailable(),
        }
    }

    async fn release_runtime_budget_lease(
        &self,
        lease_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<RuntimeBudgetLeaseRecord> {
        let mut lease = self.read_budget_lease(lease_id).await.map_or_else(
            |_| {
                self.mark_unavailable();
                None
            },
            |lease| {
                self.mark_available();
                lease
            },
        )?;
        if lease.status != "reserved" {
            return None;
        }
        "released".clone_into(&mut lease.status);
        lease.updated_at = now;
        self.write_budget_lease(&lease).await.map_or_else(
            |_| {
                self.mark_unavailable();
                None
            },
            |()| {
                self.mark_available();
                Some(lease)
            },
        )
    }

    async fn expire_runtime_budget_leases(
        &self,
        tenant_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<RuntimeBudgetLeaseRecord> {
        let leases = if let Ok(leases) = self.read_tenant_budget_leases(tenant_id).await {
            self.mark_available();
            leases
        } else {
            self.mark_unavailable();
            return Vec::new();
        };
        let mut expired = Vec::new();
        for mut lease in leases {
            if lease.status == "reserved" && lease.expires_at <= now {
                "expired".clone_into(&mut lease.status);
                lease.updated_at = now;
                match self.write_budget_lease(&lease).await {
                    Ok(()) => expired.push(lease),
                    Err(_) => self.mark_unavailable(),
                }
            }
        }
        expired.sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
        expired
    }

    async fn runtime_budget_leases_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Vec<RuntimeBudgetLeaseRecord> {
        self.read_tenant_budget_leases(tenant_id).await.map_or_else(
            |_| {
                self.mark_unavailable();
                Vec::new()
            },
            |mut leases| {
                self.mark_available();
                leases.sort_by(|left, right| {
                    right
                        .created_at
                        .cmp(&left.created_at)
                        .then_with(|| left.lease_id.cmp(&right.lease_id))
                });
                leases
            },
        )
    }
}
