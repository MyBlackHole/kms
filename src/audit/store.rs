use crate::audit::logger::{AuditEvent, AuditStore};
use crate::crypto::sm3_engine::Sm3Engine;
use crate::crypto::traits::HashEngine;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct InMemoryAuditStore {
    events: DashMap<String, AuditEvent>,
    counter: AtomicU64,
}

impl Default for InMemoryAuditStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryAuditStore {
    pub fn new() -> Self {
        Self {
            events: DashMap::new(),
            counter: AtomicU64::new(0),
        }
    }
}

#[async_trait::async_trait]
impl AuditStore for InMemoryAuditStore {
    async fn append(&self, event: &AuditEvent) -> crate::Result<()> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        self.events.insert(event.event_id.clone(), event.clone());
        Ok(())
    }

    async fn query(&self, start_time: i64, end_time: i64) -> crate::Result<Vec<AuditEvent>> {
        let mut results: Vec<AuditEvent> = self
            .events
            .iter()
            .filter(|e| e.timestamp >= start_time && e.timestamp <= end_time)
            .map(|e| e.value().clone())
            .collect();
        results.sort_by_key(|e| e.timestamp);
        Ok(results)
    }

    async fn get_latest(&self) -> crate::Result<Option<AuditEvent>> {
        Ok(self
            .events
            .iter()
            .max_by_key(|e| e.timestamp)
            .map(|e| e.value().clone()))
    }

    async fn verify_chain(&self) -> crate::Result<bool> {
        let hasher = Sm3Engine::new();
        let mut events: Vec<AuditEvent> = self.events.iter().map(|e| e.value().clone()).collect();
        events.sort_by_key(|e| e.timestamp);

        let mut previous_hash: Option<String> = None;

        for event in &events {
            if self::check_hash_integrity(event, &hasher, &previous_hash).is_err() {
                return Ok(false);
            }
            previous_hash = event.hash.clone();
        }

        Ok(true)
    }
}

fn check_hash_integrity(
    event: &AuditEvent,
    hasher: &Sm3Engine,
    expected_prev_hash: &Option<String>,
) -> crate::Result<()> {
    let bytes = event.canonical_bytes();
    let computed = hasher.hash(&bytes);
    let computed_hex = hex::encode(&computed);

    if let Some(ref event_hash) = event.hash {
        if event_hash != &computed_hex {
            return Err(crate::Error::VerificationFailed(
                "审计日志哈希不匹配".into(),
            ));
        }
    }
    if event.previous_hash != *expected_prev_hash {
        return Err(crate::Error::VerificationFailed(
            "审计日志链断裂：前一哈希不匹配".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::traits::HashEngine;

    #[tokio::test]
    async fn test_in_memory_audit_store_verify_chain() {
        let store = InMemoryAuditStore::new();
        let hasher = Sm3Engine::new();

        let mut first = AuditEvent::new("key.create", "admin", "CREATE", "key:one", "success");
        first.timestamp = 1000;
        first.hash = Some(hex::encode(hasher.hash(&first.canonical_bytes())));

        let mut second = AuditEvent::new("key.rotate", "admin", "ROTATE", "key:one", "success");
        second.timestamp = 1001;
        second.previous_hash = first.hash.clone();
        second.hash = Some(hex::encode(hasher.hash(&second.canonical_bytes())));

        store.append(&first).await.unwrap();
        store.append(&second).await.unwrap();
        assert!(store.verify_chain().await.unwrap());

        let mut tampered = second.clone();
        tampered.action = "DELETE".into();
        store.events.insert(tampered.event_id.clone(), tampered);
        assert!(!store.verify_chain().await.unwrap());
    }
}
