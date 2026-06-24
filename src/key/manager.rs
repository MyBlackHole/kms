use crate::crypto::sm3_engine::Sm3Engine;
use crate::crypto::traits::HashEngine;
use crate::key::store::KeyStore;
use crate::key::types::*;
use crate::Error;
use chrono::Utc;

pub struct KeyManager {
    pub store: Box<dyn KeyStore>,
    hasher: Sm3Engine,
}

impl KeyManager {
    pub fn new(store: Box<dyn KeyStore>) -> Self {
        Self {
            store,
            hasher: Sm3Engine::new(),
        }
    }

    pub async fn create_key(
        &self,
        name: &str,
        spec: KeySpec,
        policy: KeyPolicy,
        _owner: Option<&str>,
    ) -> crate::Result<Key> {
        let key_len = spec.key_length.max(16) as usize;
        let mut material = vec![0u8; key_len];
        getrandom::getrandom(&mut material)
            .map_err(|e| Error::Internal(format!("无法生成密钥材料: {}", e)))?;
        let material_hash = hex::encode(self.hasher.hash(&material));

        let mut key = Key::new(name, spec, policy);
        key.owner = _owner.map(String::from);

        let version = KeyVersion {
            version_number: 1,
            key_material_hash: material_hash,
            key_material: Some(material),
            hsm_key_id: None,
            state: KeyState::Enabled,
            created_at: Utc::now(),
            destroyed_at: None,
        };
        key.versions.push(version);
        key.current_version = 1;
        key.updated_at = Utc::now();

        self.store.create_key(&key).await?;
        Ok(key)
    }

    pub async fn get_key(&self, key_id: &str) -> crate::Result<Key> {
        self.store.get_key(key_id).await
    }

    pub async fn list_keys(&self) -> crate::Result<Vec<Key>> {
        self.store.list_keys().await
    }

    pub async fn enable_key(&self, key_id: &str) -> crate::Result<Key> {
        let mut key = self.store.get_key(key_id).await?;
        if matches!(key.state, KeyState::Destroyed | KeyState::Archived) {
            return Err(Error::Internal("已归档或已销毁的密钥无法启用".into()));
        }
        key.state = KeyState::Enabled;
        key.updated_at = Utc::now();
        self.store.update_key(&key).await?;
        Ok(key)
    }

    pub async fn disable_key(&self, key_id: &str) -> crate::Result<Key> {
        let mut key = self.store.get_key(key_id).await?;
        if matches!(key.state, KeyState::Destroyed | KeyState::Archived) {
            return Err(Error::Internal("已归档或已销毁的密钥无法禁用".into()));
        }
        key.state = KeyState::Disabled;
        key.updated_at = Utc::now();
        self.store.update_key(&key).await?;
        Ok(key)
    }

    pub async fn rotate_key(&self, key_id: &str) -> crate::Result<Key> {
        let mut key = self.store.get_key(key_id).await?;

        if let Some(max_versions) = key.policy.max_versions.checked_sub(1) {
            while key.versions.len() >= max_versions as usize {
                let oldest = key.versions.first().map(|v| v.version_number);
                if let Some(ver) = oldest {
                    key.versions.retain(|v| v.version_number != ver);
                } else {
                    break;
                }
            }
        }

        let new_version_number = key.current_version + 1;
        let mut key_material = vec![0u8; key.spec.key_length as usize];
        getrandom::getrandom(&mut key_material)
            .map_err(|e| Error::Internal(format!("无法生成密钥材料: {}", e)))?;

        let material_hash = hex::encode(self.hasher.hash(&key_material));

        let new_version = KeyVersion {
            version_number: new_version_number,
            key_material_hash: material_hash,
            key_material: Some(key_material),
            hsm_key_id: None,
            state: KeyState::Enabled,
            created_at: Utc::now(),
            destroyed_at: None,
        };

        key.versions.push(new_version);
        key.current_version = new_version_number;
        key.updated_at = Utc::now();

        self.store.update_key(&key).await?;

        Ok(key)
    }

    pub async fn archive_key(
        &self,
        key_id: &str,
        dep_store: &dyn crate::key::dependency::DependencyStore,
    ) -> crate::Result<Key> {
        let mut key = self.store.get_key(key_id).await?;

        if dep_store.has_dependents(key_id).await.unwrap_or(false) {
            return Err(Error::Internal(format!(
                "密钥 {} 存在依赖关系，无法归档。请先解除所有依赖。",
                key_id
            )));
        }

        key.state = KeyState::PendingArchive;
        key.updated_at = Utc::now();
        self.store.update_key(&key).await?;
        Ok(key)
    }

    pub async fn destroy_key(
        &self,
        key_id: &str,
        dep_store: &dyn crate::key::dependency::DependencyStore,
    ) -> crate::Result<Key> {
        let mut key = self.store.get_key(key_id).await?;

        if dep_store.has_dependents(key_id).await.unwrap_or(false) {
            return Err(Error::Internal(format!(
                "密钥 {} 存在依赖关系，无法销毁。请先解除所有依赖。",
                key_id
            )));
        }

        if !matches!(key.state, KeyState::Disabled | KeyState::PendingArchive) {
            return Err(Error::Internal("只有已禁用或待归档的密钥才能销毁".into()));
        }

        for version in &mut key.versions {
            if !matches!(version.state, KeyState::Destroyed | KeyState::Archived) {
                version.state = KeyState::Destroyed;
                version.destroyed_at = Some(Utc::now());
            }
        }

        key.state = KeyState::Destroyed;
        key.updated_at = Utc::now();
        self.store.update_key(&key).await?;
        Ok(key)
    }

    /// 获取指定密钥当前版本的材料（用于导出）
    pub fn get_key_material<'a>(&self, key: &'a Key) -> Option<&'a [u8]> {
        key.versions
            .iter()
            .find(|v| v.version_number == key.current_version)
            .and_then(|v| v.key_material.as_deref())
    }

    /// 为指定密钥版本存储外部密钥材料（用于导入）
    pub async fn store_key_material(
        &self,
        key_id: &str,
        version_number: u32,
        material: Vec<u8>,
    ) -> crate::Result<()> {
        let mut key = self.store.get_key(key_id).await?;
        let material_hash = hex::encode(self.hasher.hash(&material));
        let version = key
            .versions
            .iter_mut()
            .find(|v| v.version_number == version_number)
            .ok_or_else(|| Error::Internal("版本不存在".into()))?;
        version.key_material = Some(material);
        version.key_material_hash = material_hash;
        self.store.update_key(&key).await
    }

    pub fn derive_cmk(&self, key_material: &[u8], key_id: &str, version: u32) -> Vec<u8> {
        let info = format!("KMS_CMK_{}_{}", key_id, version);
        let mut derived = self.hasher.hash(&[key_material, info.as_bytes()].concat());
        derived.resize(16, 0);
        derived
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::dependency::SqliteDependencyStore;
    use crate::key::store::KeyStoreSqlite;

    fn spec() -> crate::key::types::KeySpec {
        crate::key::types::KeySpec {
            algorithm: crate::key::types::KeyAlgorithm::Sm4,
            key_length: 128,
            usage: vec![],
            extractable: false,
        }
    }

    fn policy() -> crate::key::types::KeyPolicy {
        crate::key::types::KeyPolicy {
            rotation_days: Some(90),
            expiration_days: None,
            max_versions: 3,
            require_mfa_to_disable: false,
            require_mfa_to_destroy: true,
            allowed_roles: vec![],
        }
    }

    async fn setup() -> (KeyManager, sqlx::SqlitePool) {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::store::migrations::run_migrations(&pool)
            .await
            .unwrap();
        let store = KeyStoreSqlite::new(pool.clone());
        let km = KeyManager::new(Box::new(store));
        (km, pool)
    }

    #[tokio::test]
    async fn test_create_key() {
        let (km, _pool) = setup().await;
        let key = km.create_key("test", spec(), policy(), None).await.unwrap();
        assert_eq!(key.name, "test");
        assert_eq!(key.state, crate::key::types::KeyState::Enabled);
        assert_eq!(key.current_version, 1);
        assert_eq!(key.versions.len(), 1);
        assert!(
            key.versions[0].key_material.is_some(),
            "创建密钥时应该生成材料"
        );
    }

    #[tokio::test]
    async fn test_get_key() {
        let (km, _pool) = setup().await;
        let created = km
            .create_key("get-test", spec(), policy(), None)
            .await
            .unwrap();
        let fetched = km.get_key(&created.id).await.unwrap();
        assert_eq!(fetched.id, created.id);
        assert_eq!(fetched.name, "get-test");
    }

    #[tokio::test]
    async fn test_enable_disable_cycle() {
        let (km, _pool) = setup().await;
        let key = km
            .create_key("cycle", spec(), policy(), None)
            .await
            .unwrap();

        let disabled = km.disable_key(&key.id).await.unwrap();
        assert_eq!(disabled.state, crate::key::types::KeyState::Disabled);

        let enabled = km.enable_key(&key.id).await.unwrap();
        assert_eq!(enabled.state, crate::key::types::KeyState::Enabled);
    }

    #[tokio::test]
    async fn test_rotate_key() {
        let (km, _pool) = setup().await;
        let key = km
            .create_key("rotate", spec(), policy(), None)
            .await
            .unwrap();
        assert_eq!(key.current_version, 1);
        assert_eq!(key.versions.len(), 1);

        let rotated = km.rotate_key(&key.id).await.unwrap();
        assert_eq!(rotated.current_version, 2);
        assert_eq!(rotated.versions.len(), 2, "轮换后应产生新版本");
    }

    #[tokio::test]
    async fn test_archive_and_destroy() {
        let (km, pool) = setup().await;
        let dep_store = SqliteDependencyStore::new(pool.clone());
        let key = km
            .create_key("archive-destroy", spec(), policy(), None)
            .await
            .unwrap();

        km.disable_key(&key.id).await.unwrap();

        let archived = km.archive_key(&key.id, &dep_store).await.unwrap();
        assert_eq!(archived.state, crate::key::types::KeyState::PendingArchive);

        km.destroy_key(&key.id, &dep_store).await.unwrap();
        let destroyed = km.get_key(&key.id).await.unwrap();
        assert_eq!(destroyed.state, crate::key::types::KeyState::Destroyed);
    }

    #[tokio::test]
    async fn test_list_keys() {
        let (km, _pool) = setup().await;
        km.create_key("k1", spec(), policy(), None).await.unwrap();
        km.create_key("k2", spec(), policy(), None).await.unwrap();
        km.create_key("k3", spec(), policy(), None).await.unwrap();

        let keys = km.list_keys().await.unwrap();
        assert_eq!(keys.len(), 3);
    }
}
