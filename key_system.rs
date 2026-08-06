// src/key_system.rs

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use chrono::{DateTime, Local, Duration};
use rand::Rng;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseKey {
    pub key: String,
    pub created_at: String,
    pub expires_at: String,
    pub max_devices: u32,
    pub current_devices: u32,
    pub features: Vec<String>,
    pub is_active: bool,
    pub owner: String,
    pub last_used: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyUsage {
    pub key_hash: String,
    pub ip: String,
    pub timestamp: String,
    pub action: String,
}

#[derive(Debug)]
pub struct KeySystem {
    keys_file: String,
    keys: Mutex<HashMap<String, LicenseKey>>,
    usage_log: Mutex<Vec<KeyUsage>>,
}

impl KeySystem {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let keys_file = "logs/keys/keys.json".to_string();
        let keys = if Path::new(&keys_file).exists() {
            let content = fs::read_to_string(&keys_file)?;
            let keys: HashMap<String, LicenseKey> = serde_json::from_str(&content)?;
            keys
        } else {
            HashMap::new()
        };
        
        Ok(KeySystem {
            keys_file,
            keys: Mutex::new(keys),
            usage_log: Mutex::new(Vec::new()),
        })
    }
    
    /// Генерация нового ключа
    pub fn generate_key(
        &self,
        days_valid: u32,
        max_devices: u32,
        features: Vec<String>,
        owner: String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        
        // Генерируем ключ в формате XXXX-XXXX-XXXX-XXXX
        let key = format!(
            "{:04X}-{:04X}-{:04X}-{:04X}",
            rng.gen::<u16>(),
            rng.gen::<u16>(),
            rng.gen::<u16>(),
            rng.gen::<u16>()
        );
        
        let created = Local::now();
        let expires = created + Duration::days(days_valid as i64);
        
        let license_key = LicenseKey {
            key: key.clone(),
            created_at: created.format("%Y-%m-%d %H:%M:%S").to_string(),
            expires_at: expires.format("%Y-%m-%d %H:%M:%S").to_string(),
            max_devices,
            current_devices: 0,
            features,
            is_active: true,
            owner,
            last_used: None,
        };
        
        let mut keys = self.keys.lock().unwrap();
        keys.insert(key.clone(), license_key);
        self.save_keys(&keys)?;
        
        Ok(key)
    }
    
    /// Валидация ключа
    pub fn validate_key(&self, key: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let keys = self.keys.lock().unwrap();
        
        if let Some(license) = keys.get(key) {
            // Проверяем активность
            if !license.is_active {
                return Ok(false);
            }
            
            // Проверяем срок действия
            let expires = DateTime::parse_from_str(
                &format!("{} +0000", license.expires_at),
                "%Y-%m-%d %H:%M:%S %z"
            )?;
            
            if expires < Local::now() {
                return Ok(false);
            }
            
            // Проверяем количество устройств
            if license.current_devices >= license.max_devices {
                return Ok(false);
            }
            
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    /// Активация устройства по ключу
    pub fn activate_device(
        &self,
        key: &str,
        ip: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut keys = self.keys.lock().unwrap();
        
        if let Some(license) = keys.get_mut(key) {
            if !license.is_active {
                return Ok(false);
            }
            
            // Проверяем срок
            let expires = DateTime::parse_from_str(
                &format!("{} +0000", license.expires_at),
                "%Y-%m-%d %H:%M:%S %z"
            )?;
            
            if expires < Local::now() {
                return Ok(false);
            }
            
            // Проверяем количество
            if license.current_devices >= license.max_devices {
                return Ok(false);
            }
            
            license.current_devices += 1;
            license.last_used = Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
            
            // Логируем использование
            let mut usage_log = self.usage_log.lock().unwrap();
            let hash = format!("{:x}", Sha256::digest(key.as_bytes()));
            usage_log.push(KeyUsage {
                key_hash: hash,
                ip: ip.to_string(),
                timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                action: "activate".to_string(),
            });
            
            self.save_keys(&keys)?;
            self.save_usage_log(&usage_log)?;
            
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    /// Деактивация устройства
    pub fn deactivate_device(&self, key: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut keys = self.keys.lock().unwrap();
        
        if let Some(license) = keys.get_mut(key) {
            if license.current_devices > 0 {
                license.current_devices -= 1;
            }
            self.save_keys(&keys)?;
        }
        
        Ok(())
    }
    
    /// Получение информации о ключе
    pub fn get_key_info(&self, key: &str) -> Option<LicenseKey> {
        let keys = self.keys.lock().unwrap();
        keys.get(key).cloned()
    }
    
    /// Получение статистики
    pub fn get_stats(&self) -> KeyStats {
        let keys = self.keys.lock().unwrap();
        
        let total = keys.len();
        let active = keys.values().filter(|k| k.is_active).count();
        let expired = keys.values()
            .filter(|k| {
                if let Ok(expires) = DateTime::parse_from_str(
                    &format!("{} +0000", k.expires_at),
                    "%Y-%m-%d %H:%M:%S %z"
                ) {
                    expires < Local::now()
                } else {
                    false
                }
            })
            .count();
        
        let total_devices: u32 = keys.values().map(|k| k.current_devices).sum();
        let max_devices: u32 = keys.values().map(|k| k.max_devices).sum();
        
        KeyStats {
            total_keys: total,
            active_keys: active,
            expired_keys: expired,
            total_devices,
            max_devices,
        }
    }
    
    /// Получение количества ключей
    pub fn get_key_count(&self) -> usize {
        let keys = self.keys.lock().unwrap();
        keys.len()
    }
    
    /// Сохранение ключей
    fn save_keys(&self, keys: &HashMap<String, LicenseKey>) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(keys)?;
        fs::write(&self.keys_file, json)?;
        Ok(())
    }
    
    /// Сохранение лога использования
    fn save_usage_log(&self, log: &[KeyUsage]) -> Result<(), Box<dyn std::error::Error>> {
        let log_file = "logs/keys/usage.json";
        let json = serde_json::to_string_pretty(log)?;
        fs::write(log_file, json)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct KeyStats {
    pub total_keys: usize,
    pub active_keys: usize,
    pub expired_keys: usize,
    pub total_devices: u32,
    pub max_devices: u32,
}