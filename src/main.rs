// ============================================================
//  ARLIAN PERIMETER v8.2
//  AI-Powered Rogue Device Detector
//  FULL IPv6 SUPPORT | Kayoli Learning | Self-Training
// ============================================================

use chrono::{Datelike, Local, Timelike};
use colored::*;
use dashmap::DashMap;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

mod antiflood;
mod ddos;
use crate::antiflood::AntiFlood;
use crate::ddos::DdosProtector;

// ============================================================
//  CONSTANTS / КОНСТАНТЫ
// ============================================================

const VERSION: &str = "8.2";
const BUILD_DATE: Option<&str> = option_env!("BUILD_DATE");

const AI_DIR: &str = "ArlianAI";
const KAYOLI_DIR: &str = "ArlianAI/Kayoli";
const TRAINING_DIR: &str = "ArlianAI/training_data";
const AI_LOGS_DIR: &str = "ArlianAI/logs";
const MODELS_DIR: &str = "ArlianAI/models";

const MAX_SAMPLES_PER_IP: usize = 500;
const TRIM_TO_SAMPLES: usize = 400;
const SAMPLE_THRESHOLD_RATIO: f32 = 0.3;
const MIN_SAMPLES_FOR_BEHAVIOR: usize = 5;
const BEHAVIOR_MIN_APPEARANCES: u32 = 10;
const MAX_IP_AGE_SECS: u64 = 7 * 24 * 3600;

const RISK_KAYOLI_SCALE: f64 = 100.0;
const RISK_UNUSUAL_TIME: f64 = 0.4;
const RISK_UNUSUAL_PORTS_MAX: f64 = 0.6;
const RISK_LOW_SAMPLE_PENALTY: f64 = 0.5;
const RISK_ANOMALY_SCALE: f64 = 35.0;
const RISK_DANGEROUS_PORT: u8 = 20;
const RISK_MASS_SCAN: u8 = 15;
const MASS_SCAN_THRESHOLD: usize = 5;
const HIGH_RISK_THRESHOLD: u8 = 60;

const SCAN_PORTS: [u16; 6] = [80, 443, 22, 445, 3389, 5900];

// ============================================================
//  UNIVERSAL IP ADDRESS / УНИВЕРСАЛЬНЫЙ IP АДРЕС
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpAddrUniversal {
    V4(u32),
    V6(u128),
}

impl IpAddrUniversal {
    pub fn new(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => IpAddrUniversal::V4(u32::from(v4)),
            IpAddr::V6(v6) => IpAddrUniversal::V6(u128::from(v6)),
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        if let Ok(ip) = s.parse::<Ipv4Addr>() {
            Some(IpAddrUniversal::V4(u32::from(ip)))
        } else if let Ok(ip) = s.parse::<Ipv6Addr>() {
            Some(IpAddrUniversal::V6(u128::from(ip)))
        } else {
            None
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            IpAddrUniversal::V4(ip) => {
                let [a, b, c, d] = ip.to_be_bytes();
                format!("{}.{}.{}.{}", a, b, c, d)
            }
            IpAddrUniversal::V6(ip) => {
                let bytes = ip.to_be_bytes();
                let octets: [u16; 8] = [
                    u16::from_be_bytes([bytes[0], bytes[1]]),
                    u16::from_be_bytes([bytes[2], bytes[3]]),
                    u16::from_be_bytes([bytes[4], bytes[5]]),
                    u16::from_be_bytes([bytes[6], bytes[7]]),
                    u16::from_be_bytes([bytes[8], bytes[9]]),
                    u16::from_be_bytes([bytes[10], bytes[11]]),
                    u16::from_be_bytes([bytes[12], bytes[13]]),
                    u16::from_be_bytes([bytes[14], bytes[15]]),
                ];
                Ipv6Addr::from(octets).to_string()
            }
        }
    }

    pub fn is_v4(&self) -> bool {
        matches!(self, IpAddrUniversal::V4(_))
    }

    pub fn is_v6(&self) -> bool {
        matches!(self, IpAddrUniversal::V6(_))
    }

    pub fn as_v4(&self) -> Option<u32> {
        match self {
            IpAddrUniversal::V4(ip) => Some(*ip),
            _ => None,
        }
    }

    pub fn as_v6(&self) -> Option<u128> {
        match self {
            IpAddrUniversal::V6(ip) => Some(*ip),
            _ => None,
        }
    }

    pub fn is_local(&self) -> bool {
        match self {
            IpAddrUniversal::V4(ip) => {
                *ip == 0 || *ip == 0x7f000001 || (*ip & 0xffff0000) == 0xa9fe0000
            }
            IpAddrUniversal::V6(ip) => {
                let ip = *ip;
                ip == 1
                    || ip == 0x7f000000000000000000000000000001
                    || (ip & 0xff000000000000000000000000000000)
                        == 0xfe800000000000000000000000000000
            }
        }
    }

    pub fn is_public(&self) -> bool {
        !self.is_local()
    }

    pub fn protocol(&self) -> &'static str {
        match self {
            IpAddrUniversal::V4(_) => "IPv4",
            IpAddrUniversal::V6(_) => "IPv6",
        }
    }
}

// ============================================================
//  DATA STRUCTURES / СТРУКТУРЫ ДАННЫХ
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrainingSample {
    timestamp: String,
    ip: String,
    #[serde(default)]
    ip_type: String,
    hour: u32,
    day_of_week: u32,
    open_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceBehavior {
    ip: String,
    #[serde(default)]
    ip_type: String,
    typical_hours: Vec<u32>,
    typical_ports: Vec<u16>,
    appearance_count: u32,
    #[serde(default)]
    first_seen: String,
    last_seen: String,
    #[serde(default)]
    unique_days: u32,
    #[serde(default)]
    avg_interval_minutes: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HackerProfile {
    ip: String,
    ip_type: String,
    mac: Option<String>,
    first_seen: String,
    last_seen: String,
    attack_count: u32,
    scanned_ports: Vec<u16>,
    suspicious_activities: Vec<String>,
    risk_score: u8,
    status: String,
    warning_count: u32,
    recent_events: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IntelligenceLog {
    timestamp: String,
    ip: String,
    ip_type: String,
    event_type: String,
    details: String,
    risk_level: u8,
    source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LearningPoint {
    timestamp: String,
    devices_learned: usize,
    total_samples: usize,
    sample_to_device_ratio: f64,
    ipv6_count: usize,
    ipv4_count: usize,
}

// ============================================================
//  AI LOGGER / AI ЛОГГЕР
// ============================================================

struct AILogger {
    event_log: Mutex<fs::File>,
    anomaly_log: Mutex<fs::File>,
    decision_log: Mutex<fs::File>,
}

impl AILogger {
    fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let today = Local::now().format("%Y-%m-%d");
        let open = |name: &str| {
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{}/{}_{}.log", AI_LOGS_DIR, name, today))
        };
        Ok(AILogger {
            event_log: Mutex::new(open("every_event")?),
            anomaly_log: Mutex::new(open("anomalies_detected")?),
            decision_log: Mutex::new(open("ai_decisions")?),
        })
    }

    fn log_event(&self, event: &str) {
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        if let Ok(mut f) = self.event_log.lock() {
            let _ = writeln!(f, "[{}] {}", ts, event);
        }
        println!("[EVENT] {}", event);
    }

    fn log_anomaly(&self, ip: &str, risk: u8, details: &str) {
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        if let Ok(mut f) = self.anomaly_log.lock() {
            let _ = writeln!(f, "[{}] ANOMALY IP={} risk={}% {}", ts, ip, risk, details);
        }
        println!(
            "{}",
            format!("⚠️ ANOMALY / АНОМАЛИЯ {}: {}% - {}", ip, risk, details).red()
        );
    }

    fn log_decision(&self, decision: &str) {
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        if let Ok(mut f) = self.decision_log.lock() {
            let _ = writeln!(f, "[{}] {}", ts, decision);
        }
        self.log_event(&format!("DECISION: {}", decision));
    }
}

// ============================================================
//  KAYOLI / KAYOLI
// ============================================================

struct KayoliTrainer {
    attack_patterns: Vec<String>,
    _normal_patterns: Vec<String>,
    _custom_rules: Vec<String>,
    logger: Arc<AILogger>,
}

impl KayoliTrainer {
    fn new(logger: Arc<AILogger>) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let mut trainer = KayoliTrainer {
            attack_patterns: Vec::new(),
            _normal_patterns: Vec::new(),
            _custom_rules: Vec::new(),
            logger,
        };
        trainer.load_patterns()?;
        Ok(trainer)
    }

    fn load_patterns(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self._normal_patterns = Self::load_or_create(
            &format!("{}/normal_behavior.txt", KAYOLI_DIR),
            DEFAULT_NORMAL_BEHAVIOR,
        )?;
        for line in &self._normal_patterns {
            self.logger
                .log_event(&format!("KAYOLI: нормальный паттерн: {}", line));
        }

        self.attack_patterns = Self::load_or_create(
            &format!("{}/attack_patterns.txt", KAYOLI_DIR),
            DEFAULT_ATTACK_PATTERNS,
        )?;

        self._custom_rules = Self::load_or_create(
            &format!("{}/custom_rules.txt", KAYOLI_DIR),
            DEFAULT_CUSTOM_RULES,
        )?;
        Ok(())
    }

    fn load_or_create(
        path: &str,
        default: &str,
    ) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
        if !Path::new(path).exists() {
            fs::write(path, default)?;
        }
        let content = fs::read_to_string(path)?;
        Ok(content
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect())
    }

    fn detect(&self, hour: u32, ports: &[u16]) -> (u8, Vec<String>) {
        let mut risk: u32 = 0;
        let mut matches = Vec::new();

        let dangerous = [22u16, 445, 3389, 5900];

        for pattern in &self.attack_patterns {
            if pattern.contains("port_scan") {
                if ports.iter().any(|p| dangerous.contains(p)) {
                    risk += 15;
                    matches.push(format!("Паттерн атаки: {}", pattern));
                }
            }
            if pattern.contains("night_activity") && (hour >= 23 || hour <= 6) {
                risk += 15;
                matches.push(format!("Ночная активность: {}", pattern));
            }
            if pattern.contains("mass_scan") && ports.len() > MASS_SCAN_THRESHOLD {
                risk += 20;
                matches.push(format!("Массовое сканирование: {}", pattern));
            }
        }
        (risk.min(100) as u8, matches)
    }
}

const DEFAULT_NORMAL_BEHAVIOR: &str = r#"# ARLIAN KAYOLI - Нормальное поведение устройств
router:0-23:53,67,68,80,443
printer:9-18:515,631,9100
camera:0-23:554,8080,80
pc_work:9-20:80,443,22,3389
pc_home:17-23:80,443,22,445,3389
smart_tv:18-23:80,443,554,1900
iot_sensor:0-23:1883,8883
phone:0-23:80,443,5228
"#;

const DEFAULT_ATTACK_PATTERNS: &str = r#"# ARLIAN KAYOLI - Паттерны атак
port_scan:22,445,3389,5900,1433,3306
smb_attack:445
ssh_brute:22
rdp_attack:3389
mass_scan:>5_ports
night_activity:23-6
"#;

const DEFAULT_CUSTOM_RULES: &str = r#"# ARLIAN KAYOLI - Пользовательские правила
rule:port_445_risk=+30
rule:night_hour_risk=+15
rule:mass_scan_threshold=10
rule:mass_scan_risk=+25
"#;

// ============================================================
//  КОНФИГ
// ============================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    network: String,
    scan_interval: u64,
    ban_real: bool,
    scan_timeout_ms: u64,
    max_concurrent_scans: usize,
    ai_learning_mode: bool,
    anomaly_threshold: f64,
    rate_limit_ms: u64,
    ip_protocol: String,
    enable_ipv6: bool,
    enable_ipv4: bool,
    // Пороги DDoS / Anti-Flood (настраиваемые)
    #[serde(default = "default_syn_threshold")]
    syn_threshold: usize,
    #[serde(default = "default_ip_threshold")]
    ip_threshold: usize,
    #[serde(default = "default_udp_threshold")]
    udp_threshold: usize,
    #[serde(default = "default_icmp_threshold")]
    icmp_threshold: usize,
    #[serde(default = "default_http_threshold")]
    http_threshold: usize,
    #[serde(default = "default_ssh_threshold")]
    ssh_threshold: usize,
    #[serde(default = "default_ddos_min_sources")]
    ddos_min_sources: usize,
    #[serde(default = "default_ban_duration_secs")]
    ban_duration_secs: u64,
    #[serde(default = "default_permanent_ban_after")]
    permanent_ban_after: u32,
    // IPv6: максимальное число адресов для сканирования подсети
    #[serde(default = "default_ipv6_max_hosts")]
    ipv6_max_hosts: usize,
}

fn default_syn_threshold() -> usize { 100 }
fn default_ip_threshold() -> usize { 200 }
fn default_udp_threshold() -> usize { 150 }
fn default_icmp_threshold() -> usize { 200 }
fn default_http_threshold() -> usize { 500 }
fn default_ssh_threshold() -> usize { 40 }
fn default_ddos_min_sources() -> usize { 10 }
fn default_ban_duration_secs() -> u64 { 600 }
fn default_permanent_ban_after() -> u32 { 5 }
fn default_ipv6_max_hosts() -> usize { 65536 }

impl Default for Config {
    fn default() -> Self {
        Config {
            network: "192.168.1.0/24".to_string(),
            scan_interval: 60,
            ban_real: true,
            scan_timeout_ms: 300,
            max_concurrent_scans: 100,
            ai_learning_mode: true,
            anomaly_threshold: 0.6,
            rate_limit_ms: 5000,
            ip_protocol: "both".to_string(),
            enable_ipv6: true,
            enable_ipv4: true,
            syn_threshold: 100,
            ip_threshold: 200,
            udp_threshold: 150,
            icmp_threshold: 200,
            http_threshold: 500,
            ssh_threshold: 40,
            ddos_min_sources: 10,
            ban_duration_secs: 600,
            permanent_ban_after: 5,
            ipv6_max_hosts: 65536,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Whitelist {
    ips: Vec<String>,
    macs: Vec<String>,
    ipv6_prefixes: Vec<String>,
}

impl Default for Whitelist {
    fn default() -> Self {
        Whitelist {
            ips: vec![
                "192.168.1.1".to_string(),
                "192.168.1.2".to_string(),
                "fd00::1".to_string(),
            ],
            macs: vec!["aa:bb:cc:dd:ee:ff".to_string()],
            ipv6_prefixes: vec!["fd00::/64".to_string()],
        }
    }
}

// ============================================================
//  AI PYTHON ИНТЕГРАЦИЯ
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AiDeviceResult {
    anomaly_score: f64,
    is_anomaly: bool,
    risk: u8,
    samples_count: usize,
    last_seen: String,
    ip_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AiResult {
    timestamp: String,
    total_samples: usize,
    model_trained: bool,
    devices: HashMap<String, AiDeviceResult>,
}

impl AiResult {
    fn load() -> Option<Self> {
        let path = format!("{}/ai_result.json", MODELS_DIR);
        let content = fs::read_to_string(&path).ok()?;
        serde_json::from_str(&content).ok()
    }
}

fn run_ai_python() {
    std::thread::spawn(
        || match std::process::Command::new("python3").arg("ai.py").output() {
            Ok(out) => {
                if !out.status.success() {
                    eprintln!(
                        "{}",
                        format!("[AI.PY] Ошибка: {}", String::from_utf8_lossy(&out.stderr))
                            .yellow()
                    );
                }
            }
            Err(e) => eprintln!("{}", format!("[AI.PY] Не запустился: {}", e).yellow()),
        },
    );
}

// ============================================================
//  IP ФУНКЦИИ
// ============================================================

fn ip_to_u32(ip: &str) -> Option<u32> {
    if ip.contains(':') {
        return None; // IPv6 не конвертируется в u32
    }
    let mut parts = ip.split('.');
    let a: u8 = parts.next()?.parse().ok()?;
    let b: u8 = parts.next()?.parse().ok()?;
    let c: u8 = parts.next()?.parse().ok()?;
    let d: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(u32::from_be_bytes([a, b, c, d]))
}

fn validate_ip(ip: &str) -> bool {
    if ip.contains(':') {
        return ip.parse::<Ipv6Addr>().is_ok();
    }
    ip.split('.').count() == 4 && ip.split('.').all(|p| p.parse::<u8>().is_ok())
}

fn parse_cidr(
    cidr: &str,
    ipv6_max_hosts: usize,
) -> Result<Vec<IpAddrUniversal>, Box<dyn Error + Send + Sync>> {
    // Пробуем как IPv4
    if let Ok(net) = cidr.parse::<ipnet::Ipv4Net>() {
        let mut ips = Vec::new();
        for ip in net.hosts() {
            ips.push(IpAddrUniversal::V4(u32::from(ip)));
        }
        return Ok(ips);
    }

    // Пробуем как IPv6
    if let Ok(net) = cidr.parse::<ipnet::Ipv6Net>() {
        let mut ips = Vec::new();
        // Для IPv6 НЕ перебираем все адреса (в /64 их 2^64 — невозможно).
        // Сканируем только первые N адресов подсети (настраивается в config.json,
        // поле ipv6_max_hosts). По умолчанию 65536 (первые /48 подсети).
        for ip in net.hosts().take(ipv6_max_hosts) {
            ips.push(IpAddrUniversal::V6(u128::from(ip)));
        }
        return Ok(ips);
    }

    Err("Неверный CIDR формат".into())
}

// ============================================================
//  ARP ДЛЯ IPv4 И IPv6
// ============================================================

fn get_mac_from_ip(ip: &str) -> Option<String> {
    if ip.contains(':') {
        return get_mac_from_ipv6(ip);
    }
    get_mac_from_ipv4(ip)
}

fn get_mac_from_ipv4(ip: &str) -> Option<String> {
    if !validate_ip(ip) {
        return None;
    }
    if let Ok(content) = fs::read_to_string("/proc/net/arp") {
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 4 && cols[0] == ip && cols[2] == "0x2" {
                let mac = cols[3];
                if mac.len() == 17 && mac.contains(':') {
                    return Some(mac.to_lowercase());
                }
            }
        }
    }
    let out = std::process::Command::new("arp")
        .args(["-n", ip])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout.lines().find(|l| l.contains(ip)).and_then(|line| {
        line.split_whitespace()
            .find(|w| w.len() == 17 && w.contains(':'))
            .map(|m| m.to_lowercase())
    })
}

fn get_mac_from_ipv6(ip: &str) -> Option<String> {
    if let Ok(content) = fs::read_to_string("/proc/net/ipv6_neighbour") {
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 5 {
                let ip6 = cols[0];
                let mac = cols[4];
                if ip6 == ip && mac.len() == 17 && mac.contains(':') {
                    return Some(mac.to_lowercase());
                }
            }
        }
    }

    let out = std::process::Command::new("ip")
        .args(["-6", "neigh", "show"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout.lines().find(|l| l.contains(ip)).and_then(|line| {
        line.split_whitespace()
            .skip(2)
            .find(|w| w.len() == 17 && w.contains(':'))
            .map(|m| m.to_lowercase())
    })
}

// ============================================================
//  RATE LIMITER (С ПОДДЕРЖКОЙ IPv6)
// ============================================================

struct RateLimiter {
    last_scan_v4: DashMap<u32, Instant>,
    last_scan_v6: DashMap<u128, Instant>,
    last_scan_generic: DashMap<String, Instant>,
    min_interval: Duration,
    max_entries: usize,
    stats: RwLock<RateLimiterStats>,
}

#[derive(Debug, Clone, Default)]
struct RateLimiterStats {
    total_requests: u64,
    allowed_requests: u64,
    denied_requests: u64,
    ipv4_hits: u64,
    ipv6_hits: u64,
    cache_size: usize,
}

impl RateLimiter {
    fn new(min_interval_ms: u64) -> Self {
        RateLimiter {
            last_scan_v4: DashMap::new(),
            last_scan_v6: DashMap::new(),
            last_scan_generic: DashMap::new(),
            min_interval: Duration::from_millis(min_interval_ms),
            max_entries: 10000,
            stats: RwLock::new(RateLimiterStats::default()),
        }
    }

    fn allow_scan(&self, ip: &str) -> bool {
        let now = Instant::now();

        if let Some(ip_addr) = IpAddrUniversal::from_str(ip) {
            match ip_addr {
                IpAddrUniversal::V4(ip4) => {
                    if let Some(last) = self.last_scan_v4.get(&ip4) {
                        if now.duration_since(*last) < self.min_interval {
                            self.update_stats(false);
                            return false;
                        }
                    }
                    self.last_scan_v4.insert(ip4, now);
                    self.update_stats_ipv4(true);
                }
                IpAddrUniversal::V6(ip6) => {
                    if let Some(last) = self.last_scan_v6.get(&ip6) {
                        if now.duration_since(*last) < self.min_interval {
                            self.update_stats(false);
                            return false;
                        }
                    }
                    self.last_scan_v6.insert(ip6, now);
                    self.update_stats_ipv6(true);
                }
            }
        }

        if let Some(last) = self.last_scan_generic.get(ip) {
            if now.duration_since(*last) < self.min_interval {
                self.update_stats(false);
                return false;
            }
        }

        self.last_scan_generic.insert(ip.to_string(), now);
        self.update_stats(true);
        true
    }

    fn update_stats(&self, allowed: bool) {
        if let Ok(mut stats) = self.stats.write() {
            stats.total_requests += 1;
            if allowed {
                stats.allowed_requests += 1;
            } else {
                stats.denied_requests += 1;
            }
            stats.cache_size = self.last_scan_generic.len();
        }
    }

    fn update_stats_ipv4(&self, allowed: bool) {
        if let Ok(mut stats) = self.stats.write() {
            stats.ipv4_hits += 1;
            if allowed {
                stats.allowed_requests += 1;
            } else {
                stats.denied_requests += 1;
            }
        }
    }

    fn update_stats_ipv6(&self, allowed: bool) {
        if let Ok(mut stats) = self.stats.write() {
            stats.ipv6_hits += 1;
            if allowed {
                stats.allowed_requests += 1;
            } else {
                stats.denied_requests += 1;
            }
        }
    }

    fn cleanup(&self) {
        let max_age = Duration::from_secs(MAX_IP_AGE_SECS);
        self.last_scan_v4.retain(|_, last| last.elapsed() < max_age);
        self.last_scan_v6.retain(|_, last| last.elapsed() < max_age);
        self.last_scan_generic
            .retain(|_, last| last.elapsed() < max_age);

        if self.last_scan_generic.len() > self.max_entries {
            let mut entries: Vec<(String, Instant)> = self
                .last_scan_generic
                .iter()
                .map(|e| (e.key().clone(), *e.value()))
                .collect();
            entries.sort_by_key(|(_, t)| *t);
            let to_remove = entries.len() - self.max_entries;
            for (key, _) in entries.iter().take(to_remove) {
                self.last_scan_generic.remove(key);
            }
        }
    }

    fn print_stats(&self) {
        if let Ok(stats) = self.stats.read() {
            println!("   Rate Limiter:");
            println!(
                "     Total/Всего: {}, Allowed/Разрешено: {}, Blocked/Блокировано: {}",
                stats.total_requests, stats.allowed_requests, stats.denied_requests
            );
            println!("     IPv4: {}, IPv6: {}", stats.ipv4_hits, stats.ipv6_hits);
            println!("     Cache/Кэш: {}", stats.cache_size);
        }
    }
}

// ============================================================
//  AI ДЕТЕКТОР (ОБНОВЛЕННЫЙ)
// ============================================================

struct AIDetector {
    training_data: DashMap<String, Vec<TrainingSample>>,
    device_behaviors: DashMap<String, DeviceBehavior>,
    hacker_profiles: DashMap<String, HackerProfile>,
    intel_logs: DashMap<u64, IntelligenceLog>,
    intel_log_counter: AtomicU64,
    anomaly_threshold: f64,
    kayoli: KayoliTrainer,
    ai_logger: Arc<AILogger>,
    learning_curve: Mutex<Vec<LearningPoint>>,
}

impl AIDetector {
    fn new(
        anomaly_threshold: f64,
        ai_logger: Arc<AILogger>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let kayoli = KayoliTrainer::new(ai_logger.clone())?;
        let detector = AIDetector {
            training_data: DashMap::new(),
            device_behaviors: DashMap::new(),
            hacker_profiles: DashMap::new(),
            intel_logs: DashMap::new(),
            intel_log_counter: AtomicU64::new(0),
            anomaly_threshold,
            kayoli,
            ai_logger: ai_logger.clone(),
            learning_curve: Mutex::new(Vec::new()),
        };
        detector.load_training_data()?;
        detector.ai_logger.log_event("AI Детектор инициализирован");
        Ok(detector)
    }

    fn save_training_data(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let samples: Vec<TrainingSample> = self
            .training_data
            .iter()
            .flat_map(|e| e.value().clone())
            .collect();
        if !samples.is_empty() {
            fs::write(
                format!("{}/devices.json", TRAINING_DIR),
                serde_json::to_string_pretty(&samples)?,
            )?;
        }

        let behaviors: Vec<DeviceBehavior> = self
            .device_behaviors
            .iter()
            .map(|e| e.value().clone())
            .collect();
        if !behaviors.is_empty() {
            fs::write(
                format!("{}/behaviors.json", TRAINING_DIR),
                serde_json::to_string_pretty(&behaviors)?,
            )?;
        }

        let profiles: Vec<HackerProfile> = self
            .hacker_profiles
            .iter()
            .map(|e| e.value().clone())
            .collect();
        if !profiles.is_empty() {
            fs::write(
                format!("{}/hacker_profiles.json", TRAINING_DIR),
                serde_json::to_string_pretty(&profiles)?,
            )?;
        }

        self.ai_logger.log_event(&format!(
            "Сохранено: {} образцов, {} поведений, {} профилей",
            samples.len(),
            behaviors.len(),
            profiles.len()
        ));
        Ok(())
    }

    fn load_training_data(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let path = format!("{}/devices.json", TRAINING_DIR);
        if Path::new(&path).exists() {
            let samples: Vec<TrainingSample> = serde_json::from_str(&fs::read_to_string(&path)?)?;
            self.ai_logger
                .log_event(&format!("Загружено {} образцов", samples.len()));
            for mut sample in samples {
                // Автозаполнение ip_type для старых данных
                if sample.ip_type.is_empty() {
                    sample.ip_type = if sample.ip.contains(':') {
                        "IPv6".to_string()
                    } else {
                        "IPv4".to_string()
                    };
                }
                self.training_data
                    .entry(sample.ip.clone())
                    .or_default()
                    .push(sample);
            }
        }

        let behaviors_path = format!("{}/behaviors.json", TRAINING_DIR);
        if Path::new(&behaviors_path).exists() {
            let behaviors: Vec<DeviceBehavior> =
                serde_json::from_str(&fs::read_to_string(&behaviors_path)?)?;
            for mut b in behaviors {
                // Автозаполнение ip_type для старых данных
                if b.ip_type.is_empty() {
                    b.ip_type = if b.ip.contains(':') {
                        "IPv6".to_string()
                    } else {
                        "IPv4".to_string()
                    };
                }
                self.device_behaviors.insert(b.ip.clone(), b);
            }
        }
        Ok(())
    }

    fn save_learning_curve(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let path = format!("{}/learning_curve.json", AI_LOGS_DIR);
        let curve = self.learning_curve.lock().unwrap();
        fs::write(&path, serde_json::to_string_pretty(&*curve)?)?;
        Ok(())
    }

    fn save_intel_logs(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let path = format!(
            "{}/intel_{}.json",
            AI_LOGS_DIR,
            Local::now().format("%Y-%m-%d")
        );
        let logs: Vec<IntelligenceLog> =
            self.intel_logs.iter().map(|e| e.value().clone()).collect();
        fs::write(path, serde_json::to_string_pretty(&logs)?)?;
        Ok(())
    }

    fn collect_sample(&self, ip: String, hour: u32, day: u32, ports: Vec<u16>) {
        let ip_type = if ip.contains(':') { "IPv6" } else { "IPv4" };
        let sample = TrainingSample {
            timestamp: Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            ip: ip.clone(),
            ip_type: ip_type.to_string(),
            hour,
            day_of_week: day,
            open_ports: ports.clone(),
        };
        self.ai_logger.log_event(&format!(
            "Образец {} ({}) : порты {:?} в {}ч",
            ip, ip_type, ports, hour
        ));
        let mut entry = self.training_data.entry(ip).or_default();
        entry.push(sample);
        if entry.len() > MAX_SAMPLES_PER_IP {
            let drain_count = entry.len() - TRIM_TO_SAMPLES;
            entry.drain(0..drain_count);
        }
    }

    fn update_behavior(&self, ip: &str) {
        let samples = match self.training_data.get(ip) {
            Some(s) if s.len() >= MIN_SAMPLES_FOR_BEHAVIOR => s.value().clone(),
            _ => return,
        };

        let mut hours: HashMap<u32, u32> = HashMap::new();
        let mut ports: HashMap<u16, u32> = HashMap::new();
        let mut days: HashSet<u32> = HashSet::new();
        let mut last_ts: Option<chrono::NaiveDateTime> = None;
        let mut intervals: Vec<i64> = Vec::new();

        for sample in &samples {
            *hours.entry(sample.hour).or_insert(0) += 1;
            for &port in &sample.open_ports {
                *ports.entry(port).or_insert(0) += 1;
            }
            days.insert(sample.day_of_week);

            if let Ok(ts) =
                chrono::NaiveDateTime::parse_from_str(&sample.timestamp, "%Y-%m-%d %H:%M:%S%.3f")
            {
                if let Some(prev) = last_ts {
                    let diff = (ts - prev).num_seconds();
                    if diff > 0 {
                        intervals.push(diff);
                    }
                }
                last_ts = Some(ts);
            }
        }

        let threshold = (samples.len() as f32 * SAMPLE_THRESHOLD_RATIO) as u32;

        let typical_hours: Vec<u32> = hours
            .iter()
            .filter(|(_, &c)| c >= threshold)
            .map(|(&h, _)| h)
            .collect();

        let typical_ports: Vec<u16> = ports
            .iter()
            .filter(|(_, &c)| c >= threshold)
            .map(|(&p, _)| p)
            .collect();

        let avg_interval = if !intervals.is_empty() {
            intervals.iter().sum::<i64>() as f64 / intervals.len() as f64 / 60.0
        } else {
            0.0
        };

        self.ai_logger.log_event(&format!(
            "Поведение {}: часы {:?}, порты {:?}, интервал {:.1} мин",
            ip, typical_hours, typical_ports, avg_interval
        ));

        let ip_type = if ip.contains(':') { "IPv6" } else { "IPv4" };
        let behavior = DeviceBehavior {
            ip: ip.to_string(),
            ip_type: ip_type.to_string(),
            typical_hours,
            typical_ports,
            appearance_count: samples.len() as u32,
            first_seen: samples
                .first()
                .map(|s| s.timestamp.clone())
                .unwrap_or_default(),
            last_seen: samples
                .last()
                .map(|s| s.timestamp.clone())
                .unwrap_or_default(),
            unique_days: days.len() as u32,
            avg_interval_minutes: avg_interval,
        };
        self.device_behaviors.insert(ip.to_string(), behavior);
    }

    fn detect_anomaly(&self, ip: &str, hour: u32, ports: &[u16]) -> (bool, Vec<String>, f64) {
        let mut anomalies = Vec::new();
        let mut confidence = 0.0f64;

        let (kayoli_risk, kayoli_matches) = self.kayoli.detect(hour, ports);
        if kayoli_risk > 0 {
            anomalies.extend(kayoli_matches.iter().cloned());
            confidence += kayoli_risk as f64 / RISK_KAYOLI_SCALE;
            self.ai_logger.log_event(&format!(
                "KAYOLI: риск {}%, совпадений {}",
                kayoli_risk,
                kayoli_matches.len()
            ));
        }

        if let Some(behavior) = self.device_behaviors.get(ip) {
            if !behavior.typical_hours.is_empty()
                && !behavior.typical_hours.contains(&hour)
                && behavior.appearance_count > BEHAVIOR_MIN_APPEARANCES
            {
                anomalies.push(format!(
                    "Необычное время: {}ч (обычно {:?}ч)",
                    hour, behavior.typical_hours
                ));
                confidence += RISK_UNUSUAL_TIME;
            }

            if !ports.is_empty() && !behavior.typical_ports.is_empty() {
                let unusual: Vec<u16> = ports
                    .iter()
                    .filter(|p| !behavior.typical_ports.contains(p))
                    .copied()
                    .collect();
                if !unusual.is_empty() {
                    let ratio = unusual.len() as f64 / ports.len() as f64;
                    confidence += (ratio * RISK_UNUSUAL_PORTS_MAX).min(RISK_UNUSUAL_PORTS_MAX);
                    anomalies.push(format!("Необычные порты: {:?}", unusual));
                }
            }

            if behavior.appearance_count < MIN_SAMPLES_FOR_BEHAVIOR as u32 {
                confidence *= RISK_LOW_SAMPLE_PENALTY;
            }
        }

        let is_anomaly = confidence > self.anomaly_threshold;
        if is_anomaly {
            self.ai_logger
                .log_anomaly(ip, (confidence * 100.0) as u8, &anomalies.join(", "));
        }
        (is_anomaly, anomalies, confidence)
    }

    fn analyze_device(&self, ip: &str, scanned_ports: Vec<u16>) -> HackerProfile {
        let now = Local::now();
        let hour = now.hour();
        let ip_type = if ip.contains(':') { "IPv6" } else { "IPv4" };

        let (is_anomaly, anomalies, confidence) = self.detect_anomaly(ip, hour, &scanned_ports);

        let mut risk: u32 = 0;
        let mut activities = Vec::new();

        if is_anomaly {
            risk += (RISK_ANOMALY_SCALE * confidence) as u32;
            activities.extend(anomalies);
        }

        const DANGEROUS_PORTS: [u16; 5] = [22, 23, 445, 3389, 5900];
        if scanned_ports.iter().any(|p| DANGEROUS_PORTS.contains(p)) {
            risk += RISK_DANGEROUS_PORT as u32;
            activities.push("Опасный порт обнаружен".to_string());
        }

        if scanned_ports.len() > MASS_SCAN_THRESHOLD {
            risk += RISK_MASS_SCAN as u32;
            activities.push(format!(
                "Массовое сканирование ({} портов)",
                scanned_ports.len()
            ));
        }

        let risk_score = risk.min(100) as u8;
        let status = match risk_score {
            70..=255 => "investigating",
            40..=69 => "monitoring",
            _ => "low_risk",
        };

        // Сохраняем в Intel лог
        if risk_score >= HIGH_RISK_THRESHOLD {
            self.save_intel_event(
                ip,
                "high_risk",
                &format!("{}% - {}", risk_score, activities.join(", ")),
                risk_score,
                "AI",
            );
        }

        self.ai_logger.log_decision(&format!(
            "Анализ {} ({}) : риск {}%, статус {}, активностей: {}",
            ip,
            ip_type,
            risk_score,
            status,
            activities.len()
        ));

        HackerProfile {
            ip: ip.to_string(),
            ip_type: ip_type.to_string(),
            mac: get_mac_from_ip(ip),
            first_seen: now.format("%Y-%m-%d %H:%M:%S").to_string(),
            last_seen: now.format("%Y-%m-%d %H:%M:%S").to_string(),
            attack_count: 1,
            scanned_ports,
            suspicious_activities: activities,
            risk_score,
            status: status.to_string(),
            warning_count: if risk_score >= HIGH_RISK_THRESHOLD {
                1
            } else {
                0
            },
            recent_events: Vec::new(),
        }
    }

    fn save_intel_event(
        &self,
        ip: &str,
        event_type: &str,
        details: &str,
        risk_level: u8,
        source: &str,
    ) {
        let ip_type = if ip.contains(':') { "IPv6" } else { "IPv4" };
        let log = IntelligenceLog {
            timestamp: Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            ip: ip.to_string(),
            ip_type: ip_type.to_string(),
            event_type: event_type.to_string(),
            details: details.to_string(),
            risk_level,
            source: source.to_string(),
        };
        let id = self.intel_log_counter.fetch_add(1, Ordering::Relaxed);
        self.intel_logs.insert(id, log);
        self.ai_logger.log_event(&format!(
            "INTEL: {} - {} - {} (риск {}%)",
            ip, event_type, details, risk_level
        ));
    }

    fn cleanup_old_data(&self) {
        self.training_data.retain(|_, samples| {
            if samples.is_empty() {
                return false;
            }
            if let Some(last) = samples.last() {
                if let Ok(ts) =
                    chrono::NaiveDateTime::parse_from_str(&last.timestamp, "%Y-%m-%d %H:%M:%S%.3f")
                {
                    let age = Local::now().naive_local() - ts;
                    if age.num_seconds() > MAX_IP_AGE_SECS as i64 {
                        return false;
                    }
                }
            }
            if samples.len() > MAX_SAMPLES_PER_IP {
                let drain_count = samples.len() - TRIM_TO_SAMPLES;
                samples.drain(0..drain_count);
            }
            true
        });

        if self.intel_logs.len() > 10000 {
            let mut ids: Vec<u64> = self.intel_logs.iter().map(|e| *e.key()).collect();
            ids.sort_unstable();
            let to_remove = ids.len() - 10000;
            for id in ids.iter().take(to_remove) {
                self.intel_logs.remove(id);
            }
        }
    }

    fn update_learning_curve(&self) {
        let total: usize = self.training_data.iter().map(|e| e.len()).sum();
        let devices = self.device_behaviors.len();
        let mut ipv4_count = 0;
        let mut ipv6_count = 0;

        for entry in self.device_behaviors.iter() {
            if entry.value().ip_type == "IPv6" {
                ipv6_count += 1;
            } else {
                ipv4_count += 1;
            }
        }

        let point = LearningPoint {
            timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            devices_learned: devices,
            total_samples: total,
            sample_to_device_ratio: if devices > 0 {
                total as f64 / devices as f64
            } else {
                0.0
            },
            ipv4_count,
            ipv6_count,
        };
        if let Ok(mut curve) = self.learning_curve.lock() {
            curve.push(point);
            if curve.len() > 10000 {
                curve.drain(0..1000);
            }
        }
        let _ = self.save_learning_curve();
    }

    fn print_health_status(&self) {
        let total: usize = self.training_data.iter().map(|e| e.len()).sum();
        let mut ipv4_devices = 0;
        let mut ipv6_devices = 0;

        for entry in self.device_behaviors.iter() {
            if entry.value().ip_type == "IPv6" {
                ipv6_devices += 1;
            } else {
                ipv4_devices += 1;
            }
        }

        println!("\n HEALTH STATUS / СОСТОЯНИЕ:");
        println!(
            "   Devices learned/Обучено устройств: {} (IPv4: {}, IPv6: {})",
            self.device_behaviors.len(),
            ipv4_devices,
            ipv6_devices
        );
        println!("   Total samples/Всего образцов:    {}", total);
        println!("   Intel logs/Intel логов:       {}", self.intel_logs.len());
        println!(
            "   Kayoli patterns/Kayoli паттернов:  {}",
            self.kayoli.attack_patterns.len()
        );
    }
}

// ============================================================
//  СКАНИРОВАНИЕ
// ============================================================

async fn scan_port(ip: &str, port: u16, timeout_ms: u64) -> bool {
    let addr = if ip.contains(':') {
        format!("[{}]:{}", ip, port)
    } else {
        format!("{}:{}", ip, port)
    };
    matches!(
        timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await,
        Ok(Ok(_))
    )
}

async fn arp_ping(ip: &str) -> bool {
    let ping_cmd = if ip.contains(':') { "ping6" } else { "ping" };
    let out = tokio::process::Command::new(ping_cmd)
        .args(["-c", "1", "-W", "1", ip])
        .output()
        .await;
    out.map(|o| o.status.success()).unwrap_or(false)
}

async fn smart_scan_host(ip: &str, timeout_ms: u64) -> (bool, Vec<u16>) {
    if !arp_ping(ip).await {
        return (false, vec![]);
    }

    let mut open_ports = Vec::new();
    for &port in &SCAN_PORTS {
        if scan_port(ip, port, timeout_ms).await {
            open_ports.push(port);
        }
    }

    (!open_ports.is_empty(), open_ports)
}

// ============================================================
//  БАН МЕНЕДЖЕР
// ============================================================

struct BanManager {
    banned_ips: DashMap<String, ()>,
    real_ban: bool,
    metrics: Arc<Metrics>,
}

impl BanManager {
    fn new(real_ban: bool, metrics: Arc<Metrics>) -> Self {
        let banned_ips: DashMap<String, ()> = DashMap::new();
        for ip in load_banned_ips() {
            banned_ips.insert(ip, ());
        }
        BanManager {
            banned_ips,
            real_ban,
            metrics,
        }
    }

    async fn try_ban(&self, ip: &str) -> bool {
        if self.banned_ips.contains_key(ip) {
            return false;
        }
        self.banned_ips.insert(ip.to_string(), ());
        self.metrics.inc_bans();

        if self.real_ban {
            println!("ЗАБАНЕН IP: {}", ip);
            let s = ip.to_string();
            let is_v6 = ip.contains(':');
            tokio::task::spawn_blocking(move || {
                if is_v6 {
                    let _ = std::process::Command::new("ip6tables")
                        .args(["-A", "INPUT", "-s", &s, "-j", "DROP"])
                        .output();
                    let _ = std::process::Command::new("ip6tables")
                        .args(["-A", "FORWARD", "-s", &s, "-j", "DROP"])
                        .output();
                } else {
                    for chain in &["INPUT", "FORWARD"] {
                        let _ = std::process::Command::new("iptables")
                            .args(["-A", chain, "-s", &s, "-j", "DROP"])
                            .output();
                    }
                }
            })
            .await
            .ok();
        }
        true
    }
}

// ============================================================
//  БАЗА ДАННЫХ (ОБНОВЛЕННАЯ)
// ============================================================

fn init_database() -> Result<(), Box<dyn Error + Send + Sync>> {
    let conn = Connection::open("rogue.db")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS banned_devices (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ip        TEXT NOT NULL UNIQUE,
            ip_type   TEXT DEFAULT 'IPv4',
            mac       TEXT,
            reason    TEXT,
            banned_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hacker_profiles (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            ip                    TEXT NOT NULL UNIQUE,
            ip_type               TEXT DEFAULT 'IPv4',
            mac                   TEXT,
            first_seen            TEXT NOT NULL,
            last_seen             TEXT NOT NULL,
            attack_count          INTEGER DEFAULT 1,
            scanned_ports         TEXT,
            suspicious_activities TEXT,
            risk_score            INTEGER DEFAULT 0,
            status                TEXT DEFAULT 'monitoring',
            warning_count         INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS intel_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT NOT NULL,
            ip         TEXT NOT NULL,
            ip_type    TEXT DEFAULT 'IPv4',
            event_type TEXT NOT NULL,
            details    TEXT,
            risk_level INTEGER DEFAULT 0,
            source     TEXT DEFAULT 'AI'
        );",
    )?;
    Ok(())
}

fn load_banned_ips() -> Vec<String> {
    if !Path::new("rogue.db").exists() {
        return vec![];
    }
    let Ok(conn) = Connection::open("rogue.db") else {
        return vec![];
    };
    let Ok(mut stmt) = conn.prepare("SELECT ip FROM banned_devices") else {
        return vec![];
    };
    stmt.query_map([], |row| row.get::<_, String>(0))
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
}

fn save_hacker_profile(profile: &HackerProfile) -> Result<(), Box<dyn Error + Send + Sync>> {
    let conn = Connection::open("rogue.db")?;
    conn.execute(
        "INSERT OR REPLACE INTO hacker_profiles
         (ip, ip_type, mac, first_seen, last_seen, attack_count, scanned_ports,
          suspicious_activities, risk_score, status, warning_count)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        rusqlite::params![
            profile.ip,
            profile.ip_type,
            profile.mac.as_deref().unwrap_or("unknown"),
            profile.first_seen,
            profile.last_seen,
            profile.attack_count,
            serde_json::to_string(&profile.scanned_ports).unwrap_or_default(),
            serde_json::to_string(&profile.suspicious_activities).unwrap_or_default(),
            profile.risk_score,
            profile.status,
            profile.warning_count,
        ],
    )?;
    Ok(())
}

fn log_ban_to_db(
    ip: &str,
    mac: Option<&str>,
    reason: &str,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let ip_type = if ip.contains(':') { "IPv6" } else { "IPv4" };
    let conn = Connection::open("rogue.db")?;
    conn.execute(
        "INSERT OR IGNORE INTO banned_devices (ip, ip_type, mac, reason, banned_at) VALUES (?1,?2,?3,?4,?5)",
        rusqlite::params![
            ip,
            ip_type,
            mac.unwrap_or("unknown"),
            reason,
            Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        ],
    )?;
    Ok(())
}

// ============================================================
//  МЕТРИКИ
// ============================================================

struct Metrics {
    total_scans: AtomicU64,
    total_rogue: AtomicU64,
    total_bans: AtomicU64,
    ipv4_scans: AtomicU64,
    ipv6_scans: AtomicU64,
}

impl Metrics {
    fn new() -> Self {
        Metrics {
            total_scans: AtomicU64::new(0),
            total_rogue: AtomicU64::new(0),
            total_bans: AtomicU64::new(0),
            ipv4_scans: AtomicU64::new(0),
            ipv6_scans: AtomicU64::new(0),
        }
    }
    fn inc_scans(&self) {
        self.total_scans.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_rogue(&self) {
        self.total_rogue.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_bans(&self) {
        self.total_bans.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_ipv4(&self) {
        self.ipv4_scans.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_ipv6(&self) {
        self.ipv6_scans.fetch_add(1, Ordering::Relaxed);
    }

    fn print(&self) {
        println!("\n{}", "SESSION STATS / СТАТИСТИКА СЕССИИ:".bright_cyan().bold());
        println!(
            "   Scans/Сканирований:  {} (IPv4: {}, IPv6: {})",
            self.total_scans.load(Ordering::Relaxed),
            self.ipv4_scans.load(Ordering::Relaxed),
            self.ipv6_scans.load(Ordering::Relaxed)
        );
        println!(
            "   Rogue found/Чужих найдено: {}",
            self.total_rogue.load(Ordering::Relaxed)
        );
        println!(
            "   Banned IP/Забанено IP:   {}",
            self.total_bans.load(Ordering::Relaxed)
        );
    }
}

// ============================================================
//  СИСТЕМА КЛЮЧЕЙ
// ============================================================

// ============================================================
//  СИСТЕМА КЛЮЧЕЙ
// ============================================================

mod key_system {
    use super::*;
    use chrono::DateTime;
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LicenseKey {
        pub key: String,
        pub created_at: String,
        pub expires_at: String,
        pub max_devices: u32,
        pub features: Vec<String>,
        pub owner: String,
        pub devices: Vec<String>,
        pub active: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct KeySystemStats {
        pub total_keys: usize,
        pub active_keys: usize,
        pub expired_keys: usize,
        pub total_devices: u32,
        pub max_devices: u32,
    }

    pub struct KeySystem {
        keys: HashMap<String, LicenseKey>,
        keys_file: String,
    }

    impl KeySystem {
        pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let keys_file = "keys.json".to_string();
            let keys = if Path::new(&keys_file).exists() {
                let content = fs::read_to_string(&keys_file)?;
                serde_json::from_str(&content)?
            } else {
                HashMap::new()
            };
            Ok(KeySystem { keys, keys_file })
        }

        pub fn generate_key(
            &mut self,
            days: u32,
            max_devices: u32,
            features: Vec<String>,
            owner: String,
        ) -> Result<String, Box<dyn std::error::Error>> {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros();

            let key = format!(
                "ARLIAN-{}-{}",
                chrono::Local::now().format("%Y%m%d"),
                timestamp % 1000000
            );

            let now = Local::now();
            let expires = now + chrono::Duration::days(days as i64);

            let license = LicenseKey {
                key: key.clone(),
                created_at: now.to_rfc3339(),
                expires_at: expires.to_rfc3339(),
                max_devices,
                features,
                owner,
                devices: Vec::new(),
                active: true,
            };

            self.keys.insert(key.clone(), license);
            self.save()?;
            Ok(key)
        }

        pub fn activate_device(
            &mut self,
            key: &str,
            device_id: &str,
        ) -> Result<bool, Box<dyn std::error::Error>> {
            if let Some(license) = self.keys.get_mut(key) {
                if !license.active {
                    return Ok(false);
                }

                let now = Local::now();
                if let Ok(expires) = DateTime::parse_from_rfc3339(&license.expires_at) {
                    if now > expires.with_timezone(&Local) {
                        license.active = false;
                        self.save()?;
                        return Ok(false);
                    }
                }

                if license.devices.len() >= license.max_devices as usize {
                    return Ok(false);
                }

                if !license.devices.contains(&device_id.to_string()) {
                    license.devices.push(device_id.to_string());
                    self.save()?;
                }
                Ok(true)
            } else {
                Ok(false)
            }
        }

        pub fn get_stats(&self) -> KeySystemStats {
            let now = Local::now();
            let mut total_keys = 0;
            let mut active_keys = 0;
            let mut expired_keys = 0;
            let mut total_devices = 0;
            let mut max_devices = 0;

            for license in self.keys.values() {
                total_keys += 1;
                if license.active {
                    if let Ok(expires) = DateTime::parse_from_rfc3339(&license.expires_at) {
                        if now > expires.with_timezone(&Local) {
                            expired_keys += 1;
                        } else {
                            active_keys += 1;
                            total_devices += license.devices.len() as u32;
                            max_devices += license.max_devices;
                        }
                    }
                }
            }

            KeySystemStats {
                total_keys,
                active_keys,
                expired_keys,
                total_devices,
                max_devices,
            }
        }

        pub fn get_key_count(&self) -> usize {
            self.keys.len()
        }

        fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
            fs::write(&self.keys_file, serde_json::to_string_pretty(&self.keys)?)?;
            Ok(())
        }
    }
}

// ============================================================
//  КОНСОЛЬНЫЙ МЕНЕДЖЕР
// ============================================================

mod console_manager {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum LogLevel {
        Info,
        Warn,
        Error,
        Success,
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum LogTarget {
        Main,
        Monitor,
        KeySystem,
    }

    pub struct ConsoleManager {
        monitor_file: String,
    }

    impl ConsoleManager {
        pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
            fs::create_dir_all("logs/monitor")?;
            fs::create_dir_all("logs/key_system")?;

            Ok(ConsoleManager {
                monitor_file: format!(
                    "logs/monitor/monitor_{}.log",
                    Local::now().format("%Y-%m-%d")
                ),
            })
        }

        pub fn launch_monitor_console(&self) -> Result<(), Box<dyn std::error::Error>> {
            let _ = fs::write(
                &self.monitor_file,
                format!(
                    "=== MONITOR STARTED at {} ===\n",
                    Local::now().format("%Y-%m-%d %H:%M:%S")
                ),
            );
            Ok(())
        }

        pub async fn log(&self, target: LogTarget, level: LogLevel, message: String) {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            let level_str = match level {
                LogLevel::Info => "INFO",
                LogLevel::Warn => "WARN",
                LogLevel::Error => "ERROR",
                LogLevel::Success => "SUCCESS",
            };

            let log_line = format!("[{}] [{}] {}", timestamp, level_str, message);

            let filename = match target {
                LogTarget::Main => "logs/main.log",
                LogTarget::Monitor => &self.monitor_file,
                LogTarget::KeySystem => "logs/key_system/keys.log",
            };

            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(filename)
                .map(|mut f| {
                    let _ = writeln!(&mut f, "{}", log_line);
                });

            match level {
                LogLevel::Info => println!("{}", log_line),
                LogLevel::Warn => println!("{}", log_line.yellow()),
                LogLevel::Error => println!("{}", log_line.red()),
                LogLevel::Success => println!("{}", log_line.green()),
            }
        }

        pub async fn show_status(&self) {
            println!("\n{}", "SYSTEM STATUS / СИСТЕМНЫЙ СТАТУС".bold().bright_yellow());
            println!("  Console/Консоль: Active/Активна");
            println!(
                "  Monitoring/Мониторинг: {}",
                if Path::new(&self.monitor_file).exists() {
                    "Active/Активен"
                } else {
                    "Not running/Не запущен"
                }
            );
            println!("  Logs/Логи: logs/");
            println!("  Time/Время: {}", Local::now().format("%Y-%m-%d %H:%M:%S"));
        }
    }
}

// ============================================================
//  ОСНОВНОЙ ЦИКЛ СКАНИРОВАНИЯ (ОБНОВЛЕННЫЙ)
// ============================================================

async fn scan_network(
    config: &Config,
    whitelist: &Whitelist,
    ban_manager: Arc<BanManager>,
    metrics: Arc<Metrics>,
    ai: Arc<AIDetector>,
    rate_limiter: Arc<RateLimiter>,
    antiflood: Arc<AntiFlood>,
    ddos: Arc<DdosProtector>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    println!(
        "\n{}",
        format!("СКАНИРУЮ: {}", config.network).bright_cyan()
    );
    println!(
        "{}",
        format!("ПРОТОКОЛ: {}", config.ip_protocol.to_uppercase()).bright_cyan()
    );
    let start = Instant::now();
    metrics.inc_scans();

    let ips = parse_cidr(&config.network, config.ipv6_max_hosts)?;
    let total_ips = ips.len();
    println!("   Всего IP в сети: {}", total_ips);

    let wl_ips: HashSet<String> = whitelist.ips.iter().cloned().collect();
    let wl_macs: HashSet<String> = whitelist.macs.iter().cloned().collect();
    let learning_mode = config.ai_learning_mode;
    let timeout_ms = config.scan_timeout_ms;

    let semaphore = Arc::new(Semaphore::new(config.max_concurrent_scans));
    let scan_cache: Arc<DashMap<String, bool>> = Arc::new(DashMap::new());

    let mut tasks = Vec::with_capacity(ips.len());

    for ip_addr in ips {
        let ip_str = ip_addr.to_string();

        // Проверяем протокол
        match config.ip_protocol.as_str() {
            "ipv4" if !ip_addr.is_v4() => continue,
            "ipv6" if !ip_addr.is_v6() => continue,
            _ => {}
        }

        // Rate limiting
        if !rate_limiter.allow_scan(&ip_str) {
            continue;
        }

        let sem = semaphore.clone();
        let cache = scan_cache.clone();
        let wl_ips = wl_ips.clone();
        let wl_macs = wl_macs.clone();
        let ban = ban_manager.clone();
        let ai_ref = ai.clone();
        let metrics_ref = metrics.clone();
        let ip_str_clone = ip_str.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            if let Some(cached) = cache.get(&ip_str_clone) {
                return (
                    ip_str_clone,
                    *cached,
                    vec![],
                    wl_ips,
                    wl_macs,
                    ban,
                    ai_ref,
                    metrics_ref,
                );
            }

            let (alive, ports) = smart_scan_host(&ip_str_clone, timeout_ms).await;
            cache.insert(ip_str_clone.clone(), alive);

            (
                ip_str_clone,
                alive,
                ports,
                wl_ips,
                wl_macs,
                ban,
                ai_ref,
                metrics_ref,
            )
        }));
    }

    let now = Local::now();
    let hour = now.hour();
    let day = now.weekday().num_days_from_monday();
    let mut found = 0u32;
    let mut rogue = 0u32;

    for task in tasks {
        let (ip_str, alive, ports, wl_ips, wl_macs, ban, ai_ref, metrics_ref) = match task.await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{}", format!("Ошибка задачи: {}", e).yellow());
                continue;
            }
        };

        if !alive {
            continue;
        }
        found += 1;

        if ip_str.contains(':') {
            metrics_ref.inc_ipv6();
        } else {
            metrics_ref.inc_ipv4();
        }

        let mac = get_mac_from_ip(&ip_str);

        ai_ref.collect_sample(ip_str.clone(), hour, day, ports.clone());
        ai_ref.update_behavior(&ip_str);

        let is_whitelisted = wl_ips.contains(&ip_str);
        let is_mac_whitelisted = mac.as_ref().map(|m| wl_macs.contains(m)).unwrap_or(false);

        // РЕГИСТРАЦИЯ В АНТИ-ФЛУД: только для чужих устройств с высоким риском,
        // и только 1 запись за скан (НЕ по числу портов), чтобы НЕ банить своих
        if !is_whitelisted && !is_mac_whitelisted && !ports.is_empty() {
            // Регистрируем только самый опасный порт устройства (если есть)
            let highest_risk = ports.iter().copied().max().unwrap_or(0);
            antiflood.register_tcp(&ip_str, highest_risk);
        }

        if is_whitelisted || is_mac_whitelisted {
            println!("{}", format!("   {} — СВОЙ", ip_str).bright_green());
        } else {
            println!("{}", format!("   {} — ЧУЖОЙ!", ip_str).bright_red());
            rogue += 1;
            metrics_ref.inc_rogue();

            let profile = ai_ref.analyze_device(&ip_str, ports);

            if profile.risk_score >= HIGH_RISK_THRESHOLD {
                println!(
                    "{}",
                    format!("   ВЫСОКИЙ РИСК: {}%", profile.risk_score).red()
                );
                for activity in &profile.suspicious_activities {
                    println!("      {}", activity);
                }
            }

            let profile_clone = profile.clone();
            tokio::task::spawn_blocking(move || {
                let _ = save_hacker_profile(&profile_clone);
            });

            if !learning_mode && ban.try_ban(&ip_str).await {
                let ip_str_clone = ip_str.clone();
                let mac_clone = mac.clone();
                tokio::task::spawn_blocking(move || {
                    let _ = log_ban_to_db(&ip_str_clone, mac_clone.as_deref(), "rogue_device");
                });
            } else if learning_mode {
                println!("   [ОБУЧЕНИЕ] Бан не применён");
            }
        }
    }

    ai.cleanup_old_data();
    ai.update_learning_curve();
    rate_limiter.cleanup();
    antiflood.periodic_cleanup().await;
    ddos.periodic_cleanup();

    run_ai_python();

    if let Some(ai_result) = AiResult::load() {
        if ai_result.model_trained {
            println!("\n{}", "[AI] Isolation Forest результаты:".bright_magenta());
            let mut anomalies: Vec<_> = ai_result
                .devices
                .iter()
                .filter(|(_, d)| d.is_anomaly)
                .collect();
            anomalies.sort_by(|a, b| b.1.risk.cmp(&a.1.risk));
            if anomalies.is_empty() {
                println!("   Аномалий не обнаружено");
            } else {
                for (ip, d) in anomalies.iter().take(5) {
                    let ip_type = if ip.contains(':') { "IPv6" } else { "IPv4" };
                    println!("   {} [{}] риск {}%", ip.bright_red(), ip_type, d.risk);
                }
            }
        } else {
            println!(
                "{}",
                format!("[AI] Сбор данных: {}/10 образцов", ai_result.total_samples).yellow()
            );
        }
    }

    println!(
        "\n{} Найдено: {} устройств, Чужих: {}",
        "".bright_cyan(),
        found,
        rogue
    );
    println!("Время: {:.2} сек", start.elapsed().as_secs_f64());
    if learning_mode {
        println!(
            "{}",
            "РЕЖИМ ОБУЧЕНИЯ: бан отключён, данные собираются".yellow()
        );
    }
    ai.print_health_status();
    rate_limiter.print_stats();
    antiflood.print_status();
    Ok(())
}

// ============================================================
//  GRACEFUL SHUTDOWN
// ============================================================

async fn shutdown(ai: Arc<AIDetector>, metrics: Arc<Metrics>) {
    println!("\n{}", "Сохранение состояния AI...".bright_yellow());
    if let Err(e) = ai.save_training_data() {
        eprintln!("Ошибка сохранения training data: {}", e);
    }
    if let Err(e) = ai.save_intel_logs() {
        eprintln!("Ошибка сохранения intel logs: {}", e);
    }
    ai.ai_logger.log_event("Завершение работы ARLIAN PERIMETER");
    metrics.print();
    println!("{}", "Состояние сохранено".bright_green());
}

// ============================================================
//  ИНИЦИАЛИЗАЦИЯ
// ============================================================

fn init_directories() -> Result<(), Box<dyn Error + Send + Sync>> {
    for dir in [
        AI_DIR,
        KAYOLI_DIR,
        TRAINING_DIR,
        AI_LOGS_DIR,
        MODELS_DIR,
        "logs",
        "logs/monitor",
        "logs/key_system",
    ] {
        fs::create_dir_all(dir)?;
    }
    Ok(())
}

fn init_files() -> Result<bool, Box<dyn Error + Send + Sync>> {
    init_directories()?;
    println!("\n{}", "ПРОВЕРКА ФАЙЛОВ...".bright_yellow().bold());

    let is_first_run = !Path::new("config.json").exists();

    if !Path::new("config.json").exists() {
        let default_config = Config::default();
        fs::write(
            "config.json",
            serde_json::to_string_pretty(&default_config)?,
        )?;
        println!("   Создан: config.json");
    }
    if !Path::new("whitelist.json").exists() {
        fs::write(
            "whitelist.json",
            serde_json::to_string_pretty(&Whitelist::default())?,
        )?;
        println!("   Создан: whitelist.json");
    }

    println!("   AI директории готовы");

    if is_first_run {
        println!(
            "\n{}",
            "ПЕРВЫЙ ЗАПУСК! Файлы созданы.".bright_green().bold()
        );
        println!(
            "{}",
            "Kayoli: редактируй .txt в ArlianAI/Kayoli/".bright_yellow()
        );
        println!(
            "{}",
            "IPv6: настрой сети в config.json (enable_ipv6: true)".bright_yellow()
        );
        return Ok(false);
    }
    println!("   Все файлы найдены\n");
    Ok(true)
}

fn load_config() -> Result<Config, Box<dyn Error + Send + Sync>> {
    let content = fs::read_to_string("config.json")?;
    let config: Config = serde_json::from_str(&content)?;
    Ok(config)
}

fn load_whitelist() -> Result<Whitelist, Box<dyn Error + Send + Sync>> {
    let content = fs::read_to_string("whitelist.json")?;
    let whitelist: Whitelist = serde_json::from_str(&content)?;
    Ok(whitelist)
}

// ============================================================
//  MAIN
// ============================================================

#[tokio::main]
async fn main() {
    let sep = "=".repeat(60);
    println!("{}", sep.bright_cyan());
    println!(
        "{}",
        format!("ARLIAN PERIMETER v{}", VERSION).bright_red().bold()
    );
    println!(
        "{}",
        format!("   Built: {}", BUILD_DATE.unwrap_or("dev")).bright_white()
    );
    println!("{}", "   AI-Powered Rogue Device Detector".bright_white());
    println!("{}", "   FULL IPv6 SUPPORT".bright_white());
    println!("{}", sep.bright_cyan());

    #[cfg(unix)]
    if !std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
    {
        eprintln!("\n{}", "Запусти с sudo!".bright_red().bold());
        std::process::exit(1);
    }

    // ============================================================
    // 1. КОНСОЛЬ
    // ============================================================

    let console = match console_manager::ConsoleManager::new() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("Ошибка консольного менеджера: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = console.launch_monitor_console() {
        eprintln!("⚠️ Не удалось запустить мониторинг-консоль: {}", e);
    }

    console
        .log(
            console_manager::LogTarget::Main,
            console_manager::LogLevel::Info,
            "🚀 ARLIAN PERIMETER запущен".to_string(),
        )
        .await;

    // ============================================================
    // 2. СИСТЕМА КЛЮЧЕЙ
    // ============================================================

    let mut key_system = match key_system::KeySystem::new() {
        Ok(ks) => ks,
        Err(e) => {
            console
                .log(
                    console_manager::LogTarget::KeySystem,
                    console_manager::LogLevel::Error,
                    format!("❌ Ошибка системы ключей: {}", e),
                )
                .await;
            // Создаём пустую систему ключей без паники (unwrap)
            let mut ks = match key_system::KeySystem::new() {
                Ok(ks) => ks,
                Err(e2) => {
                    eprintln!("Критическая ошибка системы ключей: {}", e2);
                    std::process::exit(1);
                }
            };
            let _ = ks.generate_key(
                30,
                5,
                vec!["ai".to_string(), "scan".to_string()],
                "Demo".to_string(),
            );
            ks
        }
    };

    if key_system.get_key_count() == 0 {
        console
            .log(
                console_manager::LogTarget::Main,
                console_manager::LogLevel::Warn,
                "⚠️ Нет лицензионных ключей!".to_string(),
            )
            .await;

        let demo_key = key_system
            .generate_key(
                30,
                5,
                vec!["ai".to_string(), "scan".to_string()],
                "Demo User".to_string(),
            )
            .unwrap_or_else(|_| "ERROR".to_string());

        console
            .log(
                console_manager::LogTarget::Main,
                console_manager::LogLevel::Success,
                format!("🔑 Демо-ключ: {}", demo_key),
            )
            .await;
    }

    let stats = key_system.get_stats();
    console
        .log(
            console_manager::LogTarget::Monitor,
            console_manager::LogLevel::Info,
            format!(
                "🔑 Ключи: {} всего, {} активных, {} истекших",
                stats.total_keys, stats.active_keys, stats.expired_keys
            ),
        )
        .await;

    // ============================================================
    // 3. БАЗА ДАННЫХ
    // ============================================================

    if let Err(e) = init_database() {
        eprintln!("Ошибка БД: {}", e);
        std::process::exit(1);
    }

    // ============================================================
    // 4. ФАЙЛЫ
    // ============================================================

    match init_files() {
        Ok(false) => std::process::exit(0),
        Ok(true) => {}
        Err(e) => {
            eprintln!("Ошибка инициализации: {}", e);
            std::process::exit(1);
        }
    }

    // ============================================================
    // 5. КОНФИГИ
    // ============================================================

    let config = load_config().unwrap_or_default();
    let whitelist = load_whitelist().unwrap_or_default();
    let metrics = Arc::new(Metrics::new());
    let ban_manager = Arc::new(BanManager::new(
        config.ban_real && !config.ai_learning_mode,
        metrics.clone(),
    ));

    let ai_logger = match AILogger::new() {
        Ok(l) => Arc::new(l),
        Err(e) => {
            eprintln!("Ошибка логгера: {}", e);
            std::process::exit(1);
        }
    };

    let ai = match AIDetector::new(config.anomaly_threshold, ai_logger) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            eprintln!("Ошибка AI: {}", e);
            std::process::exit(1);
        }
    };

    let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit_ms));

    // Анти-флуд модуль v2.0
    let mut antiflood = AntiFlood::new(
        config.ban_real && !config.ai_learning_mode,
        config.ai_learning_mode,
    );
    antiflood.set_thresholds(
        config.syn_threshold,
        config.ip_threshold,
        config.udp_threshold,
        config.icmp_threshold,
        config.http_threshold,
        config.ssh_threshold,
        config.ddos_min_sources,
        config.ban_duration_secs,
        config.permanent_ban_after,
    );
    antiflood.set_whitelist(&whitelist.ips);
    let antiflood = Arc::new(antiflood);

    // DDoS Protection модуль v1.0 (реальный захват пакетов)
    let mut ddos = DdosProtector::new(
        config.ban_real && !config.ai_learning_mode,
        config.ai_learning_mode,
        antiflood.clone(),
    );
    ddos.set_thresholds(
        config.syn_threshold,
        config.udp_threshold,
        config.icmp_threshold,
        config.http_threshold,
        config.ssh_threshold,
        config.ddos_min_sources,
        config.ban_duration_secs,
        config.permanent_ban_after,
    );
    ddos.set_whitelist(&whitelist.ips);
    let ddos = Arc::new(ddos);
    // Запускаем захват пакетов на всех доступных интерфейсах
    if let Ok(devices) = pcap::Device::list() {
        for device in devices {
            if device.flags.is_up() && !device.flags.is_loopback() {
                if let Err(e) = ddos.start_capture(&device.name) {
                    eprintln!("{}", format!("[DDoS] Не удалось захватить {}: {}", device.name, e).yellow());
                }
            }
        }
    }

    console
        .log(
            console_manager::LogTarget::Main,
            console_manager::LogLevel::Info,
            "💡 Введите 'help' для списка команд".to_string(),
        )
        .await;

    println!("\nНАСТРОЙКИ:");
    println!("   Сеть:           {}", config.network);
    println!("   Протокол:       {}", config.ip_protocol);
    println!(
        "   IPv4:           {}",
        if config.enable_ipv4 {
            "ВКЛ"
        } else {
            "ВЫКЛ"
        }
    );
    println!(
        "   IPv6:           {}",
        if config.enable_ipv6 {
            "ВКЛ"
        } else {
            "ВЫКЛ"
        }
    );
    println!(
        "   Режим AI:       {}",
        if config.ai_learning_mode {
            "ОБУЧЕНИЕ (бан выключен)".yellow()
        } else {
            "АКТИВНЫЙ (бан включён)".green()
        }
    );
    println!("   Порог аномалии: {}", config.anomaly_threshold);

    ai.print_health_status();

    println!("\nМОНИТОРИНГ ЗАПУЩЕН. Ctrl+C для остановки");
    println!("   Логи: ArlianAI/logs/every_event_*.log\n");

    // ============================================================
    // 6. ОСНОВНОЙ ЦИКЛ
    // ============================================================

    let scan_loop = {
        let config = config.clone();
        let whitelist = whitelist.clone();
        let ban_manager = ban_manager.clone();
        let metrics = metrics.clone();
        let ai = ai.clone();
        let rate_limiter = rate_limiter.clone();
        let antiflood = antiflood.clone();
        let ddos = ddos.clone();
        async move {
            loop {
                if let Err(e) = scan_network(
                    &config,
                    &whitelist,
                    ban_manager.clone(),
                    metrics.clone(),
                    ai.clone(),
                    rate_limiter.clone(),
                    antiflood.clone(),
                    ddos.clone(),
                )
                .await
                {
                    eprintln!("{}", format!("Ошибка сканирования: {}", e).bright_red());
                }
                tokio::time::sleep(Duration::from_secs(config.scan_interval)).await;
            }
        }
    };

    // ============================================================
    // 7. КОМАНДНАЯ СТРОКА
    // ============================================================

    let console_clone = console.clone();
    let key_system_clone = Arc::new(Mutex::new(key_system));
    let ai_cmd = ai.clone();
    let metrics_cmd = metrics.clone();
    let antiflood_cmd = antiflood.clone();
    let ddos_cmd = ddos.clone();

    let cmd_loop = tokio::spawn(async move {
        loop {
            print!("{} ", "arlian>".bright_green());
            std::io::stdout().flush().unwrap();

            let mut input = String::new();
            let bytes_read = std::io::stdin().read_line(&mut input).unwrap();
            // EOF (например, stdin закрыт): выходим из цикла, чтобы не крутить горячий цикл
            if bytes_read == 0 {
                break;
            }
            let input = input.trim();
            if input.is_empty() {
                continue;
            }

            match input {
                "help" => {
                    println!("\n{}", "📚 ДОСТУПНЫЕ КОМАНДЫ".bold().bright_yellow());
                    println!("  help           - Показать эту справку");
                    println!("  status         - Показать статус системы");
                    println!("  keys           - Показать информацию о ключах");
                    println!("  genkey <дней>  - Сгенерировать новый ключ");
                    println!("  activate <key> - Активировать ключ");
                    println!("  stats          - Показать статистику сканирования");
                    println!("  flood          - Показать статус anti-flood");
                    println!("  ddos           - Показать статус DDoS Protection");
                    println!("  banned         - Список забаненных IP");
                    println!("  unban <ip>     - Разбанить IP");
                    println!("  quit/exit      - Выйти из программы");
                    println!("");
                }
                "status" => {
                    console_clone.show_status().await;
                    ai_cmd.print_health_status();
                    rate_limiter.print_stats();
                    antiflood_cmd.print_status();
                }
                "stats" => {
                    metrics_cmd.print();
                    rate_limiter.print_stats();
                }
                "keys" => {
                    let ks = key_system_clone.lock().unwrap();
                    let stats = ks.get_stats();
                    println!("\n{}", "🔑 ИНФОРМАЦИЯ О КЛЮЧАХ".bold().bright_yellow());
                    println!("  Всего ключей: {}", stats.total_keys);
                    println!("  Активных: {}", stats.active_keys);
                    println!("  Истекших: {}", stats.expired_keys);
                    println!(
                        "  Устройств: {} из {}",
                        stats.total_devices, stats.max_devices
                    );
                    println!("");
                }
                cmd if cmd.starts_with("genkey") => {
                    let parts: Vec<&str> = cmd.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let days = parts[1].parse::<u32>().unwrap_or(30);
                        // Освобождаем блокировку до await
                        let result: Result<String, String> = {
                            let mut ks = key_system_clone.lock().unwrap();
                            ks.generate_key(
                                days,
                                5,
                                vec!["ai".to_string(), "scan".to_string()],
                                "Generated".to_string(),
                            )
                            .map_err(|e| e.to_string())
                        };
                        match result {
                            Ok(key) => {
                                console_clone
                                    .log(
                                        console_manager::LogTarget::Main,
                                        console_manager::LogLevel::Success,
                                        format!("🔑 Новый ключ: {}", key),
                                    )
                                    .await;
                            }
                            Err(err_msg) => {
                                console_clone
                                    .log(
                                        console_manager::LogTarget::Main,
                                        console_manager::LogLevel::Error,
                                        format!("❌ Ошибка: {}", err_msg),
                                    )
                                    .await;
                            }
                        }
                    }
                }
                cmd if cmd.starts_with("activate") => {
                    let parts: Vec<&str> = cmd.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let key = parts[1].to_string();
                        // Освобождаем блокировку до await
                        let result: Result<bool, String> = {
                            let mut ks = key_system_clone.lock().unwrap();
                            ks.activate_device(&key, "127.0.0.1")
                                .map_err(|e| e.to_string())
                        };
                        match result {
                            Ok(true) => {
                                console_clone
                                    .log(
                                        console_manager::LogTarget::Main,
                                        console_manager::LogLevel::Success,
                                        format!("✅ Ключ {} активирован", key),
                                    )
                                    .await;
                            }
                            Ok(false) => {
                                console_clone
                                    .log(
                                        console_manager::LogTarget::Main,
                                        console_manager::LogLevel::Error,
                                        format!("❌ Не удалось активировать ключ {}", key),
                                    )
                                    .await;
                            }
                            Err(err_msg) => {
                                console_clone
                                    .log(
                                        console_manager::LogTarget::Main,
                                        console_manager::LogLevel::Error,
                                        format!("❌ Ошибка: {}", err_msg),
                                    )
                                    .await;
                            }
                        }
                    }
                }
                "flood" => {
                    antiflood_cmd.print_status();
                }
                "ddos" => {
                    ddos_cmd.print_status();
                }
                "banned" => {
                    let banned = antiflood_cmd.get_banned_ips();
                    println!("\n{}", "🚫 ЗАБАНЕННЫЕ IP".bold().bright_yellow());
                    if banned.is_empty() {
                        println!("  Нет забаненных IP");
                    } else {
                        for ip in &banned {
                            println!("  {}", ip.bright_red());
                        }
                    }
                    println!("");
                }
                cmd if cmd.starts_with("unban") => {
                    let parts: Vec<&str> = cmd.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if antiflood_cmd.unban(parts[1]) {
                            console_clone
                                .log(
                                    console_manager::LogTarget::Main,
                                    console_manager::LogLevel::Success,
                                    format!("✅ IP {} разбанен", parts[1]),
                                )
                                .await;
                        } else {
                            console_clone
                                .log(
                                    console_manager::LogTarget::Main,
                                    console_manager::LogLevel::Warn,
                                    format!("❓ IP {} не найден в списке банов", parts[1]),
                                )
                                .await;
                        }
                    }
                }
                "quit" | "exit" => {
                    console_clone
                        .log(
                            console_manager::LogTarget::Main,
                            console_manager::LogLevel::Info,
                            "👋 Завершение работы...".to_string(),
                        )
                        .await;
                    std::process::exit(0);
                }
                _ => {
                    console_clone
                        .log(
                            console_manager::LogTarget::Main,
                            console_manager::LogLevel::Warn,
                            format!("❓ Неизвестная команда: {}", input),
                        )
                        .await;
                }
            }
        }
    });

    // ============================================================
    // 8. ЗАПУСК
    // ============================================================

    tokio::select! {
        _ = scan_loop => {},
        _ = tokio::signal::ctrl_c() => {
            println!("\n{}", "Остановка...".bright_yellow().bold());
            shutdown(ai.clone(), metrics.clone()).await;
        }
        _ = cmd_loop => {}
    }

    println!("\n{}", "ARLIAN PERIMETER ОСТАНОВЛЕН".bright_green().bold());
}
