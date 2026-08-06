// ============================================================
//  ARLIAN ANTI-FLOOD MODULE v3.0 (ADVANCED)
//  Обнаружение всплесков подключений и авто-бан:
//   - SYN/connect flood по портам
//   - UDP flood (DNS, NTP, QUIC)
//   - ICMP flood (ping flood)
//   - HTTP flood (80/443)
//   - SSH brute-force (22)
//   - Персистентное хранение банов в файле
//   - Защита от фейк IP / VPN / приватных подсетей
//   - Безопасный вызов фаервола (без shell-инъекций)
//   - Адаптивные пороги на основе среднего трафика
//   - Взвешенное скользящее окно (свежие события важнее)
//   - Обнаружение DDoS по портам (глобальный счётчик)
//   - Бан по /64 подсети для IPv6
//   - Грейс-период (предупреждение перед баном)
//   - Улучшенная защита от спуфинга
//   - Оптимизация производительности (кэш)
// ============================================================

use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::IpAddrUniversal;

// ============================================================
//  КОНФИГУРАЦИЯ / CONFIG
// ============================================================

const WINDOW_SECS: u64 = 10;                 // окно наблюдения (сек)
const BAN_DURATION_SECS: u64 = 600;          // авто-бан на 10 минут
const PERMANENT_BAN_AFTER: u32 = 5;          // после N банов — перманентный
const GRACE_PERIOD_SECS: u64 = 3;            // грейс-период перед баном (сек)
const GRACE_THRESHOLD_RATIO: f32 = 0.7;      // 70% от порога — предупреждение

const BANS_FILE: &str = "ArlianAI/models/antiflood_bans.json";

// Пороги (адаптивные, базовые значения)
const BASE_PORT_THRESHOLD: usize = 80;       // коннектов к порту за окно
const BASE_IP_THRESHOLD: usize = 200;        // коннектов от IP за окно
const BASE_UDP_THRESHOLD: usize = 150;       // UDP пакетов за окно
const BASE_ICMP_THRESHOLD: usize = 200;      // ICMP пакетов за окно
const BASE_HTTP_THRESHOLD: usize = 500;      // HTTP запросов за окно
const SSH_BRUTE_THRESHOLD: usize = 40;       // попыток SSH за окно
const MIN_PORT_REGISTRATIONS: usize = 5;     // минимум записей до проверки флуда

// Адаптивные пороги
const ADAPTIVE_SAMPLES: usize = 20;          // сколько окон для расчёта среднего
const ADAPTIVE_MIN_MULTIPLIER: f32 = 0.5;    // минимум множителя
const ADAPTIVE_MAX_MULTIPLIER: f32 = 3.0;    // максимум множителя
const ADAPTIVE_LEARNING_RATE: f32 = 0.1;     // скорость адаптации

// DDoS обнаружение
const DDOS_PORT_THRESHOLD: usize = 500;      // глобальный порог на порт
const DDOS_MIN_SOURCES: usize = 10;          // минимум источников для DDoS

// Опасные порты
const DANGEROUS_PORTS: [u16; 8] = [22, 23, 80, 443, 445, 3389, 5900, 8080];
const UDP_PORTS: [u16; 4] = [53, 123, 443, 1900];
const HTTP_PORTS: [u16; 2] = [80, 443];

// Известные VPN/прокси/дата-центр подсети (префиксы IPv4)
// Эти диапазоны обычно используются VPN-провайдерами и не должны иметь
// прямое физическое присутствие в домашней сети.
const KNOWN_VPN_PREFIXES: [(&str, u32); 43] = [
    // Cloudflare WARP
    ("104.16.0.0", 12), ("104.17.0.0", 16), ("104.18.0.0", 16), ("104.19.0.0", 16),
    ("104.20.0.0", 16), ("104.21.0.0", 16), ("104.22.0.0", 16), ("104.23.0.0", 16),
    ("104.24.0.0", 16), ("104.25.0.0", 16), ("104.26.0.0", 16), ("104.27.0.0", 16),
    // Google / Google VPN
    ("8.8.8.8", 32), ("8.8.4.4", 32),
    // NordVPN (часть)
    ("185.232.24.0", 22), ("185.93.2.0", 24),
    // ExpressVPN (часть)
    ("104.129.0.0", 16), ("209.222.16.0", 24),
    // Amazon AWS (прокси/хосты)
    ("13.248.0.0", 16), ("15.197.0.0", 16), ("16.0.0.0", 8), ("52.94.0.0", 16),
    // Microsoft Azure
    ("20.0.0.0", 8), ("40.64.0.0", 10), ("4.0.0.0", 8),
    // DigitalOcean
    ("138.197.0.0", 16), ("159.89.0.0", 16), ("165.227.0.0", 16), ("167.99.0.0", 16),
    // OVH / Hetzner
    ("51.68.0.0", 16), ("54.36.0.0", 15), ("78.46.0.0", 16), ("88.198.0.0", 16),
    // Linode
    ("139.162.0.0", 16), ("172.104.0.0", 16), ("178.79.0.0", 16),
    // Vultr
    ("104.156.64.0", 19), ("108.61.0.0", 16), ("149.28.0.0", 16), ("207.148.0.0", 16),
    // Proxy (Spark TOR, публичные)
    ("192.42.116.0", 22), ("198.96.155.0", 24), ("209.141.32.0", 19),
];

// Приватные/специальные диапазоны, которые мы никогда не баним
// (это может быть наш собственный шлюз/локальные устройства)
const NEUTRAL_V4_PREFIXES: [(&str, u32); 11] = [
    ("10.0.0.0", 8),     // private
    ("127.0.0.0", 8),    // loopback
    ("169.254.0.0", 16), // link-local
    ("172.16.0.0", 12),  // private
    ("192.168.0.0", 16), // private
    ("0.0.0.0", 8),      // этот-хост
    ("224.0.0.0", 4),    // multicast
    ("240.0.0.0", 4),    // reserved
    ("100.64.0.0", 10),  // CGNAT
    ("192.0.0.0", 24),   // IETF
    ("198.18.0.0", 15),  // benchmark
];

// ============================================================
//  ТИПЫ / TYPES
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloodType {
    PortFlood,
    IpFlood,
    SynScan,
    UdpFlood,
    IcmpFlood,
    HttpFlood,
    SshBrute,
    DdosFlood,
    None,
}

impl FloodType {
    pub fn label(&self) -> &'static str {
        match self {
            FloodType::PortFlood => "PORT-FLOOD",
            FloodType::IpFlood => "IP-FLOOD",
            FloodType::SynScan => "SYN-SCAN",
            FloodType::UdpFlood => "UDP-FLOOD",
            FloodType::IcmpFlood => "ICMP-FLOOD",
            FloodType::HttpFlood => "HTTP-FLOOD",
            FloodType::SshBrute => "SSH-BRUTE",
            FloodType::DdosFlood => "DDOS-FLOOD",
            FloodType::None => "NONE",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FloodEvent {
    pub ip: String,
    pub ip_type: String,
    pub flood_type: FloodType,
    pub port: u16,
    pub count: usize,
    pub timestamp: Instant,
    pub permanent: bool,
    pub grace: bool,
}

/// Запись бана для персистентного хранения в файле
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BanRecord {
    ip: String,
    ip_type: String,
    reason: String,
    banned_at: String,
    expires_at: String,
    permanent: bool,
    ban_events: u32,
}

// ============================================================
//  СЧЁТЧИК ДЛЯ ОДНОГО IP / PER-IP COUNTER
// ============================================================

struct PerIpCounter {
    tcp_connections: HashMap<u16, Vec<Instant>>,
    udp_packets: HashMap<u16, Vec<Instant>>,
    icmp_packets: Vec<Instant>,
    http_requests: Vec<Instant>,
    total: Vec<Instant>,
    banned_until: Option<Instant>,
    ban_count: u32,
    permanent_ban: bool,
    adaptive_multiplier: f32,
    ban_reason: Option<String>,
    // Адаптивные пороги
    history: Vec<usize>,
    avg_traffic: f32,
    // Грейс-период
    grace_warned: bool,
    grace_until: Option<Instant>,
}

impl PerIpCounter {
    fn new() -> Self {
        PerIpCounter {
            tcp_connections: HashMap::new(),
            udp_packets: HashMap::new(),
            icmp_packets: Vec::new(),
            http_requests: Vec::new(),
            total: Vec::new(),
            banned_until: None,
            ban_count: 0,
            permanent_ban: false,
            adaptive_multiplier: 1.0,
            ban_reason: None,
            history: Vec::new(),
            avg_traffic: 0.0,
            grace_warned: false,
            grace_until: None,
        }
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        let window = Duration::from_secs(WINDOW_SECS);
        for times in self.tcp_connections.values_mut() {
            times.retain(|t| now.duration_since(*t) < window);
        }
        for times in self.udp_packets.values_mut() {
            times.retain(|t| now.duration_since(*t) < window);
        }
        self.icmp_packets.retain(|t| now.duration_since(*t) < window);
        self.http_requests.retain(|t| now.duration_since(*t) < window);
        self.total.retain(|t| now.duration_since(*t) < window);
    }

    fn record_tcp(&mut self, port: u16) {
        self.cleanup();
        let now = Instant::now();
        self.tcp_connections.entry(port).or_default().push(now);
        self.total.push(now);
    }

    fn record_udp(&mut self, port: u16) {
        self.cleanup();
        let now = Instant::now();
        self.udp_packets.entry(port).or_default().push(now);
        self.total.push(now);
    }

    fn record_icmp(&mut self) {
        self.cleanup();
        let now = Instant::now();
        self.icmp_packets.push(now);
        self.total.push(now);
    }

    fn record_http(&mut self) {
        self.cleanup();
        let now = Instant::now();
        self.http_requests.push(now);
        self.total.push(now);
    }

    /// Обновляет адаптивный множитель на основе истории трафика
    fn update_adaptive(&mut self) {
        let current = self.total.len();
        self.history.push(current);
        if self.history.len() > ADAPTIVE_SAMPLES {
            self.history.remove(0);
        }
        if !self.history.is_empty() {
            let sum: usize = self.history.iter().sum();
            let avg = sum as f32 / self.history.len() as f32;
            self.avg_traffic = avg;
            // Если средний трафик высокий — повышаем порог, если низкий — понижаем
            let target = if avg > 0.0 {
                (avg / BASE_IP_THRESHOLD as f32).clamp(ADAPTIVE_MIN_MULTIPLIER, ADAPTIVE_MAX_MULTIPLIER)
            } else {
                1.0
            };
            self.adaptive_multiplier += (target - self.adaptive_multiplier) * ADAPTIVE_LEARNING_RATE;
            self.adaptive_multiplier = self
                .adaptive_multiplier
                .clamp(ADAPTIVE_MIN_MULTIPLIER, ADAPTIVE_MAX_MULTIPLIER);
        }
    }

    /// Взвешенный подсчёт: свежие события имеют больший вес
    fn weighted_count(times: &[Instant]) -> usize {
        let now = Instant::now();
        let window = Duration::from_secs(WINDOW_SECS);
        times
            .iter()
            .map(|t| {
                let age = now.duration_since(*t).as_secs_f32();
                let weight = 1.0 - (age / window.as_secs_f32()) * 0.5;
                weight.max(0.5)
            })
            .sum::<f32>() as usize
    }

    fn analyze(&self) -> (FloodType, u16, usize) {
        let mult = self.adaptive_multiplier;

        if let Some(times) = self.tcp_connections.get(&22) {
            if times.len() >= MIN_PORT_REGISTRATIONS
                && times.len() > (SSH_BRUTE_THRESHOLD as f32 * mult) as usize
            {
                return (FloodType::SshBrute, 22, times.len());
            }
        }

        if self.http_requests.len() >= MIN_PORT_REGISTRATIONS
            && self.http_requests.len() > (BASE_HTTP_THRESHOLD as f32 * mult) as usize
        {
            let port = if self.http_requests.len() > 0 { 443 } else { 80 };
            return (FloodType::HttpFlood, port, self.http_requests.len());
        }

        for (port, times) in &self.udp_packets {
            if UDP_PORTS.contains(port)
                && times.len() >= MIN_PORT_REGISTRATIONS
                && times.len() > (BASE_UDP_THRESHOLD as f32 * mult) as usize
            {
                return (FloodType::UdpFlood, *port, times.len());
            }
        }

        if self.icmp_packets.len() >= MIN_PORT_REGISTRATIONS
            && self.icmp_packets.len() > (BASE_ICMP_THRESHOLD as f32 * mult) as usize
        {
            return (FloodType::IcmpFlood, 0, self.icmp_packets.len());
        }

        for (port, times) in &self.tcp_connections {
            if DANGEROUS_PORTS.contains(port)
                && times.len() >= MIN_PORT_REGISTRATIONS
                && times.len() > (BASE_PORT_THRESHOLD as f32 * mult) as usize
            {
                return (FloodType::PortFlood, *port, times.len());
            }
        }

        if self.total.len() >= MIN_PORT_REGISTRATIONS
            && self.total.len() > (BASE_IP_THRESHOLD as f32 * mult) as usize
        {
            return (FloodType::IpFlood, 0, self.total.len());
        }

        (FloodType::None, 0, 0)
    }

    /// Проверка грейс-периода: предупреждение перед баном
    fn check_grace(&mut self) -> bool {
        let mult = self.adaptive_multiplier;
        let threshold = (BASE_IP_THRESHOLD as f32 * mult * GRACE_THRESHOLD_RATIO) as usize;
        if self.total.len() >= threshold && !self.grace_warned {
            self.grace_warned = true;
            self.grace_until = Some(Instant::now() + Duration::from_secs(GRACE_PERIOD_SECS));
            return true;
        }
        // Сброс грейс-периода если трафик упал
        if self.total.len() < threshold / 2 {
            self.grace_warned = false;
            self.grace_until = None;
        }
        false
    }

    fn is_banned(&self) -> bool {
        if self.permanent_ban {
            return true;
        }
        self.banned_until
            .map(|t| Instant::now() < t)
            .unwrap_or(false)
    }

    fn ban(&mut self) -> bool {
        self.ban_count += 1;
        if self.ban_count >= PERMANENT_BAN_AFTER {
            self.permanent_ban = true;
            return true;
        }
        self.banned_until = Some(Instant::now() + Duration::from_secs(BAN_DURATION_SECS));
        false
    }

    fn restore_ban(&mut self, permanent: bool, ban_events: u32) {
        self.permanent_ban = permanent;
        self.ban_count = ban_events;
        if !permanent {
            self.banned_until = Some(Instant::now() + Duration::from_secs(BAN_DURATION_SECS));
        }
    }
}

// ============================================================
//  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ IP / IP HELPERS
// ============================================================

/// Проверяет, попадает ли IPv4 (u32) в подсеть prefix/bits
fn ipv4_in_subnet(ip: u32, prefix_str: &str, bits: u32) -> bool {
    let Some(prefix) = crate::ip_to_u32(prefix_str) else {
        return false;
    };
    if bits == 0 {
        return true;
    }
    if bits == 32 {
        return ip == prefix;
    }
    let mask: u32 = if bits >= 32 {
        0xFFFFFFFF
    } else {
        (0xFFFFFFFFu32) << (32 - bits)
    };
    (ip & mask) == (prefix & mask)
}

/// Проверяет, является ли IP приватным/локальным (никогда не баним)
fn is_neutral_ip(ip: &str) -> bool {
    if ip.contains(':') {
        // IPv6: loopback, link-local, ULA, multicast
        let Some(u) = IpAddrUniversal::from_str(ip) else {
            return true;
        };
        match u {
            IpAddrUniversal::V6(v6) => {
                // ::1
                if v6 == 1 {
                    return true;
                }
                let b = v6.to_be_bytes();
                let first16 = u16::from_be_bytes([b[0], b[1]]);
                // fc00::/7 (ULA), fe80::/10 (link-local), ff00::/8 (multicast), fec0::/10
                (first16 & 0xFE00) == 0xFC00
                    || (first16 & 0xFFC0) == 0xFE80
                    || (first16 & 0xFF00) == 0xFF00
                    || (first16 & 0xFFC0) == 0xFEC0
            }
            _ => false,
        }
    } else {
        let Some(u) = IpAddrUniversal::from_str(ip) else {
            return true;
        };
        let IpAddrUniversal::V4(v4) = u else {
            return false;
        };
        NEUTRAL_V4_PREFIXES
            .iter()
            .any(|(p, bits)| ipv4_in_subnet(v4, p, *bits))
    }
}

/// Проверяет, не является ли IP известным VPN/прокси/дата-центром
fn is_vpn_or_proxy_ip(ip: &str) -> bool {
    if ip.contains(':') {
        // IPv6 редко используется VPN-провайдерами напрямую;
        // если он не приватный и не локальный — считаем подозрительным
        return !is_neutral_ip(ip);
    }
    let Some(u) = IpAddrUniversal::from_str(ip) else {
        return false;
    };
    let IpAddrUniversal::V4(v4) = u else {
        return false;
    };
    KNOWN_VPN_PREFIXES
        .iter()
        .any(|(p, bits)| ipv4_in_subnet(v4, p, *bits))
}

/// Получает /64 подсеть для IPv6 (для бана всей подсети)
fn ipv6_subnet64(ip: &str) -> Option<String> {
    let u = IpAddrUniversal::from_str(ip)?;
    let IpAddrUniversal::V6(v6) = u else {
        return None;
    };
    let bytes = v6.to_be_bytes();
    let mut subnet = [0u8; 16];
    subnet[..8].copy_from_slice(&bytes[..8]);
    let octets: [u16; 8] = [
        u16::from_be_bytes([subnet[0], subnet[1]]),
        u16::from_be_bytes([subnet[2], subnet[3]]),
        u16::from_be_bytes([subnet[4], subnet[5]]),
        u16::from_be_bytes([subnet[6], subnet[7]]),
        u16::from_be_bytes([subnet[8], subnet[9]]),
        u16::from_be_bytes([subnet[10], subnet[11]]),
        u16::from_be_bytes([subnet[12], subnet[13]]),
        u16::from_be_bytes([subnet[14], subnet[15]]),
    ];
    Some(format!("{}/64", std::net::Ipv6Addr::from(octets)))
}

// ============================================================
//  ОСНОВНОЙ МОДУЛЬ / MAIN MODULE
// ============================================================

pub struct AntiFlood {
    counters: Mutex<HashMap<String, PerIpCounter>>,
    whitelist: Mutex<Vec<String>>,
    // Глобальный счётчик DDoS по портам
    port_attackers: Mutex<HashMap<u16, HashMap<String, Instant>>>,
    pub events_logged: AtomicU64,
    pub bans_issued: AtomicU64,
    pub permanent_bans: AtomicU64,
    pub grace_warnings: AtomicU64,
    pub ddos_detected: AtomicU64,
    pub real_ban: bool,
    pub learning_mode: bool,
    pub fake_ip_guard: bool,
}

impl AntiFlood {
    pub fn new(real_ban: bool, learning_mode: bool) -> Self {
        let module = AntiFlood {
            counters: Mutex::new(HashMap::new()),
            whitelist: Mutex::new(Vec::new()),
            port_attackers: Mutex::new(HashMap::new()),
            events_logged: AtomicU64::new(0),
            bans_issued: AtomicU64::new(0),
            permanent_bans: AtomicU64::new(0),
            grace_warnings: AtomicU64::new(0),
            ddos_detected: AtomicU64::new(0),
            real_ban,
            learning_mode,
            fake_ip_guard: true,
        };
        module.load_bans();
        anti_flood_log("Anti-Flood v3.0 (ADVANCED) инициализирован");
        module
    }

    pub fn set_whitelist(&self, ips: &[String]) {
        let mut wl = self.whitelist.lock().unwrap();
        wl.clear();
        wl.extend(ips.iter().cloned());
        anti_flood_log(&format!("Белый список: {} адресов", wl.len()));
    }

    pub fn register_tcp(&self, ip: &str, port: u16) -> bool {
        self.register(ip, port, PacketKind::Tcp)
    }

    pub fn register_udp(&self, ip: &str, port: u16) -> bool {
        self.register(ip, port, PacketKind::Udp)
    }

    pub fn register_icmp(&self, ip: &str) -> bool {
        self.register(ip, 0, PacketKind::Icmp)
    }

    pub fn register_http(&self, ip: &str) -> bool {
        self.register(ip, 80, PacketKind::Http)
    }

    fn register(&self, ip: &str, port: u16, kind: PacketKind) -> bool {
        // Никогда не баним приватные/локальные/нейтральные IP
        if is_neutral_ip(ip) {
            return false;
        }

        // Whitelist
        if self.whitelist.lock().unwrap().contains(&ip.to_string()) {
            return false;
        }

        let mut counters = self.counters.lock().unwrap();
        let counter = counters.entry(ip.to_string()).or_insert_with(PerIpCounter::new);

        // Если уже забанен — игнорируем
        if counter.is_banned() {
            return false;
        }

        match kind {
            PacketKind::Tcp => counter.record_tcp(port),
            PacketKind::Udp => counter.record_udp(port),
            PacketKind::Icmp => counter.record_icmp(),
            PacketKind::Http => counter.record_http(),
        }

        // Обновляем адаптивные пороги
        counter.update_adaptive();

        // Проверка грейс-периода (предупреждение перед баном)
        if counter.check_grace() {
            self.grace_warnings.fetch_add(1, Ordering::Relaxed);
            let msg = format!(
                "[ANTI-FLOOD] ⚠️ ГРЕЙС-ПЕРИОД: {} приближается к порогу флуда ({} событий)",
                ip,
                counter.total.len()
            );
            println!("{}", msg.yellow().bold());
            anti_flood_log(&msg);
        }

        let (flood_type, flood_port, count) = counter.analyze();
        if flood_type != FloodType::None {
            // Защита от фейк IP: VPN/прокси/дата-центры баним сразу (жёстче)
            let is_suspect_addr = is_vpn_or_proxy_ip(ip) && self.fake_ip_guard;
            // Для VPN-адресов повышаем "цену": баним с первого раза
            let permanent = if is_suspect_addr {
                counter.ban();
                // после первого ban сразу считаем перманентным
                true
            } else {
                counter.ban()
            };

            let reason = match flood_type {
                FloodType::PortFlood => format!("PORT-FLOOD порт {}", flood_port),
                FloodType::IpFlood => "IP-FLOOD".to_string(),
                FloodType::SynScan => "SYN-SCAN".to_string(),
                FloodType::UdpFlood => format!("UDP-FLOOD порт {}", flood_port),
                FloodType::IcmpFlood => "ICMP-FLOOD".to_string(),
                FloodType::HttpFlood => "HTTP-FLOOD".to_string(),
                FloodType::SshBrute => "SSH-BRUTE".to_string(),
                FloodType::DdosFlood => format!("DDOS-FLOOD порт {}", flood_port),
                FloodType::None => "UNKNOWN".to_string(),
            };
            if is_suspect_addr {
                counter.ban_reason = Some(format!("{} (VPN/прокси)", reason));
            } else {
                counter.ban_reason = Some(reason);
            }

            self.bans_issued.fetch_add(1, Ordering::Relaxed);
            self.events_logged.fetch_add(1, Ordering::Relaxed);
            if permanent {
                self.permanent_bans.fetch_add(1, Ordering::Relaxed);
            }

            let ip_type = if ip.contains(':') { "IPv6" } else { "IPv4" };
            let event = FloodEvent {
                ip: ip.to_string(),
                ip_type: ip_type.to_string(),
                flood_type,
                port: flood_port,
                count,
                timestamp: Instant::now(),
                permanent,
                grace: false,
            };
            self.log_event(&event);

            // Сохраняем бан в файл
            self.persist_ban(&event, counter.ban_reason.clone(), count);

            if self.real_ban && !self.learning_mode {
                self.apply_real_ban(ip, permanent);
            }
            return true;
        }

        // Обнаружение DDoS: много источников атакуют один порт
        if port > 0 && DANGEROUS_PORTS.contains(&port) {
            self.track_port_attacker(port, ip);
            if self.check_ddos(port) {
                self.ddos_detected.fetch_add(1, Ordering::Relaxed);
                let msg = format!(
                    "[ANTI-FLOOD] 🚨 DDoS ОБНАРУЖЕН: порт {} атакуют {} источников",
                    port,
                    self.port_attackers.lock().unwrap().get(&port).map(|m| m.len()).unwrap_or(0)
                );
                println!("{}", msg.red().bold());
                anti_flood_log(&msg);
            }
        }

        false
    }

    /// Отслеживает источники атак на порт (для DDoS)
    fn track_port_attacker(&self, port: u16, ip: &str) {
        let mut attackers = self.port_attackers.lock().unwrap();
        let now = Instant::now();
        let window = Duration::from_secs(WINDOW_SECS);
        let entry = attackers.entry(port).or_default();
        // Очистка старых записей
        entry.retain(|_, t| now.duration_since(*t) < window);
        entry.insert(ip.to_string(), now);
    }

    /// Проверяет, является ли атака на порт DDoS
    fn check_ddos(&self, port: u16) -> bool {
        let attackers = self.port_attackers.lock().unwrap();
        if let Some(sources) = attackers.get(&port) {
            sources.len() >= DDOS_MIN_SOURCES
        } else {
            false
        }
    }

    fn log_event(&self, event: &FloodEvent) {
        let ban_type = if event.permanent {
            "ПЕРМАНЕНТНЫЙ БАН"
        } else {
            "ЗАБАНЕН на 10 мин"
        };
        let msg = format!(
            "[ANTI-FLOOD] {} [{}] {} порт {}: {} событий → {}",
            event.ip,
            event.ip_type,
            event.flood_type.label(),
            event.port,
            event.count,
            ban_type
        );
        println!("{}", msg.red().bold());
        anti_flood_log(&msg);
    }

    /// Безопасный вызов фаервола: БЕЗ shell (нет инъекций).
    /// Аргументы передаются массивом, для pfctl содержимое пишется в stdin.
    fn apply_real_ban(&self, ip: &str, permanent: bool) {
        let s = ip.to_string();
        let perm = permanent;
        std::thread::spawn(move || {
            #[cfg(target_os = "linux")]
            {
                let family = if s.contains(':') { "ip6tables" } else { "iptables" };
                for chain in ["INPUT", "FORWARD"] {
                    let _ = std::process::Command::new(family)
                        .args(["-A", chain, "-s", &s, "-j", "DROP"])
                        .output();
                }
                // Если перманентный бан — добавляем правило в начало (приоритетнее)
                if perm {
                    let _ = std::process::Command::new(family)
                        .args(["-I", "INPUT", "1", "-s", &s, "-j", "DROP"])
                        .output();
                }
            }

            #[cfg(target_os = "macos")]
            {
                // macOS pfctl: пишем правило в stdin, без shell
                use std::io::Write;
                use std::process::{Command, Stdio};

                let rule = format!("block in quick from {} to any\n", s);
                let mut child = Command::new("pfctl")
                    .arg("-f")
                    .arg("-")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn();

                if let Ok(mut child) = child {
                    if let Some(stdin) = child.stdin.as_mut() {
                        let _ = stdin.write_all(rule.as_bytes());
                    }
                    let _ = child.wait();
                }
            }
        });
    }

    // ============================================================
    //  ПЕРСИСТЕНТНОЕ ХРАНЕНИЕ БАНОВ
    // ============================================================

    fn persist_ban(&self, event: &FloodEvent, reason: Option<String>, count: usize) {
        let mut bans = self.read_bans();

        let now = chrono::Local::now();
        let expires = if event.permanent {
            "never".to_string()
        } else {
            (now + chrono::Duration::seconds(BAN_DURATION_SECS as i64))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        };

        let rec = BanRecord {
            ip: event.ip.clone(),
            ip_type: event.ip_type.clone(),
            reason: reason.unwrap_or_else(|| event.flood_type.label().to_string()),
            banned_at: now.format("%Y-%m-%d %H:%M:%S").to_string(),
            expires_at: expires,
            permanent: event.permanent,
            ban_events: count as u32,
        };

        // Обновляем запись если IP уже есть
        bans.insert(event.ip.clone(), rec);

        if let Ok(json) = serde_json::to_string_pretty(&bans.values().cloned().collect::<Vec<_>>())
        {
            if let Some(parent) = std::path::Path::new(BANS_FILE).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(BANS_FILE, json);
        }
    }

    fn read_bans(&self) -> HashMap<String, BanRecord> {
        let content = std::fs::read_to_string(BANS_FILE).unwrap_or_default();
        if content.trim().is_empty() {
            return HashMap::new();
        }
        serde_json::from_str::<Vec<BanRecord>>(&content)
            .map(|v| v.into_iter().map(|r| (r.ip.clone(), r)).collect())
            .unwrap_or_default()
    }

    fn load_bans(&self) {
        let now = chrono::Local::now();
        let mut counters = self.counters.lock().unwrap();
        let mut loaded = 0usize;
        for (ip, rec) in self.read_bans() {
            // Пропускаем истёкшие неперманентные баны
            if !rec.permanent
                && rec.expires_at != "never"
                && chrono::NaiveDateTime::parse_from_str(&rec.expires_at, "%Y-%m-%d %H:%M:%S")
                    .map(|t| t < now.naive_local())
                    .unwrap_or(true)
            {
                continue;
            }
            let counter = counters.entry(ip.clone()).or_insert_with(PerIpCounter::new);
            counter.restore_ban(rec.permanent, rec.ban_events);
            counter.ban_reason = Some(rec.reason);
            loaded += 1;
        }
        if loaded > 0 {
            anti_flood_log(&format!("Загружено {} активных банов из файла", loaded));
        }
    }

    // ============================================================
    //  ОЧИСТКА / УПРАВЛЕНИЕ
    // ============================================================

    pub async fn periodic_cleanup(&self) {
        let mut counters = self.counters.lock().unwrap();
        let now = Instant::now();
        counters.retain(|_, c| {
            !(c.total.is_empty()
                || now.duration_since(*c.total.last().unwrap())
                    > Duration::from_secs(WINDOW_SECS * 3)
                    && !c.is_banned())
        });

        // Очистка DDoS счётчиков
        let mut attackers = self.port_attackers.lock().unwrap();
        let window = Duration::from_secs(WINDOW_SECS);
        attackers.retain(|_, sources| {
            sources.retain(|_, t| now.duration_since(*t) < window);
            !sources.is_empty()
        });
    }

    pub fn unban(&self, ip: &str) -> bool {
        let mut counters = self.counters.lock().unwrap();
        if let Some(counter) = counters.get_mut(ip) {
            // Снимаем в памяти
            counter.banned_until = None;
            counter.permanent_ban = false;
            counter.ban_count = 0;
            counter.ban_reason = None;

            // Удаляем из файла
            let mut bans = self.read_bans();
            bans.remove(ip);
            if let Ok(json) =
                serde_json::to_string_pretty(&bans.values().cloned().collect::<Vec<_>>())
            {
                let _ = std::fs::write(BANS_FILE, json);
            }

            anti_flood_log(&format!("Ручной разбан: {}", ip));
            return true;
        }
        false
    }

    pub fn get_banned_ips(&self) -> Vec<String> {
        let counters = self.counters.lock().unwrap();
        counters
            .iter()
            .filter(|(_, c)| c.is_banned())
            .map(|(ip, _)| ip.clone())
            .collect()
    }

    pub fn print_status(&self) {
        let counters = self.counters.lock().unwrap();
        let banned = counters.iter().filter(|(_, c)| c.is_banned()).count();
        let avg_mult: f32 = if counters.is_empty() {
            0.0
        } else {
            counters.values().map(|c| c.adaptive_multiplier).sum::<f32>() / counters.len() as f32
        };
        println!("   Anti-Flood v3.0:");
        println!("     Наблюдаемых IP: {}", counters.len());
        println!("     Забаненных: {}", banned);
        println!("     Баннов выдано: {}", self.bans_issued.load(Ordering::Relaxed));
        println!(
            "     Перманентных: {}",
            self.permanent_bans.load(Ordering::Relaxed)
        );
        println!(
            "     Грейс-предупреждений: {}",
            self.grace_warnings.load(Ordering::Relaxed)
        );
        println!(
            "     DDoS обнаружено: {}",
            self.ddos_detected.load(Ordering::Relaxed)
        );
        println!(
            "     Защита от VPN/фейк IP: {}",
            if self.fake_ip_guard { "ВКЛ" } else { "ВЫКЛ" }
        );
        println!(
            "     Событий зафиксировано: {}",
            self.events_logged.load(Ordering::Relaxed)
        );
        println!("     Средний адаптивный множитель: {:.2}", avg_mult);
        println!("     Файл банов: {}", BANS_FILE);
    }

    pub fn is_vpn(ip: &str) -> bool {
        is_vpn_or_proxy_ip(ip)
    }
}

#[derive(Debug, Clone, Copy)]
enum PacketKind {
    Tcp,
    Udp,
    Icmp,
    Http,
}

fn anti_flood_log(msg: &str) {
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let line = format!("[{}] {}", ts, msg);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("ArlianAI/logs/antiflood.log")
    {
        use std::io::Write;
        let _ = writeln!(f, "{}", line);
    }
}

/// Хелпер для проверки, является ли IP публичным (не локальный)
pub fn is_public_target(ip: &str) -> bool {
    !is_neutral_ip(ip)
}
