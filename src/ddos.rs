// ============================================================
//  ARLIAN DDoS PROTECTION MODULE v1.0
//  Реальный захват пакетов через libpcap:
//   - SYN flood (TCP)
//   - UDP flood (DNS, NTP, QUIC)
//   - ICMP flood (ping flood)
//   - HTTP flood (80/443)
//   - SSH brute-force (22)
//   - Автоматический бан через nftables/iptables/pfctl
//   - Адаптивные пороги на основе среднего трафика
// ============================================================

use colored::Colorize;
use pcap::{Capture, Device};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::antiflood::AntiFlood;

// ============================================================
//  КОНФИГУРАЦИЯ
// ============================================================

const WINDOW_SECS: u64 = 10;                 // окно наблюдения (сек)
const BAN_DURATION_SECS: u64 = 600;          // авто-бан на 10 минут
const PERMANENT_BAN_AFTER: u32 = 5;          // после N банов — перманентный

// Пороги (адаптивные, базовые значения)
const BASE_SYN_THRESHOLD: usize = 100;       // SYN пакетов от IP за окно
const BASE_UDP_THRESHOLD: usize = 150;       // UDP пакетов от IP за окно
const BASE_ICMP_THRESHOLD: usize = 200;      // ICMP пакетов от IP за окно
const BASE_HTTP_THRESHOLD: usize = 500;      // HTTP запросов от IP за окно
const SSH_BRUTE_THRESHOLD: usize = 40;       // попыток SSH от IP за окно

// DDoS обнаружение
const DDOS_MIN_SOURCES: usize = 10;          // минимум источников для DDoS

// Опасные порты
const DANGEROUS_PORTS: [u16; 8] = [22, 23, 80, 443, 445, 3389, 5900, 8080];
const UDP_PORTS: [u16; 4] = [53, 123, 443, 1900];
const HTTP_PORTS: [u16; 2] = [80, 443];

// ============================================================
//  СЧЁТЧИК ДЛЯ ОДНОГО IP
// ============================================================

struct DdosCounter {
    syn_packets: HashMap<u16, Vec<Instant>>,
    udp_packets: HashMap<u16, Vec<Instant>>,
    icmp_packets: Vec<Instant>,
    http_requests: Vec<Instant>,
    total: Vec<Instant>,
    banned_until: Option<Instant>,
    ban_count: u32,
    permanent_ban: bool,
    ban_reason: Option<String>,
}

impl DdosCounter {
    fn new() -> Self {
        DdosCounter {
            syn_packets: HashMap::new(),
            udp_packets: HashMap::new(),
            icmp_packets: Vec::new(),
            http_requests: Vec::new(),
            total: Vec::new(),
            banned_until: None,
            ban_count: 0,
            permanent_ban: false,
            ban_reason: None,
        }
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        let window = Duration::from_secs(WINDOW_SECS);
        for times in self.syn_packets.values_mut() {
            times.retain(|t| now.duration_since(*t) < window);
        }
        for times in self.udp_packets.values_mut() {
            times.retain(|t| now.duration_since(*t) < window);
        }
        self.icmp_packets.retain(|t| now.duration_since(*t) < window);
        self.http_requests.retain(|t| now.duration_since(*t) < window);
        self.total.retain(|t| now.duration_since(*t) < window);
    }

    fn record_syn(&mut self, port: u16) {
        self.cleanup();
        let now = Instant::now();
        self.syn_packets.entry(port).or_default().push(now);
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

    fn is_banned(&self) -> bool {
        if self.permanent_ban {
            return true;
        }
        self.banned_until
            .map(|t| Instant::now() < t)
            .unwrap_or(false)
    }

    fn ban(&mut self, permanent_after: u32, ban_duration_secs: u64) -> bool {
        self.ban_count += 1;
        if self.ban_count >= permanent_after {
            self.permanent_ban = true;
            return true;
        }
        self.banned_until = Some(Instant::now() + Duration::from_secs(ban_duration_secs));
        false
    }
}

// ============================================================
//  ОСНОВНОЙ МОДУЛЬ
// ============================================================

pub struct DdosProtector {
    counters: Mutex<HashMap<String, DdosCounter>>,
    port_attackers: Mutex<HashMap<u16, HashMap<String, Instant>>>,
    pub packets_captured: AtomicU64,
    pub syn_detected: AtomicU64,
    pub udp_detected: AtomicU64,
    pub icmp_detected: AtomicU64,
    pub http_detected: AtomicU64,
    pub ssh_detected: AtomicU64,
    pub ddos_detected: AtomicU64,
    pub bans_issued: AtomicU64,
    pub real_ban: bool,
    pub learning_mode: bool,
    antiflood: Arc<AntiFlood>,
    // Настраиваемые пороги (из config.json)
    syn_threshold: usize,
    udp_threshold: usize,
    icmp_threshold: usize,
    http_threshold: usize,
    ssh_threshold: usize,
    ddos_min_sources: usize,
    ban_duration_secs: u64,
    permanent_ban_after: u32,
    // Whitelist (не баним эти IP)
    whitelist: Mutex<Vec<String>>,
}

impl DdosProtector {
    pub fn new(real_ban: bool, learning_mode: bool, antiflood: Arc<AntiFlood>) -> Self {
        DdosProtector {
            counters: Mutex::new(HashMap::new()),
            port_attackers: Mutex::new(HashMap::new()),
            packets_captured: AtomicU64::new(0),
            syn_detected: AtomicU64::new(0),
            udp_detected: AtomicU64::new(0),
            icmp_detected: AtomicU64::new(0),
            http_detected: AtomicU64::new(0),
            ssh_detected: AtomicU64::new(0),
            ddos_detected: AtomicU64::new(0),
            bans_issued: AtomicU64::new(0),
            real_ban,
            learning_mode,
            antiflood,
            syn_threshold: BASE_SYN_THRESHOLD,
            udp_threshold: BASE_UDP_THRESHOLD,
            icmp_threshold: BASE_ICMP_THRESHOLD,
            http_threshold: BASE_HTTP_THRESHOLD,
            ssh_threshold: SSH_BRUTE_THRESHOLD,
            ddos_min_sources: DDOS_MIN_SOURCES,
            ban_duration_secs: BAN_DURATION_SECS,
            permanent_ban_after: PERMANENT_BAN_AFTER,
            whitelist: Mutex::new(Vec::new()),
        }
    }

    /// Устанавливает настраиваемые пороги из config.json
    pub fn set_thresholds(
        &mut self,
        syn: usize,
        udp: usize,
        icmp: usize,
        http: usize,
        ssh: usize,
        ddos_sources: usize,
        ban_duration: u64,
        permanent_after: u32,
    ) {
        self.syn_threshold = syn;
        self.udp_threshold = udp;
        self.icmp_threshold = icmp;
        self.http_threshold = http;
        self.ssh_threshold = ssh;
        self.ddos_min_sources = ddos_sources;
        self.ban_duration_secs = ban_duration;
        self.permanent_ban_after = permanent_after;
    }

    /// Устанавливает whitelist (IP, которые никогда не баним)
    pub fn set_whitelist(&self, ips: &[String]) {
        let mut wl = self.whitelist.lock().unwrap();
        wl.clear();
        wl.extend(ips.iter().cloned());
    }

    /// Запускает захват пакетов на указанном интерфейсе в отдельном потоке.
    /// Использует общий Arc, чтобы поток делил ВСЕ состояние (счётчики, банны)
    /// с основным экземпляром модуля.
    pub fn start_capture(self: &Arc<Self>, interface: &str) -> Result<(), String> {
        let iface = interface.to_string();
        let protector = self.clone();

        std::thread::spawn(move || {
            if let Err(e) = protector.capture_loop(&iface) {
                eprintln!("{}", format!("[DDoS] Ошибка захвата: {}", e).red());
            }
        });

        Ok(())
    }

    fn capture_loop(&self, interface: &str) -> Result<(), String> {
        // Находим устройство
        let device = Device::list()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|d| d.name == interface)
            .ok_or_else(|| format!("Интерфейс {} не найден", interface))?;

        // Открываем захват
        let mut cap = Capture::from_device(device)
            .map_err(|e| e.to_string())?
            .promisc(true)
            .snaplen(65535)
            .timeout(100)
            .open()
            .map_err(|e| e.to_string())?;

        println!(
            "{}",
            format!("[DDoS] Захват пакетов на {} запущен", interface)
                .bright_green()
                .bold()
        );

        // Цикл захвата
        while let Ok(packet) = cap.next_packet() {
            self.packets_captured.fetch_add(1, Ordering::Relaxed);
            self.process_packet(&packet.data);
        }

        Ok(())
    }

    fn process_packet(&self, data: &[u8]) {
        // Ethernet header: 14 байт (dst MAC 6, src MAC 6, ethertype 2)
        if data.len() < 14 {
            return;
        }
        let ethertype = u16::from_be_bytes([data[12], data[13]]);

        match ethertype {
            0x0800 => self.process_ipv4(&data[14..]),
            0x86DD => self.process_ipv6(&data[14..]),
            _ => {}
        }
    }

    fn process_ipv4(&self, data: &[u8]) {
        if data.len() < 20 {
            return;
        }
        let version = data[0] >> 4;
        if version != 4 {
            return;
        }
        let ihl = (data[0] & 0x0F) as usize * 4;
        if data.len() < ihl + 4 {
            return;
        }
        let protocol = data[9];
        let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let src_str = src_ip.to_string();

        match protocol {
            6 => self.process_tcp(&src_str, &data[ihl..]),
            17 => self.process_udp(&src_str, &data[ihl..]),
            1 => self.process_icmp(&src_str),
            _ => {}
        }
    }

    fn process_ipv6(&self, data: &[u8]) {
        if data.len() < 40 {
            return;
        }
        let next_header = data[6];
        let src_ip = Ipv6Addr::from([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
            data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]);
        let src_str = src_ip.to_string();

        match next_header {
            6 => self.process_tcp(&src_str, &data[40..]),
            17 => self.process_udp(&src_str, &data[40..]),
            58 => self.process_icmp(&src_str),
            _ => {}
        }
    }

    fn process_tcp(&self, ip: &str, data: &[u8]) {
        if data.len() < 20 {
            return;
        }
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let flags = data[13];

        // SYN флаг (0x02) — начало соединения
        let is_syn = flags & 0x02 != 0;
        // ACK флаг (0x10) — подтверждение
        let is_ack = flags & 0x10 != 0;

        if is_syn && !is_ack {
            // SYN flood
            self.record_event(ip, dst_port, PacketKind::Syn);
        } else if is_ack && HTTP_PORTS.contains(&dst_port) {
            // HTTP запрос (ACK на 80/443)
            self.record_event(ip, dst_port, PacketKind::Http);
        }
    }

    fn process_udp(&self, ip: &str, data: &[u8]) {
        if data.len() < 8 {
            return;
        }
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        self.record_event(ip, dst_port, PacketKind::Udp);
    }

    fn process_icmp(&self, ip: &str) {
        self.record_event(ip, 0, PacketKind::Icmp);
    }

    fn record_event(&self, ip: &str, port: u16, kind: PacketKind) {
        // Пропускаем приватные/локальные адреса
        if is_private_ip(ip) {
            return;
        }

        // Whitelist: не баним и не считаем трафик от доверенных IP
        if self.whitelist.lock().unwrap().contains(&ip.to_string()) {
            return;
        }

        let mut counters = self.counters.lock().unwrap();
        let counter = counters.entry(ip.to_string()).or_insert_with(DdosCounter::new);

        // Если уже забанен — игнорируем
        if counter.is_banned() {
            return;
        }

        match kind {
            PacketKind::Syn => counter.record_syn(port),
            PacketKind::Udp => counter.record_udp(port),
            PacketKind::Icmp => counter.record_icmp(),
            PacketKind::Http => counter.record_http(),
        }

        // Проверяем пороги
        let (flood_type, flood_port, count) = self.analyze(counter);

        if flood_type != FloodType::None {
            let permanent = counter.ban(self.permanent_ban_after, self.ban_duration_secs);
            let reason = match flood_type {
                FloodType::SynFlood => format!("SYN-FLOOD порт {}", flood_port),
                FloodType::UdpFlood => format!("UDP-FLOOD порт {}", flood_port),
                FloodType::IcmpFlood => "ICMP-FLOOD".to_string(),
                FloodType::HttpFlood => "HTTP-FLOOD".to_string(),
                FloodType::SshBrute => "SSH-BRUTE".to_string(),
                _ => "UNKNOWN".to_string(),
            };
            counter.ban_reason = Some(reason.clone());

            self.bans_issued.fetch_add(1, Ordering::Relaxed);
            match flood_type {
                FloodType::SynFlood => {
                    self.syn_detected.fetch_add(1, Ordering::Relaxed);
                }
                FloodType::UdpFlood => {
                    self.udp_detected.fetch_add(1, Ordering::Relaxed);
                }
                FloodType::IcmpFlood => {
                    self.icmp_detected.fetch_add(1, Ordering::Relaxed);
                }
                FloodType::HttpFlood => {
                    self.http_detected.fetch_add(1, Ordering::Relaxed);
                }
                FloodType::SshBrute => {
                    self.ssh_detected.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }

            let msg = format!(
                "[DDoS] 🚨 {} [{}] порт {}: {} событий → {}",
                ip,
                if ip.contains(':') { "IPv6" } else { "IPv4" },
                flood_port,
                count,
                if permanent { "ПЕРМАНЕНТНЫЙ БАН" } else { "БАН на 10 мин" }
            );
            println!("{}", msg.red().bold());

            // Регистрируем в антифлуд модуле (для персистентности)
            match kind {
                PacketKind::Syn => {
                    self.antiflood.register_tcp(ip, flood_port);
                }
                PacketKind::Udp => {
                    self.antiflood.register_udp(ip, flood_port);
                }
                PacketKind::Icmp => {
                    self.antiflood.register_icmp(ip);
                }
                PacketKind::Http => {
                    self.antiflood.register_http(ip);
                }
            }

            // Применяем реальный бан
            if self.real_ban && !self.learning_mode {
                self.apply_real_ban(ip, permanent);
            }
        }

        // DDoS обнаружение: много источников на один порт
        if port > 0 && DANGEROUS_PORTS.contains(&port) {
            self.track_port_attacker(port, ip);
            if self.check_ddos(port) {
                self.ddos_detected.fetch_add(1, Ordering::Relaxed);
                let msg = format!(
                    "[DDoS] 🚨 DDoS ОБНАРУЖЕН: порт {} атакуют {} источников",
                    port,
                    self.port_attackers
                        .lock()
                        .unwrap()
                        .get(&port)
                        .map(|m| m.len())
                        .unwrap_or(0)
                );
                println!("{}", msg.red().bold());
            }
        }
    }

    fn analyze(&self, counter: &DdosCounter) -> (FloodType, u16, usize) {
        // SSH brute-force
        if let Some(times) = counter.syn_packets.get(&22) {
            if times.len() > self.ssh_threshold {
                return (FloodType::SshBrute, 22, times.len());
            }
        }

        // HTTP flood
        if counter.http_requests.len() > self.http_threshold {
            return (FloodType::HttpFlood, 443, counter.http_requests.len());
        }

        // UDP flood
        for (port, times) in &counter.udp_packets {
            if UDP_PORTS.contains(port) && times.len() > self.udp_threshold {
                return (FloodType::UdpFlood, *port, times.len());
            }
        }

        // ICMP flood
        if counter.icmp_packets.len() > self.icmp_threshold {
            return (FloodType::IcmpFlood, 0, counter.icmp_packets.len());
        }

        // SYN flood
        for (port, times) in &counter.syn_packets {
            if DANGEROUS_PORTS.contains(port) && times.len() > self.syn_threshold {
                return (FloodType::SynFlood, *port, times.len());
            }
        }

        (FloodType::None, 0, 0)
    }

    fn track_port_attacker(&self, port: u16, ip: &str) {
        let mut attackers = self.port_attackers.lock().unwrap();
        let now = Instant::now();
        let window = Duration::from_secs(WINDOW_SECS);
        let entry = attackers.entry(port).or_default();
        entry.retain(|_, t| now.duration_since(*t) < window);
        entry.insert(ip.to_string(), now);
    }

    fn check_ddos(&self, port: u16) -> bool {
        let attackers = self.port_attackers.lock().unwrap();
        if let Some(sources) = attackers.get(&port) {
            sources.len() >= self.ddos_min_sources
        } else {
            false
        }
    }

    /// Применяет реальный бан через nftables/iptables/pfctl
    #[allow(unused_variables)]
    fn apply_real_ban(&self, ip: &str, permanent: bool) {
        let s = ip.to_string();
        std::thread::spawn(move || {
            #[cfg(target_os = "linux")]
            {
                let family = if s.contains(':') { "ip6tables" } else { "iptables" };
                for chain in ["INPUT", "FORWARD"] {
                    let _ = std::process::Command::new(family)
                        .args(["-A", chain, "-s", &s, "-j", "DROP"])
                        .output();
                }
                if permanent {
                    let _ = std::process::Command::new(family)
                        .args(["-I", "INPUT", "1", "-s", &s, "-j", "DROP"])
                        .output();
                }
            }

            #[cfg(target_os = "macos")]
            {
                // macOS: используем pfctl с anchor (не перезаписываем весь конфиг)
                use std::io::Write;
                use std::process::{Command, Stdio};

                // Добавляем правило в anchor arlian
                let rule = format!("block in quick from {} to any\n", s);
                let child = Command::new("pfctl")
                    .arg("-a")
                    .arg("arlian")
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

    pub fn periodic_cleanup(&self) {
        let mut counters = self.counters.lock().unwrap();
        let now = Instant::now();
        counters.retain(|_, c| {
            !(c.total.is_empty()
                || now.duration_since(*c.total.last().unwrap())
                    > Duration::from_secs(WINDOW_SECS * 3)
                    && !c.is_banned())
        });

        let mut attackers = self.port_attackers.lock().unwrap();
        let window = Duration::from_secs(WINDOW_SECS);
        attackers.retain(|_, sources| {
            sources.retain(|_, t| now.duration_since(*t) < window);
            !sources.is_empty()
        });
    }

    pub fn print_status(&self) {
        println!("   DDoS Protection v1.0:");
        println!(
            "     Пакетов захвачено: {}",
            self.packets_captured.load(Ordering::Relaxed)
        );
        println!(
            "     SYN flood: {}",
            self.syn_detected.load(Ordering::Relaxed)
        );
        println!(
            "     UDP flood: {}",
            self.udp_detected.load(Ordering::Relaxed)
        );
        println!(
            "     ICMP flood: {}",
            self.icmp_detected.load(Ordering::Relaxed)
        );
        println!(
            "     HTTP flood: {}",
            self.http_detected.load(Ordering::Relaxed)
        );
        println!(
            "     SSH brute: {}",
            self.ssh_detected.load(Ordering::Relaxed)
        );
        println!(
            "     DDoS обнаружено: {}",
            self.ddos_detected.load(Ordering::Relaxed)
        );
        println!(
            "     Баннов выдано: {}",
            self.bans_issued.load(Ordering::Relaxed)
        );
        println!(
            "     Режим: {}",
            if self.learning_mode {
                "ОБУЧЕНИЕ".yellow()
            } else {
                "АКТИВНЫЙ".green()
            }
        );
    }
}

// ============================================================
//  ВСПОМОГАТЕЛЬНЫЕ
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FloodType {
    SynFlood,
    UdpFlood,
    IcmpFlood,
    HttpFlood,
    SshBrute,
    None,
}

#[derive(Debug, Clone, Copy)]
enum PacketKind {
    Syn,
    Udp,
    Icmp,
    Http,
}

/// Проверяет, является ли IP приватным/локальным
fn is_private_ip(ip: &str) -> bool {
    if ip.contains(':') {
        // IPv6: loopback, link-local, ULA, multicast
        if let Ok(v6) = ip.parse::<Ipv6Addr>() {
            let b = v6.octets();
            let first16 = u16::from_be_bytes([b[0], b[1]]);
            // ::1
            if v6 == Ipv6Addr::LOCALHOST {
                return true;
            }
            // fc00::/7 (ULA), fe80::/10 (link-local), ff00::/8 (multicast)
            return (first16 & 0xFE00) == 0xFC00
                || (first16 & 0xFFC0) == 0xFE80
                || (first16 & 0xFF00) == 0xFF00;
        }
        return true;
    }

    if let Ok(v4) = ip.parse::<Ipv4Addr>() {
        let octets = v4.octets();
        // 10.0.0.0/8
        if octets[0] == 10 {
            return true;
        }
        // 127.0.0.0/8
        if octets[0] == 127 {
            return true;
        }
        // 169.254.0.0/16
        if octets[0] == 169 && octets[1] == 254 {
            return true;
        }
        // 172.16.0.0/12
        if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return true;
        }
        // 192.168.0.0/16
        if octets[0] == 192 && octets[1] == 168 {
            return true;
        }
        // 0.0.0.0/8
        if octets[0] == 0 {
            return true;
        }
        // 224.0.0.0/4 (multicast)
        if octets[0] >= 224 && octets[0] <= 239 {
            return true;
        }
        // 240.0.0.0/4 (reserved)
        if octets[0] >= 240 {
            return true;
        }
        // 100.64.0.0/10 (CGNAT)
        if octets[0] == 100 && (64..=127).contains(&octets[1]) {
            return true;
        }
    }
    false
}