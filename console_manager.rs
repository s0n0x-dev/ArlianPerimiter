// src/console_manager.rs

use colored::*;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use chrono::Local;
use tokio::sync::Mutex;
use std::env;

pub struct ConsoleManager {
    log_dir: String,
    main_log: Arc<Mutex<File>>,
    monitor_pid: Mutex<Option<u32>>,
    key_system: KeySystem,
}

impl ConsoleManager {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Создаем директории
        fs::create_dir_all("logs/main")?;
        fs::create_dir_all("logs/monitor")?;
        fs::create_dir_all("logs/keys")?;
        fs::create_dir_all("logs/security")?;
        
        let date = Local::now().format("%Y-%m-%d");
        
        let main_log = Arc::new(Mutex::new(
            File::create(format!("logs/main/arlian_{}.log", date))?
        ));
        
        Ok(ConsoleManager {
            log_dir: "logs".to_string(),
            main_log,
            monitor_pid: Mutex::new(None),
            key_system: KeySystem::new()?,
        })
    }
    
    /// Запуск мониторинг-консоли в отдельном окне
    pub fn launch_monitor_console(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Проверяем ОС
        #[cfg(target_os = "linux")]
        {
            // Создаем скрипт для мониторинга
            let monitor_script = self.create_monitor_script()?;
            
            // Запускаем в новом терминале (gnome-terminal)
            let output = Command::new("gnome-terminal")
                .arg("--")
                .arg("bash")
                .arg("-c")
                .arg(format!("echo '🖥️ ARLIAN MONITOR v1.0' && tail -f {} & exec bash", 
                    self.log_dir.clone() + "/monitor/arlian_monitor.log"))
                .spawn();
            
            match output {
                Ok(child) => {
                    let pid = child.id();
                    let mut monitor_pid = self.monitor_pid.blocking_lock();
                    *monitor_pid = Some(pid);
                    
                    println!("✅ Мониторинг-консоль запущена (PID: {})", pid);
                    println!("📁 Логи: {}/monitor/arlian_monitor.log", self.log_dir);
                    
                    Ok(())
                }
                Err(e) => {
                    // Пробуем xterm как fallback
                    self.launch_xterm()
                }
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            // Для macOS используем Terminal.app
            Command::new("osascript")
                .arg("-e")
                .arg(format!("tell application \"Terminal\" to do script \"tail -f {}/monitor/arlian_monitor.log\"", self.log_dir))
                .spawn()?;
            
            Ok(())
        }
        
        #[cfg(target_os = "windows")]
        {
            // Для Windows используем cmd
            Command::new("cmd")
                .arg("/C")
                .arg("start")
                .arg("cmd")
                .arg("/K")
                .arg(format!("type {}\\monitor\\arlian_monitor.log", self.log_dir.replace('/', "\\")))
                .spawn()?;
            
            Ok(())
        }
    }
    
    /// Fallback для xterm
    #[cfg(target_os = "linux")]
    fn launch_xterm(&self) -> Result<(), Box<dyn std::error::Error>> {
        Command::new("xterm")
            .arg("-e")
            .arg("bash")
            .arg("-c")
            .arg(format!("echo '🖥️ ARLIAN MONITOR' && tail -f {}/monitor/arlian_monitor.log", self.log_dir))
            .spawn()?;
        
        Ok(())
    }
    
    /// Создание скрипта для мониторинга
    fn create_monitor_script(&self) -> Result<String, Box<dyn std::error::Error>> {
        let script_path = "monitor.sh";
        let script = format!(
            r#"#!/bin/bash
# ARLIAN Monitor Script

echo "=========================================="
echo "🖥️  ARLIAN PERIMETER - MONITOR CONSOLE"
echo "=========================================="
echo "📁 Логи: {}/monitor/"
echo "🔑 Система ключей: {}/keys/"
echo "=========================================="
echo ""
echo "Нажмите CTRL+C для выхода"

# Отображаем последние логи
tail -f {}/monitor/arlian_monitor.log
"#,
            self.log_dir, self.log_dir, self.log_dir
        );
        
        fs::write(script_path, script)?;
        
        // Делаем исполняемым
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(script_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(script_path, perms)?;
        }
        
        Ok(script_path.to_string())
    }
    
    /// Логирование с разделением на консоли
    pub async fn log(
        &self,
        target: LogTarget,
        level: LogLevel,
        message: String,
    ) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let log_line = format!("[{}] [{}] {}", 
            timestamp,
            format!("{:?}", level).to_lowercase(),
            message
        );
        
        match target {
            LogTarget::Main => {
                // Основная консоль
                let colored = self.colorize(&log_line, level);
                println!("{}", colored);
                
                // Пишем в основной лог
                if let Ok(mut f) = self.main_log.lock().await {
                    let _ = writeln!(f, "{}", log_line);
                }
            }
            LogTarget::Monitor => {
                // Мониторинг консоль
                let colored = self.colorize(&log_line, level);
                println!("{}", colored);
                
                // Пишем в лог мониторинга
                let monitor_log = format!("{}/monitor/arlian_monitor.log", self.log_dir);
                if let Ok(mut f) = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&monitor_log)
                {
                    let _ = writeln!(f, "{}", log_line);
                }
            }
            LogTarget::KeySystem => {
                // Система ключей отдельно
                let key_log = format!("{}/keys/keys.log", self.log_dir);
                if let Ok(mut f) = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&key_log)
                {
                    let _ = writeln!(f, "{}", log_line);
                }
            }
            LogTarget::Security => {
                // Безопасность отдельно
                let sec_log = format!("{}/security/security.log", self.log_dir);
                if let Ok(mut f) = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&sec_log)
                {
                    let _ = writeln!(f, "{}", log_line);
                }
            }
        }
    }
    
    /// Цветное форматирование
    fn colorize(&self, message: &str, level: LogLevel) -> String {
        match level {
            LogLevel::Error => message.red().to_string(),
            LogLevel::Warn => message.yellow().to_string(),
            LogLevel::Info => message.blue().to_string(),
            LogLevel::Success => message.green().to_string(),
            LogLevel::Debug => message.dimmed().to_string(),
        }
    }
    
    /// Показать статус системы
    pub async fn show_status(&self) {
        let mut status = String::new();
        status.push_str(&format!("\n{}", "=".repeat(50).bright_cyan()));
        status.push_str(&format!("\n{}", "📊 СТАТУС СИСТЕМЫ".bold().bright_yellow()));
        status.push_str(&format!("\n{}", "=".repeat(50).bright_cyan()));
        
        // Логи
        status.push_str(&format!("\n📁 Логи:"));
        for dir in ["main", "monitor", "keys", "security"] {
            let path = format!("{}/{}", self.log_dir, dir);
            if Path::new(&path).exists() {
                if let Ok(entries) = fs::read_dir(&path) {
                    let count = entries.filter_map(|e| e.ok()).count();
                    status.push_str(&format!("\n   {}/: {} файлов", dir, count));
                }
            }
        }
        
        // Система ключей
        status.push_str(&format!("\n🔑 Система ключей:"));
        let key_count = self.key_system.get_key_count();
        status.push_str(&format!("\n   Активных ключей: {}", key_count));
        
        // Память
        status.push_str(&format!("\n💾 Память:"));
        if let Ok(stats) = self.get_memory_stats() {
            status.push_str(&format!("\n   Использовано: {} MB", stats));
        }
        
        status.push_str(&format!("\n{}", "=".repeat(50).bright_cyan()));
        
        println!("{}", status);
    }
    
    fn get_memory_stats(&self) -> Result<u64, Box<dyn std::error::Error>> {
        #[cfg(target_os = "linux")]
        {
            let content = fs::read_to_string("/proc/self/statm")?;
            let parts: Vec<&str> = content.split_whitespace().collect();
            if let Ok(pages) = parts[0].parse::<u64>() {
                let page_size = 4096; // обычно 4KB
                let mb = (pages * page_size) / (1024 * 1024);
                return Ok(mb);
            }
        }
        Ok(0)
    }
}

/// Уровни логирования
#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Success,
    Debug,
}

/// Цели логирования
#[derive(Debug, Clone, Copy)]
pub enum LogTarget {
    Main,      // Основная консоль
    Monitor,   // Мониторинг-консоль
    KeySystem, // Система ключей
    Security,  // Безопасность
}