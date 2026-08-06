# 🛡️ Arlian Perimeter

**Arlian Perimeter v8.0.0** — network anomaly detection system (IDS/NIDS) with artificial intelligence. Written in Rust with a Python ML module.

> ⚠️ **Disclaimer / Отказ от ответственности:** This project is intended **for educational purposes only** and for use on **your own network** that you are authorized to test. The author is not responsible for any misuse. / Проект предназначен **только для образовательных целей** и для использования в **собственной сети**. Автор не несёт ответственности за неправомерное использование.

---

## ✨ Features / Возможности

- 🔍 **Network scanning** (IPv4/IPv6, subnets, port ranges) / Сканирование сети
- 🤖 **AI module** (`ai.py`) — Isolation Forest + statistical analysis + behavioral rules
- 🧠 **LLM-like explanations** — AI explains each decision in human language (пояснения на естественном языке)
- ⚙️ **Adaptive risk threshold** — levels: normal / low / medium / high / critical
- 💾 **Self-learning knowledge base** — remembers previously found anomalies (самообучающаяся база знаний)
- 📊 **Reports & statistics** — feature importance, trends, training history (отчёты и статистика)
- 🔑 **Key system** — license key based access control (система ключей)
- 📝 **Logging** — journal of all events, AI decisions, and detected anomalies (логирование)

## 🏗️ Architecture / Архитектура

```
┌─────────────────────┐
│   Rust (CORE)       │  Scanning, network, SQLite DB
│   main.rs           │
└─────────┬───────────┘
          │ calls
          ▼
┌─────────────────────┐
│   Python (AI)       │  Isolation Forest + Z-score + rules
│   ai.py             │  LLM-like explanations
└─────────┬───────────┘
          │ writes
          ▼
┌─────────────────────┐
│ ArlianAI/models/    │  ai_result.json, model, stats
└─────────────────────┘
```

## 🚀 Installation / Установка

### Requirements / Требования

- **Rust** (edition 2021) — core build
- **Python 3.8+** — AI module
- **scikit-learn, joblib, numpy** — for full ML (optional; without them AI runs in basic mode / без них AI работает в базовом режиме)

### Build / Сборка

```bash
# Clone repository
git clone https://github.com/USERNAME/arlian-perimeter.git
cd arlian-perimeter

# Build Rust core
cargo build --release

# Install Python dependencies (recommended / рекомендуется)
pip3 install scikit-learn joblib numpy
```

### Run / Запуск

```bash
# Run main logic / Запуск с основной логикой
cargo run

# Or just AI analysis / Или только AI-анализ
python3 ai.py                    # normal analysis / обычный анализ
python3 ai.py --train            # force model training / принудительное обучение
python3 ai.py --analyze          # analyze with existing model / анализ
python3 ai.py --stats            # show stats + knowledge base / статистика
python3 ai.py --features         # show feature importance / важность признаков
python3 ai.py --clean            # clean data older than 7 days / очистка
```

## 🤖 How the AI works / Как работает AI

1. **Collect data** — Rust gathers device info (IP, ports, time) and saves to `ArlianAI/training_data/devices.json`
2. **Train** — Isolation Forest is trained on a feature vector (time, ports, activity frequency, IPv4/IPv6)
3. **Analyze** — an anomaly score is computed per IP and normalized adaptively (most suspicious = 100%)
4. **Explain** — AI generates a textual explanation for each decision and a network-wide summary
5. **Knowledge base** — found anomalies are stored in `learning_curve.json` for future comparison

### `ai_result.json` format / Формат результата

```json
{
  "timestamp": "2026-08-06 16:40:52",
  "total_samples": 133,
  "model_trained": true,
  "analysis": {
    "summary": "Анализ завершён: проверено устройств 5. Обнаружено аномалий: 2...",
    "anomalies_count": 2,
    "risky_ips": ["192.168.1.1", "192.168.1.39"]
  },
  "devices": {
    "192.168.1.1": {
      "is_anomaly": true,
      "risk": 75,
      "severity": "critical",
      "confidence": 0.98,
      "explanation": "Device 192.168.1.1. anomalous activity detected..."
    }
  }
}
```

## 📁 Project structure / Структура проекта

```
├── src/                  # Rust core
│   └── main.rs
├── ArlianAI/
│   ├── models/           # ML models and results
│   ├── training_data/    # training data
│   └── logs/             # AI journals
├── ai.py                 # Python AI module
├── build.rs
├── Cargo.toml
├── config.json
└── LICENSE
```

## 🧩 Configuration / Конфигурация

Main settings in `config.json` — subnets, port ranges, scan intervals. AI training parameters are at the top of `ai.py` (`MIN_SAMPLES_TO_TRAIN`, `RETRAIN_THRESHOLD`, `MAX_SAMPLES_PER_IP`).

## 🤝 Contributing / Вклад

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/awesome`)
3. Commit changes (`git commit -m 'Add awesome feature'`)
4. Push (`git push origin feature/awesome`)
5. Open a Pull Request

## 📄 License / Лицензия

This project is licensed under the **GPL v3** License. See the [LICENSE](LICENSE) file. / Проект распространяется под лицензией **GPL v3**.

---

**⚠️ Legal notice / Правовое уведомление:** Use only on networks you own or are authorized to test. Scanning others' networks without permission is illegal. / Используйте только на сетях, которыми владеете или имеете право тестировать.