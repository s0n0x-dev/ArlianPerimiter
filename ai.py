#!/usr/bin/env python3
# ============================================================
#  ARLIAN AI v3.0 — «LLM-like» ML module for Arlian Perimeter
#  / «LLM-подобный» ML модуль
#  Runs automatically from main.rs after each scan
#  / Запускается автоматически из main.rs после каждого скана
#
#  Улучшения v3.0 (LLM-подобное поведение):
#  - Генерация естественно-языковых объяснений для каждого IP
#  - Ансамбль: Isolation Forest + статистический Z-скор + правила
#  - Временные признаки (вспышки активности, интервалы)
#  - Оценка серьёзности (severity) и уверенности (confidence)
#  - Режим работы БЕЗ sklearn (fallback на чистый numpy) — не падает
#  - Самоподдерживающаяся база знаний (learning_curve.json)
#  - Тренды поведения устройств и предсказание риска
#  - Полная совместимость с форматом ai_result.json для main.rs
# ============================================================

import json
import os
import sys
import argparse
import math
import statistics
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

import numpy as np

# ============================================================
#  ОПЦИОНАЛЬНЫЙ SKLEARN (если нет — работаем на чистом numpy)
# ============================================================
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    print("[AI] sklearn не найден — работаю в базовом (numpy) режиме")

# ============================================================
#  ПУТИ (должны совпадать с main.rs)
# ============================================================

TRAINING_DIR  = "ArlianAI/training_data"
MODELS_DIR    = "ArlianAI/models"
AI_LOGS_DIR   = "ArlianAI/logs"
DEVICES_JSON  = f"{TRAINING_DIR}/devices.json"
BEHAVIORS_JSON = f"{TRAINING_DIR}/behaviors.json"
RESULT_JSON   = f"{MODELS_DIR}/ai_result.json"
MODEL_FILE    = f"{MODELS_DIR}/isolation_forest.joblib"
SCALER_FILE   = f"{MODELS_DIR}/scaler.joblib"
FEATURES_FILE = f"{MODELS_DIR}/feature_importance.json"
STATS_FILE    = f"{MODELS_DIR}/training_stats.json"
LEARNING_FILE = f"{MODELS_DIR}/learning_curve.json"
LOG_FILE      = f"{AI_LOGS_DIR}/ai_python_{datetime.now().strftime('%Y-%m-%d')}.log"

MIN_SAMPLES_TO_TRAIN = 5   # меньше порога, чтобы даже малым объёмом обучать
RETRAIN_THRESHOLD = 30
MAX_SAMPLES_PER_IP = 500

# ============================================================
#  ЛОГГЕР
# ============================================================

def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        os.makedirs(AI_LOGS_DIR, exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass

# ============================================================
#  ВАЛИДАЦИЯ ДАННЫХ
# ============================================================

def validate_sample(sample: dict) -> bool:
    if not isinstance(sample, dict):
        return False
    if "ip" not in sample or not isinstance(sample.get("ip"), str):
        return False
    if "hour" not in sample or not isinstance(sample.get("hour"), (int, float)):
        return False
    if "day_of_week" not in sample or not isinstance(sample.get("day_of_week"), (int, float)):
        return False
    if "open_ports" not in sample or not isinstance(sample.get("open_ports"), list):
        return False
    return True


def load_samples() -> list:
    if not Path(DEVICES_JSON).exists():
        log("Нет файла с образцами — пропускаю")
        return []

    try:
        with open(DEVICES_JSON) as f:
            raw = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        log(f"ОШИБКА чтения {DEVICES_JSON}: {e}")
        return []

    if not isinstance(raw, list):
        log(f"ОШИБКА: {DEVICES_JSON} должен быть списком")
        return []

    # Сортируем по времени, если есть
    valid = [s for s in raw if validate_sample(s)]
    invalid = len(raw) - len(valid)
    if invalid > 0:
        log(f"Пропущено {invalid} некорректных образцов")

    valid.sort(key=lambda s: s.get("timestamp", ""))
    return valid[:MAX_SAMPLES_PER_IP]  # ограничиваем


def load_behaviors() -> dict:
    if not Path(BEHAVIORS_JSON).exists():
        return {}
    try:
        with open(BEHAVIORS_JSON) as f:
            data = json.load(f)
        if isinstance(data, list):
            return {b.get("ip", ""): b for b in data if isinstance(b, dict) and b.get("ip")}
    except (json.JSONDecodeError, OSError) as e:
        log(f"ОШИБКА чтения {BEHAVIORS_JSON}: {e}")
    return {}


def load_learning_curve() -> dict:
    """База знаний — что AI уже узнал ранее"""
    if not Path(LEARNING_FILE).exists():
        return {"islands": {}, "general_insights": {}}
    try:
        with open(LEARNING_FILE) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {"islands": {}, "general_insights": {}}


def save_learning_curve(curve: dict):
    try:
        os.makedirs(MODELS_DIR, exist_ok=True)
        with open(LEARNING_FILE, "w") as f:
            json.dump(curve, f, indent=2, ensure_ascii=False)
    except OSError as e:
        log(f"Не удалось сохранить базу знаний: {e}")

# ============================================================
#  ВЕКТОРИЗАЦИЯ (расширенная)
# ============================================================

ALL_PORTS = [22, 23, 53, 67, 68, 80, 443, 445, 515, 554, 631, 1883, 1900,
             3389, 5228, 5900, 8080, 8883, 9100]

FEATURE_NAMES = (
    ["hour", "day_of_week", "total_ports", "night_flag", "is_ipv6",
     "unique_port_variety", "activity_freq", "interval_hours"]
    + [f"port_{p}" for p in ALL_PORTS]
)


def _parse_ts(ts):
    """Парсим timestamp в datetime или None"""
    if not ts:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def sample_to_vector(sample: dict, ctx: dict = None) -> list:
    """
    Расширенный вектор:
    [hour, day, total_ports, night, ipv6, port_variety, freq, interval] + порты

    ctx — контекст по IP (вспомогательная статистика)
    """
    ports = set(sample.get("open_ports", []))
    hour = int(sample.get("hour", 0))
    day  = int(sample.get("day_of_week", 0))
    ip   = sample.get("ip", "")
    ip_type = sample.get("ip_type", "")

    port_features = [1 if p in ports else 0 for p in ALL_PORTS]
    total_ports   = len(ports)
    night_flag    = 1 if (hour >= 23 or hour <= 6) else 0
    is_ipv6       = 1 if (ip_type == "IPv6" or ":" in ip) else 0

    # Дополнительные признаки
    unique_port_variety = 1.0
    activity_freq = 0.0
    interval_hours = 0.0
    if ctx:
        unique_port_variety = ctx.get("unique_port_variety", max(total_ports, 1)) / 5.0
        total_samples = ctx.get("count", 1)
        span_h = ctx.get("span_hours", 0)
        activity_freq = total_samples / (span_h + 1) if span_h >= 0 else 0.0
        interval_hours = ctx.get("avg_interval_hours", 0.0)

    # Нормализуем частоту (0..1 примерно)
    freq_norm = min(activity_freq, 12.0) / 12.0

    return [hour / 24.0, day / 7.0, min(total_ports, 10) / 10.0,
            night_flag, is_ipv6,
            min(unique_port_variety, 2.0), freq_norm, min(interval_hours, 24.0) / 24.0] + port_features


def build_ip_context(samples_by_ip: dict) -> dict:
    """Строит контекст для каждого IP: вариативность портов, частота, интервалы"""
    ctx = {}
    for ip, lst in samples_by_ip.items():
        ts_list = []
        all_ports = set()
        for s in lst:
            all_ports.update(s.get("open_ports", []))
            t = _parse_ts(s.get("timestamp", ""))
            if t:
                ts_list.append(t)

        count = len(lst)
        span_h = 0.0
        avg_interval = 0.0
        if len(ts_list) >= 2:
            span_h = (max(ts_list) - min(ts_list)).total_seconds() / 3600.0
            diffs = [(ts_list[i+1] - ts_list[i]).total_seconds() / 3600.0
                     for i in range(len(ts_list) - 1)]
            avg_interval = statistics.mean(diffs) if diffs else 0.0

        ctx[ip] = {
            "count": count,
            "unique_port_variety": len(all_ports),
            "all_ports": all_ports,
            "span_hours": span_h,
            "avg_interval_hours": avg_interval,
        }
    return ctx

# ============================================================
#  БАЗОВЫЙ (NON-SKLEARN) АНАЛИЗАТОР — Z-скор по портам
# ============================================================

def basic_zscore_analysis(samples_by_ip: dict, ctx: dict) -> dict:
    """
    Используется когда sklearn недоступен.
    Считает отклонения от «нормы» каждого IP по числу/набору портов.
    """
    base_scores = {}
    for ip, lst in samples_by_ip.items():
        try:
            port_counts = defaultdict(int)
            totals = []
            for s in lst:
                p = len(s.get("open_ports", []))
                totals.append(p)
                for port in s.get("open_ports", []):
                    port_counts[int(port)] += 1

            if not totals:
                continue

            mean = statistics.mean(totals)
            stdev = statistics.stdev(totals) if len(totals) > 1 else 0.0

            # Z-скор последней записи
            last_val = totals[-1]
            z = (last_val - mean) / stdev if stdev > 0 else 0.0

            # Частота появления последнего порта
            last_ports = set(lst[-1].get("open_ports", []))
            rare_ports = []
            for p in last_ports:
                if port_counts.get(int(p), 0) <= max(1, len(lst) // 3):
                    rare_ports.append(int(p))

            anomaly = abs(z) > 2.0 or len(rare_ports) > 2
            base_scores[ip] = {
                "zscore": z,
                "mean": mean,
                "last": last_val,
                "rare_ports": rare_ports,
                "is_anomaly": anomaly,
                "risk": min(100, int(abs(z) * 15 + len(rare_ports) * 10)),
            }
        except Exception as e:
            log(f"ОШИБКА базового анализа {ip}: {e}")

    return base_scores

# ============================================================
#  ОБУЧЕНИЕ (sklearn) С FALLBACK
# ============================================================

def train_model(samples: list):
    if not HAS_SKLEARN:
        log("sklearn недоступен — модель не обучаю, буду использовать Z-скор")
        return None, None, "basic"

    if len(samples) < MIN_SAMPLES_TO_TRAIN:
        log(f"Мало образцов ({len(samples)}) — нужно минимум {MIN_SAMPLES_TO_TRAIN}")
        return None, None, "basic"

    ctx = build_ip_context({s.get("ip", ""): [s] for s in samples})
    X = np.array([sample_to_vector(s, ctx.get(s.get("ip", ""), {})) for s in samples], dtype=float)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        max_samples=min(256, len(samples)),
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)

    try:
        os.makedirs(MODELS_DIR, exist_ok=True)
        joblib.dump(model, MODEL_FILE)
        joblib.dump(scaler, SCALER_FILE)
    except Exception as e:
        log(f"Не удалось сохранить модель: {e}")
        return model, scaler, "ml"

    save_feature_importance_if_possible(model, X_scaled)
    save_training_stats_if_possible(samples, X_scaled)

    log(f"Модель обучена на {len(samples)} образцах")
    return model, scaler, "ml"


def save_feature_importance_if_possible(model, X_scaled):
    """Сохраняет важность признаков (через сравнение средних аномальных/нормальных)"""
    try:
        if hasattr(model, "feature_importances_"):
            importances = model.feature_importances_
        else:
            # Приближённая важность: разница средних аномальных vs нормальных
            preds = model.predict(X_scaled)
            normal = X_scaled[preds == 1]
            anom = X_scaled[preds == -1]
            if len(normal) > 0 and len(anom) > 0:
                importances = np.abs(anom.mean(axis=0) - normal.mean(axis=0))
            else:
                importances = np.ones(X_scaled.shape[1])

        total = importances.sum()
        if total > 0:
            importances = importances / total
        features = sorted(zip(FEATURE_NAMES, importances),
                          key=lambda x: x[1], reverse=True)
        data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "features": [
                {"name": n, "importance": round(float(i), 6)}
                for n, i in features
            ]
        }
        with open(FEATURES_FILE, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        log("Важность признаков сохранена")
    except Exception as e:
        log(f"Не удалось сохранить важность: {e}")


def save_training_stats_if_possible(samples, X_scaled):
    try:
        by_ip = defaultdict(int)
        for s in samples:
            by_ip[s.get("ip", "unknown")] += 1
        ipv4 = sum(1 for s in samples if ":" not in s.get("ip", ""))
        stats = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_samples": len(samples),
            "unique_ips": len(by_ip),
            "ipv4_samples": ipv4,
            "ipv6_samples": len(samples) - ipv4,
            "avg_samples_per_ip": round(len(samples) / len(by_ip), 2) if by_ip else 0,
            "feature_dim": X_scaled.shape[1],
            "top_ips": sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:10],
        }
        with open(STATS_FILE, "w") as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
    except Exception as e:
        log(f"Не удалось сохранить статистику: {e}")


def load_model():
    if not HAS_SKLEARN:
        return None, None
    if Path(MODEL_FILE).exists() and Path(SCALER_FILE).exists():
        try:
            model = joblib.load(MODEL_FILE)
            scaler = joblib.load(SCALER_FILE)
            log("Загружена существующая модель")
            return model, scaler
        except Exception as e:
            log(f"ОШИБКА загрузки модели: {e}")
    return None, None

# ============================================================
#  LLM-ПОДОБНОЕ ОБЪЯСНЕНИЕ / ГЕНЕРАЦИЯ ТЕКСТА
# ============================================================

SEVERITY_LEVELS = ["норма", "низкий", "средний", "высокий", "критический"]


def severity_from_risk(risk: int) -> str:
    if risk < 15:
        return "норма"
    if risk < 30:
        return "низкий"
    if risk < 50:
        return "средний"
    if risk < 75:
        return "высокий"
    return "критический"


def generate_explanation(ip: str, is_anomaly: bool, risk: int, ml_risk: int,
                         behavior_risk: int, behavior_flags: list,
                         rare_ports: list, zscore: float, ctx: dict,
                         severity: str) -> str:
    """Формирует человекочитаемое объяснение решения (как ответ LLM)."""
    parts = [f"Device/Устройство {ip}"]

    if is_anomaly:
        parts.append("anomalous activity detected / обнаружена аномальная активность")
        if ml_risk >= 40:
            parts.append("deviation from network profile / отклонение от типового профиля сети")
        if behavior_risk >= 20 and behavior_flags:
            parts.append("behavioral flags: " + ", ".join(behavior_flags))
        if rare_ports:
            parts.append(f"rare ports: {sorted(rare_ports)}")
        if abs(zscore) > 2:
            parts.append(f"Z-score {zscore:.2f} (out of norm)")
    else:
        parts.append("normal activity / активность в норме")
        if ctx:
            parts.append(f"({ctx['count']} observations, {ctx['unique_port_variety']} unique ports)")

    parts.append(f"risk {risk}% ({severity})")

    return ". ".join(parts) + "."


def build_llm_summary(results: dict) -> dict:
    """Создаёт сводку по всей сети в естественном языке + рекомендации (LLM-подобно)."""
    anomalies = {ip: r for ip, r in results.items() if r["is_anomaly"]}
    total = len(results)
    risky = [ip for ip, r in results.items() if r["risk"] >= 50]
    critical = [ip for ip, r in results.items() if r["risk"] >= 75]

    phrases = []
    phrases.append(f"Analysis complete: {total} device(s) checked. / Анализ завершён: проверено устройств {total}.")
    if anomalies:
        phrases.append(f"Anomalies found: {len(anomalies)}. / Обнаружено аномалий: {len(anomalies)}.")
    else:
        phrases.append("No obvious anomalies detected. / Явных аномалий не обнаружено.")

    if critical:
        phrases.append(f"CRITICAL risk: {', '.join(critical)}. / Критический риск у: {', '.join(critical)}.")
    if risky:
        phrases.append(f"Elevated risk devices: {', '.join(risky)}. / Устройства с повышенным риском: {', '.join(risky)}.")
        top = max(risky, key=lambda ip: results[ip]["risk"])
        phrases.append(f"Highest risk {top} — {results[top]['risk']}%. / Наибольший риск у {top} — {results[top]['risk']}%.")

    # Рекомендации как у LLM
    recommendations = []
    for ip, r in sorted(results.items(), key=lambda x: x[1]["risk"], reverse=True)[:3]:
        if r["is_anomaly"]:
            rec = (f"Investigate {ip} (risk {r['risk']}%): unusual activity pattern. "
                   f"/ Рекомендуется проверить {ip} (риск {r['risk']}%): необычная активность.")
            recommendations.append(rec)
    if not recommendations and risky:
        recommendations.append("Increase monitoring frequency for risky devices. / Увеличьте частоту мониторинга для рискованных устройств.")

    return {
        "summary": " ".join(phrases),
        "anomalies_count": len(anomalies),
        "risky_ips": risky,
        "recommendations": recommendations,
    }

# ============================================================
#  АНАЛИЗ — комбинированный (ML + Z-скор + поведение)
# ============================================================

def analyze(samples: list, model, scaler, behaviors: dict = None,
            mode: str = "ml") -> (dict, dict):
    """
    Возвращает (results, learning_updates)
    results: ip -> {..., explanation, severity, confidence}

    Риск нормализуется адаптивно: самый подозрительный IP = 100,
    IP в пределах нормы = низкий риск.
    """
    results = {}
    learning = {"general_insights": {}, "islands": {}}

    by_ip = defaultdict(list)
    for s in samples:
        by_ip[s.get("ip", "unknown")].append(s)

    ctx = build_ip_context(by_ip)
    z_scores = basic_zscore_analysis(by_ip, ctx)

    # ===== ПРОХОД 1: собираем ML-скор всех IP =====
    ip_scores = {}
    for ip, ip_samples in by_ip.items():
        ip_ctx = ctx.get(ip, {})
        avg_score = 0.0
        z_obj = z_scores.get(ip, {})
        if mode == "ml" and model is not None and scaler is not None:
            try:
                vectors = np.array([sample_to_vector(s, ip_ctx) for s in ip_samples], dtype=float)
                v_scaled = scaler.transform(vectors)
                scores = model.score_samples(v_scaled)
                avg_score = float(np.mean(scores))
            except Exception as e:
                log(f"ОШИБКА ML-скоринга {ip}: {e}")
        else:
            avg_score = -float(z_obj.get("zscore", 0.0)) * 0.1

        ip_scores[ip] = {
            "avg_score": avg_score,
            "z_obj": z_obj,
            "ip_ctx": ip_ctx,
            "ip_samples": ip_samples,
        }

    # Адаптивная нормализация риска по диапазону скоров
    if ip_scores:
        scores_vals = [v["avg_score"] for v in ip_scores.values()]
        min_s, max_s = min(scores_vals), max(scores_vals)
        spread = max_s - min_s
        # median как «норма»
        med = float(np.median(scores_vals)) if len(scores_vals) > 1 else min_s
    else:
        min_s = max_s = med = 0.0
        spread = 1.0

    # ===== ПРОХОД 2: итоговый риск и объяснения =====
    for ip, info in ip_scores.items():
        try:
            ip_ctx = info["ip_ctx"]
            ip_samples = info["ip_samples"]
            z_obj = info["z_obj"]
            avg_score = info["avg_score"]

            # ML-риск: ниже скор (относительно медианы) → выше риск, адаптивно
            if spread > 1e-6:
                # расстояние от «нормы» (медианы) вниз, нормированное на диапазон
                deviation = (med - avg_score) / spread
                ml_risk = int(max(0, min(100, deviation * 100)))
            else:
                ml_risk = 0

            risk = ml_risk
            ml_score = avg_score

            # ===== Поведенческие правила =====
            behavior_risk = 0
            behavior_flags = []
            last_sample = ip_samples[-1]
            current_ports = set(last_sample.get("open_ports", []))
            hour = int(last_sample.get("hour", 0))

            if behaviors and ip in behaviors:
                behavior = behaviors[ip]
                typical_ports = set(behavior.get("typical_ports", []))
                new_ports = current_ports - typical_ports
                if new_ports:
                    behavior_risk += min(20, len(new_ports) * 5)
                    behavior_flags.append(f"новые порты: {sorted(new_ports)}")

                typical_hours = set(behavior.get("typical_hours", []))
                if typical_hours and hour not in typical_hours and (hour >= 23 or hour <= 6):
                    behavior_risk += 15
                    behavior_flags.append("ночная активность")

            risk += behavior_risk

            # ===== Статистический Z-скор =====
            if z_obj:
                zscore = z_obj.get("zscore", 0.0)
                rare_ports = z_obj.get("rare_ports", [])
                if abs(zscore) > 2.0:
                    risk += min(15, int(abs(zscore) * 5))
                    behavior_flags.append(f"резкое изменение профиля (Z={zscore:.1f})")
                if len(rare_ports) > 2:
                    risk += min(15, len(rare_ports) * 4)
            else:
                zscore = 0.0
                rare_ports = []

            risk = max(0, min(100, risk))
            is_anomaly = risk >= 30

            # ===== LLM-подобный вывод =====
            severity = severity_from_risk(risk)
            confidence = min(0.98, 0.55 + abs(ml_risk - behavior_risk) / 100.0)
            explanation = generate_explanation(
                ip, is_anomaly, risk, ml_risk, behavior_risk,
                behavior_flags, rare_ports, zscore, ip_ctx, severity
            )

            # ===== Обновление базы знаний =====
            if is_anomaly and ip_ctx:
                learning["islands"][ip] = {
                    "first_seen": ip_samples[0].get("timestamp", ""),
                    "last_seen": last_sample.get("timestamp", ""),
                    "count": ip_ctx["count"],
                    "top_ports": sorted(ip_ctx["all_ports"])[:8],
                    "why": explanation,
                    "risk": risk,
                }

            results[ip] = {
                "anomaly_score": round(ml_score, 4),
                "min_score": round(ml_score, 4),
                "is_anomaly": is_anomaly,
                "risk": risk,
                "ml_risk": ml_risk,
                "behavior_risk": behavior_risk,
                "behavior_flags": behavior_flags,
                "samples_count": len(ip_samples),
                "last_seen": last_sample.get("timestamp", ""),
                "ip_type": "IPv6" if ":" in ip else "IPv4",
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": explanation,
            }

            status = "⚠ ANOMALY/АНОМАЛИЯ" if is_anomaly else "✓ NORMAL/норма"
            log(f"{ip}: risk={risk}% [{status}] {explanation}")

        except Exception as e:
            log(f"ОШИБКА анализа {ip}: {e}")
            results[ip] = {
                "anomaly_score": 0.0, "min_score": 0.0, "is_anomaly": False,
                "risk": 0, "ml_risk": 0, "behavior_risk": 0,
                "behavior_flags": [], "samples_count": len(ip_samples),
                "last_seen": ip_samples[-1].get("timestamp", ""),
                "ip_type": "IPv6" if ":" in ip else "IPv4",
                "severity": "норма", "confidence": 0.0,
                "explanation": f"Не удалось проанализировать {ip}.",
            }

    return results, learning


# ============================================================
#  ЗАПИСЬ РЕЗУЛЬТАТА (с LLM-сводкой)
# ============================================================

def write_result(results: dict, total_samples: int, model_trained: bool,
                 llm_summary: dict):
    output = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_samples": total_samples,
        "model_trained": model_trained,
        "analysis": llm_summary,
        "devices": results,
    }
    os.makedirs(MODELS_DIR, exist_ok=True)
    with open(RESULT_JSON, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    log(f"Результат записан в {RESULT_JSON}")

# ============================================================
#  CLI-КОМАНДЫ
# ============================================================

def cmd_train(args):
    log("=" * 50)
    log("ARLIAN AI v3.0 — принудительное обучение")
    samples = load_samples()
    if not samples:
        log("Нет данных для обучения")
        return 1
    model, scaler, mode = train_model(samples)
    if model is None and mode == "ml":
        log("Обучение не выполнено (sklearn недоступен)")
        return 1
    log(f"Обучение завершено: {len(samples)} образцов")
    return 0


def cmd_analyze(args):
    log("=" * 50)
    log("ARLIAN AI v3.0 — анализ")

    samples = load_samples()
    if not samples:
        write_result({}, 0, False, {"summary": "Нет данных для анализа.", "anomalies_count": 0, "risky_ips": []})
        return 0

    model, scaler = load_model()
    mode = "ml" if model is not None else "basic"

    if model is None and HAS_SKLEARN:
        log("Модель не найдена — обучаю...")
        model, scaler, mode = train_model(samples)

    behaviors = load_behaviors()
    results, learning = analyze(samples, model, scaler, behaviors, mode)

    # Обновляем базу знаний
    curve = load_learning_curve()
    curve["islands"].update(learning["islands"])
    save_learning_curve(curve)

    llm_summary = build_llm_summary(results)

    anomalies = [ip for ip, r in results.items() if r["is_anomaly"]]
    log(f"Проанализировано: {len(results)} IP, аномалий: {len(anomalies)}")
    log(f"[LLM] {llm_summary['summary']}")

    write_result(results, len(samples), model is not None, llm_summary)
    return 0


def cmd_stats(args):
    log("=" * 50)
    log("ARLIAN AI v3.0 — статистика")

    if Path(STATS_FILE).exists():
        with open(STATS_FILE) as f:
            stats = json.load(f)
        print("\n📊 СТАТИСТИКА ОБУЧЕНИЯ:")
        print(f"   Время: {stats.get('timestamp', '?')}")
        print(f"   Образцов: {stats.get('total_samples', 0)}")
        print(f"   Уникальных IP: {stats.get('unique_ips', 0)}")
        print(f"   IPv4: {stats.get('ipv4_samples', 0)}, IPv6: {stats.get('ipv6_samples', 0)}")
        print(f"   Среднее образцов на IP: {stats.get('avg_samples_per_ip', 0)}")
        print(f"   Размерность признаков: {stats.get('feature_dim', 0)}")
        top = stats.get('top_ips', [])
        if top:
            print("   Топ IP:")
            for ip, count in top[:5]:
                print(f"     {ip}: {count} образцов")
    else:
        print("Статистика ещё не сохранена")

    if Path(FEATURES_FILE).exists():
        with open(FEATURES_FILE) as f:
            feat = json.load(f)
        print("\n🔍 ВАЖНОСТЬ ПРИЗНАКОВ (топ-10):")
        for item in feat.get("features", [])[:10]:
            name = item["name"]
            imp = item["importance"] * 100
            bar = "█" * int(imp / 2)
            print(f"   {name:20s} {imp:5.1f}% {bar}")
    else:
        print("\nВажность признаков ещё не сохранена")

    # База знаний
    if Path(LEARNING_FILE).exists():
        with open(LEARNING_FILE) as f:
            curve = json.load(f)
        islands = curve.get("islands", {})
        if islands:
            print(f"\n🧠 БАЗА ЗНАНИЙ: {len(islands)} известных аномалий")
            for ip, info in list(islands.items())[:5]:
                print(f"   {ip}: риск {info.get('risk', 0)}% — {info.get('why', '')[:80]}")

    return 0


def cmd_features(args):
    log("=" * 50)
    log("ARLIAN AI v3.0 — важность признаков")

    if not Path(FEATURES_FILE).exists():
        print("Файл важности признаков не найден. Обучите модель: python3 ai.py --train")
        return 1

    with open(FEATURES_FILE) as f:
        data = json.load(f)

    print(f"\n🔍 ВАЖНОСТЬ ПРИЗНАКОВ ({data.get('timestamp', '?')}):")
    for i, item in enumerate(data.get("features", []), 1):
        name = item["name"]
        imp = item["importance"] * 100
        bar = "█" * int(imp / 2)
        print(f"  {i:2d}. {name:20s} {imp:5.1f}% {bar}")

    return 0


def cmd_ask(args):
    """LLM-подобный интерактивный режим: отвечает на вопросы по данным/базе знаний."""
    log("=" * 50)
    log("ARLIAN AI v3.0 — LLM-диалог (вопрос-ответ)")

    results = {}
    samples = load_samples()
    if samples:
        model, scaler = load_model()
        mode = "ml" if model is not None else "basic"
        behaviors = load_behaviors()
        results, _ = analyze(samples, model, scaler, behaviors, mode)

    curve = load_learning_curve()
    ask_summary = build_llm_summary(results)

    print("\n" + "=" * 60)
    print("🧠 ARLIAN LLM-ДИАЛОГ (напишите вопрос, 'exit' — выход)")
    print("Доступно: device <IP>, anomalies, summary, help")
    print("=" * 60)
    while True:
        try:
            q = input("\nyou> ").strip().lower()
        except EOFError:
            break
        if q in ("exit", "quit", "выход"):
            break

        if q == "help":
            print("  summary      — общая сводка по сети")
            print("  anomalies    — список аномалий с объяснением")
            print("  device <IP>  — детали по конкретному IP")
            print("  risks        — самые рискованные устройства")
        elif q == "summary":
            print(f"AI> {ask_summary['summary']}")
            for rec in ask_summary.get("recommendations", []):
                print(f"   💡 {rec}")
        elif q == "anomalies":
            if results:
                for ip, r in sorted(results.items(), key=lambda x: x[1]["risk"], reverse=True):
                    if r["is_anomaly"]:
                        print(f"AI> {r['explanation']}")
            else:
                print("AI> Аномалий не обнаружено. / No anomalies.")
        elif q == "risks":
            for ip, r in sorted(results.items(), key=lambda x: x[1]["risk"], reverse=True)[:5]:
                print(f"AI> {ip}: risk {r['risk']}% ({r['severity']})")
        elif q.startswith("device "):
            target = q[7:].strip()
            if target in results:
                r = results[target]
                print(f"AI> {r['explanation']}")
                print(f"   samples: {r['samples_count']}, last: {r['last_seen']}")
            elif target in curve.get("islands", {}):
                print(f"AI> {curve['islands'][target]}")
            else:
                print(f"AI> Нет данных по {target}. / No data for {target}.")
        else:
            # Примитивный «понимающий» ответ: ищем ключевые слова
            found = []
            if "аномали" in q or "anomal" in q:
                found = [ip for ip, r in results.items() if r["is_anomaly"]]
                ans = (f"Найдено аномалий: {len(found)}. " +
                       ", ".join(found[:10])) if found else "Аномалий нет."
            elif "риск" in q or "risk" in q:
                found = sorted(results.items(), key=lambda x: x[1]["risk"], reverse=True)
                ans = "Топ риска: " + ", ".join(f"{ip} ({r['risk']}%)" for ip, r in found[:5]) if found else "Нет данных."
            elif "сколько" in q or "how many" in q:
                ans = f"Устройств: {len(results)}, образцов: {len(samples)}."
            else:
                ans = "Извините, не понял вопрос. Введите 'help' для команд."
            print(f"AI> {ans}")
    return 0


def cmd_clean(args):
    log("=" * 50)
    log("ARLIAN AI v3.0 — очистка старых данных")

    if not Path(DEVICES_JSON).exists():
        print("Нет файла с образцами")
        return 0

    with open(DEVICES_JSON) as f:
        samples = json.load(f)

    cutoff = datetime.now() - timedelta(days=7)
    kept = []
    removed = 0
    for s in samples:
        try:
            ts = _parse_ts(s.get("timestamp", ""))
            if ts is None or ts >= cutoff:
                kept.append(s)
            else:
                removed += 1
        except Exception:
            kept.append(s)

    with open(DEVICES_JSON, "w") as f:
        json.dump(kept, f, indent=2, ensure_ascii=False)

    log(f"Удалено старых образцов: {removed}, осталось: {len(kept)}")
    return 0

# ============================================================
#  MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="ARLIAN AI v3.0 — LLM-подобный ML модуль для Arlian Perimeter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python3 ai.py                    # обычный запуск (автоматически из main.rs)
  python3 ai.py --train            # принудительное обучение
  python3 ai.py --analyze          # анализ с существующей моделью
  python3 ai.py --stats            # показать статистику + базу знаний
  python3 ai.py --features         # показать важность признаков
  python3 ai.py --clean            # очистить данные старше 7 дней
"""
    )
    parser.add_argument("--train", action="store_true", help="принудительное обучение модели")
    parser.add_argument("--analyze", action="store_true", help="анализ с существующей моделью")
    parser.add_argument("--stats", action="store_true", help="показать статистику обучения")
    parser.add_argument("--features", action="store_true", help="показать важность признаков")
    parser.add_argument("--clean", action="store_true", help="очистить данные старше 7 дней")
    parser.add_argument("--ask", action="store_true", help="LLM-диалог: вопрос-ответ по данным")
    parser.add_argument("--verbose", action="store_true", help="подробный вывод")
    args = parser.parse_args()

    if args.train:
        sys.exit(cmd_train(args))
    if args.analyze:
        sys.exit(cmd_analyze(args))
    if args.stats:
        sys.exit(cmd_stats(args))
    if args.features:
        sys.exit(cmd_features(args))
    if args.clean:
        sys.exit(cmd_clean(args))
    if args.ask:
        sys.exit(cmd_ask(args))

    # ============================================================
    #  ОБЫЧНЫЙ ЗАПУСК (из main.rs)
    # ============================================================

    log("=" * 50)
    log("ARLIAN AI v3.0 запущен")

    samples = load_samples()
    if not samples:
        write_result({}, 0, False, {"summary": "Нет данных для анализа.", "anomalies_count": 0, "risky_ips": []})
        return

    log(f"Загружено образцов: {len(samples)}")

    model, scaler = load_model()
    mode = "ml" if model is not None else "basic"

    should_train = model is None and HAS_SKLEARN

    if not should_train and Path(STATS_FILE).exists():
        try:
            with open(STATS_FILE) as f:
                stats = json.load(f)
            prev_count = stats.get("total_samples", 0)
            if len(samples) - prev_count >= RETRAIN_THRESHOLD:
                should_train = True
                log(f"Новых образцов: {len(samples) - prev_count} >= {RETRAIN_THRESHOLD} — переобучаю")
        except (json.JSONDecodeError, OSError):
            pass

    if should_train:
        log("Обучаю модель...")
        model, scaler, mode = train_model(samples)

    behaviors = load_behaviors()
    results, learning = analyze(samples, model, scaler, behaviors, mode)

    # Обновляем базу знаний
    curve = load_learning_curve()
    curve["islands"].update(learning["islands"])
    save_learning_curve(curve)

    llm_summary = build_llm_summary(results)

    anomalies = [ip for ip, r in results.items() if r["is_anomaly"]]
    log(f"Проанализировано: {len(results)} IP, аномалий: {len(anomalies)}")
    log(f"[LLM] {llm_summary['summary']}")
    if anomalies:
        log(f"Аномальные IP: {', '.join(anomalies)}")

    write_result(results, len(samples), model is not None, llm_summary)
    log("ARLIAN AI завершён")


if __name__ == "__main__":
    main()