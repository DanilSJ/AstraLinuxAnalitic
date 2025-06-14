<div align="center">

# 🛡️ AstraLinuxAnalitic

### Система анализа журналов безопасности Astra Linux

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://python.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Latest-336791.svg)](https://postgresql.org)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-ORM-red.svg)](https://sqlalchemy.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

*Мощный инструмент для мониторинга и анализа событий безопасности в операционной системе Astra Linux*

</div>

---

## 📋 Содержание

- [🎯 О проекте](#-о-проекте)
- [✨ Возможности](#-возможности)
- [🔧 Требования](#-требования)
- [🚀 Установка](#-установка)
  - [Python 3.12](#python-312)
  - [PostgreSQL](#postgresql)
  - [Зависимости проекта](#зависимости-проекта)
- [💻 Использование](#-использование)
- [📄 Лицензия](#-лицензия)

---

## 🎯 О проекте

**AstraLinuxAnalitic** — это специализированное решение для анализа и мониторинга журналов безопасности операционной системы Astra Linux. Проект использует современные технологии Python и PostgreSQL для обеспечения эффективного сбора, обработки и анализа событий безопасности.

---

## ✨ Возможности

- 🔍 **Анализ журналов** — Глубокий анализ системных журналов безопасности
- 📊 **Визуализация данных** — Наглядное представление статистики безопасности  
- 🚨 **Мониторинг угроз** — Обнаружение подозрительной активности
- 💾 **Хранение данных** — Надежное хранение в PostgreSQL
- ⚡ **Высокая производительность** — Оптимизированные запросы с SQLAlchemy

---

## 🔧 Требования

| Компонент     | Версия | Описание                            |
|---------------|--------|-------------------------------------|
| **Python**    | 3.12+  | Основной язык программирования      |
| **PostgreSQL**| Latest | СУБД для хранения журналов          |
| **Astra Linux**| Любая | Целевая защищённая ОС               |

---

## 🚀 Установка

### Python 3.12

```bash
sudo apt update
sudo apt install -y wget build-essential libssl-dev zlib1g-dev libbz2-dev \
libreadline-dev libsqlite3-dev curl llvm libncursesw5-dev xz-utils tk-dev \
libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev
cd /tmp
wget https://www.python.org/ftp/python/3.12.3/Python-3.12.3.tgz
tar -xf Python-3.12.3.tgz
cd Python-3.12.3
./configure --enable-optimizations
make -j$(nproc)
sudo make altinstall
sudo python3.12 -m ensurepip --upgrade
sudo python3.12 -m pip install --upgrade pip
```

### PostgreSQL

```bash
sudo apt install -y postgresql postgresql-contrib
sudo systemctl enable postgresql
sudo systemctl start postgresql
```

### Настройка базы данных

```bash
sudo -u postgres psql <<EOF
CREATE DATABASE security_db;
CREATE USER admin WITH ENCRYPTED PASSWORD 'strongpassword';
GRANT ALL PRIVILEGES ON DATABASE security_db TO admin;
EOF
```

### Зависимости проекта

```bash
cd ~/AstralinuxAnalitic
sudo python3.12 -m pip install -r requirements.txt
```

---

## 💻 Использование

```bash
sudo python3.12 main.py
```

---


---

## 📂 Журналы для анализа

| Журнал        | Путь                            | Назначение                                |
|---------------|----------------------------------|-------------------------------------------|
| **audit**     | `/var/log/audit/audit.log`       | Аудит безопасности, системные вызовы      |
| **parsec**    | `/var/log/parsec/parsec.log`     | Журналы SELinux-подобного модуля ParSec   |
| **mandatory** | `/var/log/messages`              | Общесистемные сообщения                   |
| **usb**       | `/var/log/kern.log`              | Действия с USB-устройствами, сообщения ядра |

## 📄 Лицензия

Этот проект лицензирован под лицензией MIT — см. файл [LICENSE](LICENSE) для подробностей.
