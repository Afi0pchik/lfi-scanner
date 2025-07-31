# Advanced LFI Scanner

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)]()

---

## Overview

**Advanced LFI Scanner** — простой и мощный сканер для поиска **Local File Inclusion (LFI)** уязвимостей.  
Поддерживает:

- Подгрузку кастомных payload'ов из файла `payloads_lfi.txt`  
- Генерацию вариаций payload с URL-кодировкой и обходом фильтров  
- Многопоточность для ускорения сканирования  
- Детекцию WAF (Web Application Firewall)  
- Красивый прогресс-бар и вывод результатов в консоль

---

## Features

- Легко использовать с любым файлом payload’ов  
- Настраиваемое количество потоков и таймауты  
- Автоматический анализ ответа на наличие признаков LFI  
- Проверка заголовков и тела ответа на WAF  
- Сохранение результатов в файл

---

## Requirements

- Python 3.6+  
- Modules: `requests`, `rich`

---

## Installation

```bash
git clone <your-repo-url>
cd <repo-directory>
chmod +x setup.sh
./setup.sh

## Usage

source .venv/bin/activate
python scanner.py -u "http://example.com/page.php?file=" -p payloads_lfi.txt -T 20 --timeout 10 -o results.txt

## Donate
