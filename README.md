<div align="center">

# ⃤ P O R T S C O P E ⃤

### *Scan and watch network ports on any host - one command.*

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![OS](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Stars](https://img.shields.io/github/stars/MrHacker-X/portscope?style=flat-square&color=orange)
![Forks](https://img.shields.io/github/forks/MrHacker-X/portscope?style=flat-square&color=cyan)

</div>

---

## 📋 Table of Contents

- [🎯 Why PortScope?](#-why-portscope)
- [🧭 What It Does](#-what-it-does)
- [🚀 Quick Start](#-quick-start)
- [🖼️ Preview](#-preview)
- [📦 Installation](#-installation)
- [✨ Features](#-features)
- [⌨️ Usage](#%EF%B8%8F-usage)
- [⚙️ Configuration](#%EF%B8%8F-configuration)
- [🧰 Tech Stack](#-tech-stack)
- [⚠️ Disclaimer](#%EF%B8%8F-disclaimer)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)
- [👨‍💻 Developer](#-developer)

---

## 🎯 Why PortScope?

> Checking whether a service is listening shouldn't mean remembering `netstat` flags or installing nmap. **PortScope does it in two commands**: give it a host and it scans ports, identifies what's probably running on each open one, and flags availability - all from a single Python file with no root required.
>
> **It's built for quick local checks.** `python portscope.py -a list` gives you a live look at what's listening right now, without touching a config file.

---

## 🧭 What It Does

| # | Task | What it gives you |
|---|------|-------------------|
| 1️⃣ | List local ports & processes | Which ports are open, what protocol they use, and which process owns each one |
| 2️⃣ | Search by port / process / PID | Who is using port 8080? What does PID 1234 have open? |
| 3️⃣ | Check port availability | Is a port free right now, or occupied - and by whom? |

---

## 🚀 Quick Start

```bash
git clone https://github.com/MrHacker-X/portscope.git
cd portscope
pip install -r requirements.txt
python portscope.py                 # interactive menu
```

---

## 🖼️ Preview

<div align="center">

![PortScope Preview](https://i.ibb.co/C5Trhqdb/portscope.png)

</div>

---

## 📦 Installation

```bash
# 1. clone
git clone https://github.com/MrHacker-X/portscope.git
cd portscope

# 2. install dependencies
pip install -r requirements.txt

# 3. run
python portscope.py
```

### Supported Systems

| OS | Status | Notes |
|----|--------|-------|
| 🐧 Linux | ✅ Fully supported | Any distro with Python 3.8+ |
| 🪟 Windows | ✅ Fully supported | Python from python.org, then the steps above |
| 🍎 macOS | ✅ Fully supported | `brew install python`, then the steps above |
| 📱 Termux (Android) | ✅ Fully supported | `pkg install python`, then the steps above |

> 💡 PortScope runs pure TCP connect checks from userspace - no raw sockets, no elevated privileges, no drivers.

---

## ✨ Features

| | Feature | Description |
|---|---------|-------------|
| 🔍 | **Fast range scans** | Concurrent TCP connect checks across a port range with a sane timeout |
| 🏷️ | **Service identification** | Every open port resolved against a well-known ports table (SSH, HTTP, HTTPS, DNS, …) |
| 🎯 | **Single-port checks** | One-shot "is this port in use right now?" without a full scan |
| 📊 | **Rich summary tables** | Results rendered as colored Rich tables with flags for open/closed/filtered |
| 🎛️ | **Two modes** | A guided interactive menu or a fully flag-driven direct CLI |
| 🩹 | **Fail-fast validation** | Bad hostnames, bad ranges, or unreachable hosts produce one clear message |
| 🧱 | **Graceful timeouts** | Hosts that never answer don't hang the whole scan |
| 🪶 | **Minimal dependencies** | `rich` only - the scanner is standard-library sockets |

---

## ⌨️ Usage

```bash
python portscope.py                 # interactive menu
python portscope.py -h              # help
python portscope.py -v              # version
```

### Direct CLI

```bash
# list every listening/active port with its owning process
python portscope.py -a list

# find what's using port 8080
python portscope.py -a port --port 8080

# check whether port 5432 is free before starting your own service
python portscope.py -a check --port 5432

# export the port list to JSON or CSV
python portscope.py -a list -e ports_report.json
```

| Option | Values / Example | Meaning |
|--------|------------------|---------|
| `-a` / `--action` | `list` / `port` / `process` / `details` / `check` / `kill` | Which operation to run (default `list`) |
| `-p` / `--protocol` | `all` / `tcp` / `udp` | Filter results by protocol |
| `--port` | number | Target port for `-a port` / `-a check` |
| `--query` | process name | Search for `-a process` |
| `--pid` | PID | Target process for `-a details` / `-a kill` |
| `-y` / `--yes` | flag | Skip the kill confirmation prompt |
| `-e` / `--export` | a filename | Export the port list (extension decides format) |

---

## ⚙️ Configuration

Scan behavior lives in [`core/config.py`](core/config.py):

| Setting | Default | Effect |
|---------|---------|--------|
| Well-known ports table | ports → service names | How each open port is labeled |
| Default scope | common ports | Which ports `-a list` covers when no protocol filter is given |
| Default timeout | short | Seconds each individual connect attempt waits |
| Concurrency | modest thread pool | How many sockets are checked at once |

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.8+ |
| Networking | Python standard library `socket` (TCP connect scan) |
| UI | `rich` (menus, colored tables, prompts) |

---

## ⚠️ Disclaimer

> ### Read this before using PortScope.
>
> 1. **Scan only what you own.** Port-scanning hosts you don't control may be illegal in your jurisdiction and against most ISPs' and hosts' terms of service. Get written permission first.
> 2. **Not a security audit.** An "open port" only means something answered - it does not mean the service is safe, misconfigured, or exploitable. PortScope is a discovery convenience, not a vulnerability scanner.
> 3. **Firewalls distort results.** Ports can be filtered, silently dropped, or proxied; a closed result is not proof of absence.
> 4. **No warranty.** PortScope is provided "as is", with no warranty of any kind. The author is **not liable** for misuse or legal trouble from scanning without authorization.

---

## 🤝 Contributing

Contributions are welcome!

```bash
# 1. fork it
# 2. create your branch
git checkout -b feature/amazing-feature
# 3. commit
git commit -m "Add amazing feature"
# 4. push
git push origin feature/amazing-feature
# 5. open a Pull Request
```

---

## 📜 License

PortScope is the original project by MrHacker-X - see the [`LICENSE`](https://github.com/MrHacker-X/portscope) file in the upstream repository for details.

---

## 👨‍💻 Developer

| | |
|---|---|
| **Dev** | MrHacker-X |
| **GitHub** | [github.com/MrHacker-X](https://github.com/MrHacker-X) |
| **Email** | [contact@vritrasec.com](mailto:contact@vritrasec.com) |
| **Website** | [vritrasec.com](https://vritrasec.com) |
| **Network** | [link.vritrasec.com](https://link.vritrasec.com) |

---

<div align="center">

### ⭐ Star the repo if PortScope made port checks painless ⭐

*Built by MrHacker-X - scan responsibly, only where permitted.*

</div>
