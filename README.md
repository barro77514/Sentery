# 🛡️ Sentery

**Sentery** is an autonomous, AI-driven Web Penetration Testing (PT) tool designed specifically for complex Business Logic Flaws in E-commerce and Ticketing systems. It combines high-performance traffic interception with modern LLM reasoning and a human-in-the-loop workflow.

---

## 🚀 Key Features

- **⚡ High-Performance MITM Proxy (Go)**: Transparent HTTP/HTTPS interception with dynamic certificate generation and asynchronous SQLite persistence.
- **🛡️ Vulnerability Assessment (VA)**: Automatically scans security headers (CSP, HSTS, etc.) and identifies systematic misconfigurations.
- **🧠 Semantic Memory (Python/LangChain)**: Uses `sqlite-vss` (Vector Semantic Search) to remember successful attack patterns and suggest them for similar traffic structures.
- **🛒 E-commerce Intelligence**: Automatically crawls product pages to detect price discrepancies and suggests "Parameter Pollution" attacks.
- **📈 User Flow Timeline**: Visualizes the user's path through the application and highlights potential logical bypasses (e.g., skipping payment).
- **🤝 Human-in-the-loop**: AI suggests aggressive attacks; the user reviews, approves, and executes them via a beautiful dashboard.

---

## 🏗️ Architecture

- **Core Engine (Go)**: The interceptor. Decrypts TLS traffic, generates fingerprints, and manages the SQLite traffic log.
- **AI Orchestrator (Python/FastAPI)**: The brain. Uses Gemini and LangChain to analyze traffic, query the Knowledge Base, and propose exploits.
- **AdminUI (Next.js/Tailwind)**: The control center. Displays live logs, AI insights, and the flow timeline.

---

## 🛠️ Quick Start

### 1. Requirements
- Docker and Docker Compose
- (Optional) Google Gemini API Key

### 2. Installation
Clone the repository and run the setup script:

```bash
export GEMINI_API_KEY='your_api_key' # Optional
./setup.sh
```

### 3. Usage
1. **Configure Proxy**: Set your browser or testing tool to use the proxy at `localhost:8080`.
2. **HTTPS Inspection**: Download the generated `ca.crt` from the `core/` directory and add it to your browser's trusted Root CAs.
3. **Monitor Dashboard**: Open `http://localhost:3000` to see live traffic and AI suggestions.
4. **Approve Attacks**: When the AI finds a flaw (e.g., in a cart or checkout), click **"Approve & Execute"** to perform the test.

---

## 📊 Database Schema

Sentery uses SQLite as a **Semantic Memory**:
- `requests`: Every intercepted packet with structured fingerprinting.
- `knowledge_base`: Confirmed vulnerabilities and successful payloads stored as vectors for semantic lookup.
- **Automatic TTL**: Traffic logs older than 24 hours are automatically purged to maintain performance.

---

## 🛡️ Responsible Use
Sentery is intended for authorized security testing only. Always obtain permission before testing any system you do not own.
