# NexusSync

NexusSync is a secure, modular Flask-based super admin portal built for managing infrastructure configurations, real-time system monitoring, and proactive threat intelligence. Designed with security and extensibility in mind, it offers powerful tools for super administrators to control and audit their systems efficiently.

It is intended to be a **foundational base for any Flask web application**. Whether you're building a CRM, ERP, Ecommerce site, or any other enterprise-grade platform, NexusSync provides the backend architecture and admin capabilities needed to scale quickly and securely.

---

## 🚀 Features

- 🧩 **Core Functionalities**

  - Main system configuration with editable key-value entries for friendly setup
  - Change superadmin password
  - All superadmin actions are logged
  - Audit log viewing, filtering, exporting, and wiping

- 🛢️ **Database Tools**

  - Health check & diagnostics
  - Export and import database backups
  - Run custom SQL queries safely inside the web app
  - Basic and extended database configuration management

- 🌐 **IP Management**

  - IP whitelist and blacklist configuration
  - Manual banning of IPs or ranges
  - Integration with Spamhaus DROP list
  - Integration with AbuseIPDB for risk scoring

- 🧠 **Threat Intelligence**

  - Early warning system with port scanning and honeypot correlation
  - Threat scoring from local + external sources
  - GeoIP and ASN analysis for context
  - Partially working advanced correlation engine (in progress)

- 📊 **System Monitoring**

  - Real-time CPU, memory, disk, and DB metrics
  - Historical monitoring with timeline graphing
  - Wipe metric history
  - Export metrics as PNG or CSV (coming soon for anomaly detection)

- 📬 **Email & Notifications**

  - Email server setup and test tool (partially implemented)

  - SMTP configuration UI

  - Superadmin and user roles

  - IP whitelisting, session locking, and brute-force protection

- ⚙️ **System Configuration**

  - Live-editable config values stored in the database
  - Add/edit environment variables from the admin UI

- 📊 **System Monitoring**

  - Real-time CPU, memory, disk, and database usage
  - Export metrics as CSV or image

- 🧠 **Threat Intelligence**

  - Correlation engine (AbuseIPDB + local analysis)
  - Honeypot logging, port scanning, and early warning system
  - GeoIP + ASN lookup, Spamhaus DROP list integration

- 🛡️ **Security & Logging**

  - Role-based access control
  - CSP & HTTPS enforcement
  - SIEM export in CEF, LEEF, JSON, and syslog formats

---

## 🖼️ Screenshots

### 🏠 Landing Page
![Landing Page](docs/screenshots/Screenshot%202025-04-18%20122452.png)

### 🔐 Login Portal
![Login Portal](docs/screenshots/Screenshot%202025-04-18%20122537.png)

### 🧑‍💼 Super Admin Dashboard
![Super Admin Dashboard](docs/screenshots/Screenshot%202025-04-18%20122625.png)

### ⚙️ System Configuration
![System Configuration](docs/screenshots/Screenshot%202025-04-18%20122700.png)

### 🌐 IP & Threat Intelligence Management
![IP & Threat Intelligence Management](docs/screenshots/Screenshot%202025-04-18%20122911.png)

### 📈 Monitoring Dashboard
![Monitoring Dashboard](docs/screenshots/Screenshot%202025-04-18%20122952.png)

### 📝 Audit Logs
![Audit Logs](docs/screenshots/Screenshot%202025-04-18%20123032.png)

### ✉️ Email Configuration
![Email Configuration](docs/screenshots/Screenshot%202025-04-18%20123103.png)

## 🏗️ Project Structure

```
SuperAdminPortal/
├── app/
│   ├── __init__.py
│   ├── extensions.py
│   ├── blueprints/
│   │   ├── main/
│   │   │   ├── __init__.py
│   │   │   └── views.py
│   │   ├── filters/
│   │   │   └── __init__.py
│   ├── superadmin/
│   │   ├── __init__.py
│   │   ├── routes/
│   │   │   ├── __init__.py
│   │   │   ├── main.py
│   │   │   ├── audit_logs.py
│   │   │   ├── cli_config.py
│   │   │   ├── config_keys.py
│   │   │   ├── decorators.py
│   │   │   ├── geoip.py
│   │   │   ├── logger.py
│   │   │   └── *.py
│   │   ├── models/
│   │   │   └── *.py
│   │   ├── forms.py
│   ├── core/
│   │   ├── cookies.py
│   │   ├── error_handlers.py
│   │   ├── forms_shared.py
│   │   ├── location.py
│   │   ├── rate_limits.py
│   │   ├── security.py
│   ├── models/
│   │   ├── __init__.py
│   │   └── *.py
│   ├── intelligence/
│   │   ├── __init__.py
│   │   ├── behavioral.py
│   │   ├── blocklist.py
│   │   ├── constants.py
│   │   ├── correlation.py
│   │   ├── geoip.py
│   │   ├── scanning.py
│   │   ├── siem.py
│   │   ├── spamhaus.py
│   ├── templates/
│   │   ├── base.html
│   │   ├── includes/
│   │   │   └── alerts.html
│   │   ├── errors/
│   │   │   └── 404.html, 500.html, ...
│   │   ├── main/
│   │   │   └── index.html
│   │   ├── superadmin/
│   │       └── *.html
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css
│   │   ├── js/
│   │       └── script.js
├── static/
│   ├── css/
│   └── js/
├── instance/
│   ├── app.db
│   ├── GeoLite2-*.mmdb
│   └── superadmin_audit.log
├── requirements.txt
├── README.md
├── main.py
└── project_tree.py
```

---

## ⚙️ Setup

### ✅ Prerequisites

- Python 3.10+
- pip installed
- git installed
- A terminal or command prompt

### Installation

🪟 For Windows Users
# Clone the repository
git clone https://github.com/sudo0xn14r/NexusSync.git
cd NexusSync

# Create a virtual environment
python -m venv venv

# Activate the environment (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the app
python main.py

🐧 For Linux/macOS Users
# Clone the repository
git clone https://github.com/sudo0xn14r/NexusSync.git
cd NexusSync

# Create a virtual environment
python3 -m venv venv

# Activate the environment (Linux/macOS)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the app
python3 main.py

---

## 🔐 Configuration

### 🔑 Default Credentials

The application ships with a default superadmin account for initial access:

- **Username:** `superadmin`
- **Password:** `iamthesuperadmin123!`


Create a `.env` or use environment variables:

```bash
SECRET_KEY=your-secret-key
FLASK_ENV=development
SQLALCHEMY_DATABASE_URI=sqlite:///instance/app.db
ABUSEIPDB_API_KEY=your-api-key
```

Or configure everything from the SuperAdmin dashboard.

---

## 🔗 Entry Points

- **Main Landing Page:** [http://127.0.0.1:5000/](http://127.0.0.1:5000/)
- **Superadmin Login:** [http://127.0.0.1:5000/superadmin/login](http://127.0.0.1:5000/superadmin/login)
- **Superadmin Dashboard:** [http://127.0.0.1:5000/superadmin/dashboard](http://127.0.0.1:5000/superadmin/dashboard)

---

## 🧭 Roadmap

### 🚧 In Progress
- Enhance in-app database CLI capabilities for executing and managing SQL operations with improved usability and safety
- Extend email functionality with editable templates:
  - User registration confirmation
  - Two-factor authentication prompts
  - Critical system notifications
- Add startup and periodic health checks for system diagnostics
- Introduce privacy tooling to manage and audit personally identifiable information (PIIs)
- Enhance the Threat Intelligence Hub and correlation engine

### 🗓️ Planned
- Integration of Redis for request rate limiting and abuse protection
- Expand database management to support multiple DB instances (local/cloud):
  - View, modify, and alter external databases
- Implement full data retention policies for logs and metrics
- Enhance security configuration section to align with OWASP's latest web application security recommendations
