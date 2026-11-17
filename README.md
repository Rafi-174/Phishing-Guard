Phishing Guard 🛡️

A Web-Based Phishing URL Detection Platform

Phishing Guard is a web-based platform designed to identify potentially suspicious URLs using predefined rule-based analysis. It evaluates URL structures, calculates a risk score, and presents the analysis results with clear explanations.

🎯 Project Objectives

- Detect suspicious URL patterns.
- Identify potentially malicious characteristics in URLs.
- Calculate and display URL risk scores.
- Store scan records in a MySQL database.
- Maintain scan history and provide a summary dashboard.

✨ Key Features

- URL Validation: Checks whether the submitted URL is valid.
- IP Address Detection: Identifies URLs containing IP addresses.
- Suspicious Keyword Detection: Detects potentially risky words in URLs.
- Subdomain Analysis: Checks for excessive subdomains.
- Special Character Analysis: Identifies unusual special characters.
- Risk Score: Calculates a risk score based on predefined rules.
- Scan History: Stores previous scan records.
- Dashboard: Provides a summary of scanning activity.

⚙️ How It Works

1. The user enters a URL into the platform.
2. The system validates the submitted URL.
3. The URL is analyzed using predefined rules.
4. A risk score is calculated.
5. The result is displayed with relevant explanations.
6. The scan record is stored in the database.

🛠️ Technologies Used

- Frontend: HTML, CSS, JavaScript
- Backend: Python
- Database: MySQL
- Version Control: Git and GitHub

📁 Project Structure

Phishing-Guard/
│
├── Backend/
│   ├── analyzer.py
│   ├── app.py
│   ├── config.py
│   ├── database.py
│   ├── requirements.txt
│   └── test_db.py
│
├── Frontend/
│   ├── index.html
│   ├── script.js
│   └── style.css
│
├── .gitignore
└── README.md

⚠️ Disclaimer

Phishing Guard is an educational project that uses predefined rules to analyze URLs. Its results should not be considered a guarantee that a website is safe or malicious.

👨‍💻 Project

Project Name: Phishing Guard

Repository: "GitHub - Phishing Guard" (https://github.com/Rafi-174/Phishing-Guard)

🚀 Installation & Setup Guide

Follow these steps to run Phishing Guard on your local computer.

1. Clone the Repository

git clone https://github.com/Rafi-174/Phishing-Guard.git
cd Phishing-Guard

2. Set Up Python Environment

cd Backend
python -m venv .venv

Activate the virtual environment:

Windows PowerShell:

..\ .venv\Scripts\Activate.ps1

If the environment is created inside the Backend folder, use:

.venv\Scripts\Activate.ps1

3. Install Dependencies

pip install -r requirements.txt

4. Configure MySQL Database

Make sure MySQL is installed and running.

Create the database:

CREATE DATABASE phishguard_db;
USE phishguard_db;

Create the scans table:

CREATE TABLE scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url TEXT NOT NULL,
    risk_score INT NOT NULL,
    risk_level VARCHAR(50) NOT NULL,
    indicators JSON,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

5. Configure Environment Variables

Create a ".env" file inside the Backend folder.

Add your database configuration:

DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=phishguard_db
DB_PORT=3306

FRONTEND_ORIGINS=http://127.0.0.1:5500,http://localhost:5500
FLASK_DEBUG=false

Replace "your_mysql_password" with your own MySQL password.

Important: Never upload your ".env" file or database password to GitHub.

6. Test Database Connection

python test_db.py

A successful connection should display:

MySQL Connection Successful!

7. Run the Backend

python app.py

The Flask backend will run at:

"http://127.0.0.1:5000"

8. Run the Frontend

- Open the Frontend folder in VS Code.
- Open "index.html".
- Run it using the Live Server extension.
- Use the local address "http://127.0.0.1:5500".

🎉 You're Ready!

Phishing Guard is now ready to analyze URLs on your local computer.