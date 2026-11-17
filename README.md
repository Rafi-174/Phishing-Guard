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