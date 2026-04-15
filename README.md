# Suspicious Login Activity Detection System

## Overview
The Suspicious Login Activity Detection System is a web-based application that monitors and analyzes user login activity to detect unusual or potentially malicious behavior. It helps in identifying brute-force attacks, unauthorized access, and anomalous login patterns.

---

## Features

-  Detects multiple failed login attempts
- Identifies logins from unusual geographic locations
-  Detects abnormal login times
-  Interactive data visualizations and dashboards
-  Real-time suspicious activity alerts
-  Tracks device and browser usage patterns

---

##  Data Visualizations

- **Login Activity Timeline (Line Chart)**  
  Tracks login patterns over time

- **Failed vs Successful Logins (Bar Chart)**  
  Identifies brute-force attack attempts

- **Geographical Distribution (Map/Heatmap)**  
  Detects unusual login locations

- **Device/Browser Distribution (Pie Chart)**  
  Highlights anomalies in device usage

- **Suspicious Alerts Dashboard**  
  Displays flagged login activities

---

## Technologies Used

### Frontend
- HTML
- CSS
- JavaScript

### Backend
- Python (Django)

### Libraries / Tools
- Pandas (data processing)
- NumPy
- Matplotlib / Chart.js (data visualization)

---

##  Datasets Used

- **Login Logs Dataset**  
  Contains user login attempts with timestamps and status (success/failure)

- **IP Blacklist Dataset**  
  List of known malicious or suspicious IP addresses

- **City Coordinates Dataset**  
  Maps IP addresses to geographic locations

- **Remote Tools Dataset**  
  Identifies access via remote connection tools

- **Threat Intelligence Dataset**  
  Contains known attack patterns and threat types

---

## How It Works

1. Collects login data (IP, timestamp, device, location)
2. Processes data using Python and Pandas
3. Applies rules to detect suspicious patterns:
   - Multiple failed attempts
   - Login from different locations in short time
   - Unusual login timing
4. Flags suspicious activities
5. Displays results using interactive dashboards

---
