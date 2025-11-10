#Create Database
CREATE DATABASE security_analytics;
USE security_analytics;

##Departments
CREATE TABLE departments (
    dept_id INT AUTO_INCREMENT PRIMARY KEY,
    dept_name VARCHAR(100) NOT NULL
);

##Users
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    dept_id INT,
    is_active TINYINT(1) DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (dept_id)
	REFERENCES departments (dept_id)
);

##Login Events
CREATE table login_events (
    login_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    event_time DATETIME,
    ip_address VARCHAR(45),
    location VARCHAR(100),
    is_success TINYINT(1),
    failure_reason VARCHAR(255),
    device VARCHAR(100),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

##VPN Logs
CREATE TABLE vpn_logs (
    vpn_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    connect_time DATETIME,
    disconnect_time DATETIME,
    ip_address VARCHAR(45),
    location VARCHAR(100),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

#Firewall logs
CREATE TABLE firewall_logs (
    fw_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_time DATETIME,
    source_ip VARCHAR(45),
    dest_ip VARCHAR(45),
    action VARCHAR(20),          
    protocol VARCHAR(10),        
    port INT,
    threat_label VARCHAR(100)    
);

#Vulnerabilities
CREATE TABLE vulnerabilities (
    vuln_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    machine_id VARCHAR(100),
    dept_id INT,
    cve_id VARCHAR(50),
    severity VARCHAR(10),        
    detected_at DATETIME,
    remediated_at DATETIME NULL,
    FOREIGN KEY (dept_id) REFERENCES departments(dept_id)
);


##Confirming tables
SHOW TABLES;

## Core KPI Key Performance Indicators Queries ( for dashboard )
##Daily failed login trend
USE security_analytics;
SELECT
    DATE(event_time) AS login_date,
    COUNT(*) AS total_logins,
    SUM(CASE WHEN is_success = 0 THEN 1 ELSE 0 END) AS failed_logins
FROM login_events
GROUP BY DATE(event_time)
ORDER BY login_date;

##Top users with most failed logins
SELECT
    u.username,
    d.dept_name,
    COUNT(*) AS failed_count
FROM login_events le
JOIN users u ON le.user_id = u.user_id
JOIN departments d ON u.dept_id = d.dept_id
WHERE le.is_success = 0
GROUP BY u.username, d.dept_name
ORDER BY failed_count DESC
LIMIT 10;

##Open Vulnerabilities by departments
SELECT
    d.dept_name,
    COUNT(*) AS open_vulns,
    SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_vulns
FROM vulnerabilities v
JOIN departments d ON v.dept_id = d.dept_id
WHERE v.remediated_at IS NULL
GROUP BY d.dept_name
ORDER BY open_vulns DESC;




