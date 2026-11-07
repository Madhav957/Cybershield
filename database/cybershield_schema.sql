-- =====================================================================
-- CYBERSHIELD - Cybersecurity Incident Intelligence System
-- Complete MySQL Database Schema and Seed Data
-- =====================================================================

CREATE DATABASE IF NOT EXISTS `cybershield`;
USE `cybershield`;

SET FOREIGN_KEY_CHECKS = 0;

-- -----------------------------------------------------
-- Table structure for `attack_types`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `attack_types`;
CREATE TABLE `attack_types` (
  `attack_type_id` int NOT NULL AUTO_INCREMENT,
  `type_name` varchar(100) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`attack_type_id`),
  UNIQUE KEY `type_name` (`type_name`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- -----------------------------------------------------
-- Table structure for `analysts`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `analysts`;
CREATE TABLE `analysts` (
  `analyst_id` int NOT NULL AUTO_INCREMENT,
  `full_name` varchar(100) NOT NULL,
  `email` varchar(150) NOT NULL,
  `role` varchar(50) NOT NULL,
  PRIMARY KEY (`analyst_id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- -----------------------------------------------------
-- Table structure for `devices`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `devices`;
CREATE TABLE `devices` (
  `device_id` int NOT NULL AUTO_INCREMENT,
  `hostname` varchar(100) NOT NULL,
  `device_type` varchar(50) NOT NULL,
  `operating_system` varchar(100) DEFAULT NULL,
  `department` varchar(100) DEFAULT NULL,
  `criticality` enum('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL DEFAULT 'MEDIUM',
  PRIMARY KEY (`device_id`),
  UNIQUE KEY `hostname` (`hostname`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- -----------------------------------------------------
-- Table structure for `ip_addresses`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `ip_addresses`;
CREATE TABLE `ip_addresses` (
  `ip_id` int NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(45) NOT NULL,
  `reputation` enum('UNKNOWN','LOW','MEDIUM','HIGH') NOT NULL DEFAULT 'UNKNOWN',
  PRIMARY KEY (`ip_id`),
  UNIQUE KEY `ip_address` (`ip_address`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- -----------------------------------------------------
-- Table structure for `incidents`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `incidents`;
CREATE TABLE `incidents` (
  `incident_id` int NOT NULL AUTO_INCREMENT,
  `title` varchar(200) NOT NULL,
  `description` text,
  `attack_type_id` int NOT NULL,
  `severity` enum('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL DEFAULT 'MEDIUM',
  `status` enum('OPEN','INVESTIGATING','CONTAINED','RESOLVED','CLOSED') NOT NULL DEFAULT 'OPEN',
  `detected_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `resolved_at` datetime DEFAULT NULL,
  PRIMARY KEY (`incident_id`),
  KEY `attack_type_id` (`attack_type_id`),
  CONSTRAINT `incidents_ibfk_1` FOREIGN KEY (`attack_type_id`) REFERENCES `attack_types` (`attack_type_id`),
  CONSTRAINT `incidents_chk_1` CHECK (((`resolved_at` is null) or (`resolved_at` >= `detected_at`)))
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- -----------------------------------------------------
-- Table structure for `investigations`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `investigations`;
CREATE TABLE `investigations` (
  `investigation_id` int NOT NULL AUTO_INCREMENT,
  `incident_id` int NOT NULL,
  `analyst_id` int NOT NULL,
  `started_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `status` enum('ASSIGNED','IN_PROGRESS','COMPLETED') NOT NULL DEFAULT 'ASSIGNED',
  `conclusion` text,
  PRIMARY KEY (`investigation_id`),
  UNIQUE KEY `incident_id` (`incident_id`),
  KEY `analyst_id` (`analyst_id`),
  CONSTRAINT `investigations_ibfk_1` FOREIGN KEY (`incident_id`) REFERENCES `incidents` (`incident_id`) ON DELETE CASCADE,
  CONSTRAINT `investigations_ibfk_2` FOREIGN KEY (`analyst_id`) REFERENCES `analysts` (`analyst_id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- -----------------------------------------------------
-- Table structure for `incident_devices`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `incident_devices`;
CREATE TABLE `incident_devices` (
  `incident_id` int NOT NULL,
  `device_id` int NOT NULL,
  `impact_description` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`incident_id`,`device_id`),
  KEY `device_id` (`device_id`),
  CONSTRAINT `incident_devices_ibfk_1` FOREIGN KEY (`incident_id`) REFERENCES `incidents` (`incident_id`) ON DELETE CASCADE,
  CONSTRAINT `incident_devices_ibfk_2` FOREIGN KEY (`device_id`) REFERENCES `devices` (`device_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- -----------------------------------------------------
-- Table structure for `incident_ips`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `incident_ips`;
CREATE TABLE `incident_ips` (
  `incident_id` int NOT NULL,
  `ip_id` int NOT NULL,
  `association_type` enum('SOURCE','DESTINATION','RELATED') NOT NULL DEFAULT 'RELATED',
  PRIMARY KEY (`incident_id`,`ip_id`),
  KEY `ip_id` (`ip_id`),
  CONSTRAINT `incident_ips_ibfk_1` FOREIGN KEY (`incident_id`) REFERENCES `incidents` (`incident_id`) ON DELETE CASCADE,
  CONSTRAINT `incident_ips_ibfk_2` FOREIGN KEY (`ip_id`) REFERENCES `ip_addresses` (`ip_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- -----------------------------------------------------
-- Table structure for `incident_status_history`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `incident_status_history`;
CREATE TABLE `incident_status_history` (
  `history_id` int NOT NULL AUTO_INCREMENT,
  `incident_id` int NOT NULL,
  `old_status` enum('OPEN','INVESTIGATING','CONTAINED','RESOLVED','CLOSED') NOT NULL,
  `new_status` enum('OPEN','INVESTIGATING','CONTAINED','RESOLVED','CLOSED') NOT NULL,
  `changed_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `changed_by` varchar(100) NOT NULL DEFAULT 'SYSTEM',
  PRIMARY KEY (`history_id`),
  KEY `idx_status_history_incident_time` (`incident_id`,`changed_at`),
  CONSTRAINT `incident_status_history_ibfk_1` FOREIGN KEY (`incident_id`) REFERENCES `incidents` (`incident_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- -----------------------------------------------------
-- View structure for `v_incident_overview`
-- -----------------------------------------------------
DROP VIEW IF EXISTS `v_incident_overview`;
CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_incident_overview` AS select `i`.`incident_id` AS `incident_id`,`i`.`title` AS `title`,`a`.`type_name` AS `attack_type`,`i`.`severity` AS `severity`,`i`.`status` AS `status`,`i`.`detected_at` AS `detected_at`,`i`.`resolved_at` AS `resolved_at`,`an`.`full_name` AS `assigned_analyst`,`inv`.`status` AS `investigation_status`,`inv`.`conclusion` AS `conclusion` from (((`incidents` `i` join `attack_types` `a` on((`i`.`attack_type_id` = `a`.`attack_type_id`))) left join `investigations` `inv` on((`i`.`incident_id` = `inv`.`incident_id`))) left join `analysts` `an` on((`inv`.`analyst_id` = `an`.`analyst_id`)));

-- -----------------------------------------------------
-- Trigger `trg_validate_incident_status`
-- -----------------------------------------------------
DROP TRIGGER IF EXISTS `trg_validate_incident_status`;
DELIMITER $$
CREATE DEFINER=`root`@`localhost` TRIGGER `trg_validate_incident_status` BEFORE UPDATE ON `incidents` FOR EACH ROW BEGIN
    IF NOT (OLD.status <=> NEW.status)
       AND NOT (
           (OLD.status = 'OPEN'
               AND NEW.status = 'INVESTIGATING')
           OR
           (OLD.status = 'INVESTIGATING'
               AND NEW.status IN ('CONTAINED', 'RESOLVED'))
           OR
           (OLD.status = 'CONTAINED'
               AND NEW.status IN ('INVESTIGATING', 'RESOLVED'))
           OR
           (OLD.status = 'RESOLVED'
               AND NEW.status = 'CLOSED')
       )
    THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Invalid incident status transition';
    END IF;
END$$
DELIMITER ;

-- -----------------------------------------------------
-- Trigger `trg_record_incident_status`
-- -----------------------------------------------------
DROP TRIGGER IF EXISTS `trg_record_incident_status`;
DELIMITER $$
CREATE DEFINER=`root`@`localhost` TRIGGER `trg_record_incident_status` AFTER UPDATE ON `incidents` FOR EACH ROW BEGIN
    IF NOT (OLD.status <=> NEW.status) THEN
        INSERT INTO incident_status_history (
            incident_id,
            old_status,
            new_status,
            changed_by
        )
        VALUES (
            NEW.incident_id,
            OLD.status,
            NEW.status,
            COALESCE(
                NULLIF(@cybershield_actor, ''),
                'SYSTEM'
            )
        );
    END IF;
END$$
DELIMITER ;

SET FOREIGN_KEY_CHECKS = 1;

-- =====================================================================
-- Initial Seed Data
-- =====================================================================

SET FOREIGN_KEY_CHECKS = 0;

-- Dumping data for table `attack_types`
INSERT INTO `attack_types` (`attack_type_id`, `type_name`, `description`) VALUES (1, 'Brute Force', 'Repeated login attempts to guess credentials');
INSERT INTO `attack_types` (`attack_type_id`, `type_name`, `description`) VALUES (2, 'Phishing', 'Deceptive messages intended to steal information');
INSERT INTO `attack_types` (`attack_type_id`, `type_name`, `description`) VALUES (3, 'Malware', 'Malicious software detected on a system');
INSERT INTO `attack_types` (`attack_type_id`, `type_name`, `description`) VALUES (4, 'Data Exfiltration', 'Suspicious transfer of sensitive data');
INSERT INTO `attack_types` (`attack_type_id`, `type_name`, `description`) VALUES (5, 'Unauthorized Access', 'Access without valid authorization');

-- Dumping data for table `analysts`
INSERT INTO `analysts` (`analyst_id`, `full_name`, `email`, `role`) VALUES (1, 'Arjun Rao', 'arjun@cybershield.demo', 'SOC Analyst');
INSERT INTO `analysts` (`analyst_id`, `full_name`, `email`, `role`) VALUES (2, 'Priya Sharma', 'priya@cybershield.demo', 'Incident Responder');
INSERT INTO `analysts` (`analyst_id`, `full_name`, `email`, `role`) VALUES (3, 'Rahul Kumar', 'rahul@cybershield.demo', 'Security Engineer');

-- Dumping data for table `devices`
INSERT INTO `devices` (`device_id`, `hostname`, `device_type`, `operating_system`, `department`, `criticality`) VALUES (1, 'FIN-PC-01', 'Desktop', 'Windows 11', 'Finance', 'HIGH');
INSERT INTO `devices` (`device_id`, `hostname`, `device_type`, `operating_system`, `department`, `criticality`) VALUES (2, 'HR-LAPTOP-02', 'Laptop', 'Windows 11', 'Human Resources', 'MEDIUM');
INSERT INTO `devices` (`device_id`, `hostname`, `device_type`, `operating_system`, `department`, `criticality`) VALUES (3, 'WEB-SERVER-01', 'Server', 'Ubuntu Linux', 'IT', 'CRITICAL');
INSERT INTO `devices` (`device_id`, `hostname`, `device_type`, `operating_system`, `department`, `criticality`) VALUES (4, 'DEV-PC-04', 'Desktop', 'Ubuntu Linux', 'Development', 'MEDIUM');

-- Dumping data for table `ip_addresses`
INSERT INTO `ip_addresses` (`ip_id`, `ip_address`, `reputation`) VALUES (1, '203.0.113.10', 'HIGH');
INSERT INTO `ip_addresses` (`ip_id`, `ip_address`, `reputation`) VALUES (2, '198.51.100.24', 'MEDIUM');
INSERT INTO `ip_addresses` (`ip_id`, `ip_address`, `reputation`) VALUES (3, '192.0.2.45', 'LOW');
INSERT INTO `ip_addresses` (`ip_id`, `ip_address`, `reputation`) VALUES (4, '10.0.0.15', 'UNKNOWN');

-- Dumping data for table `incidents`
INSERT INTO `incidents` (`incident_id`, `title`, `description`, `attack_type_id`, `severity`, `status`, `detected_at`, `resolved_at`) VALUES (1, 'Repeated login failures', 'Multiple failed login attempts against a finance account', 1, 'HIGH', 'RESOLVED', '2026-10-15 09:15:00', '2026-10-16 19:34:22');
INSERT INTO `incidents` (`incident_id`, `title`, `description`, `attack_type_id`, `severity`, `status`, `detected_at`, `resolved_at`) VALUES (2, 'Suspicious email attachment', 'Employee reported an unexpected attachment in an email', 2, 'CRITICAL', 'OPEN', '2026-10-15 10:30:00', NULL);
INSERT INTO `incidents` (`incident_id`, `title`, `description`, `attack_type_id`, `severity`, `status`, `detected_at`, `resolved_at`) VALUES (3, 'Malware alert on web server', 'Endpoint security flagged a suspicious executable', 3, 'CRITICAL', 'RESOLVED', '2026-10-14 14:00:00', '2026-10-16 19:12:57');
INSERT INTO `incidents` (`incident_id`, `title`, `description`, `attack_type_id`, `severity`, `status`, `detected_at`, `resolved_at`) VALUES (4, 'Unusual outbound traffic', 'Unexpected outbound data transfer detected', 4, 'HIGH', 'RESOLVED', '2026-10-13 11:00:00', '2026-10-13 15:30:00');
INSERT INTO `incidents` (`incident_id`, `title`, `description`, `attack_type_id`, `severity`, `status`, `detected_at`, `resolved_at`) VALUES (5, 'Unrecognized account access', 'Access attempt detected from an unfamiliar network', 5, 'MEDIUM', 'CLOSED', '2026-10-12 08:00:00', '2026-10-12 12:00:00');
INSERT INTO `incidents` (`incident_id`, `title`, `description`, `attack_type_id`, `severity`, `status`, `detected_at`, `resolved_at`) VALUES (6, 'DDOS', 'This attack happened recently', 1, 'MEDIUM', 'OPEN', '2026-10-16 19:00:56', NULL);

-- Dumping data for table `investigations`
INSERT INTO `investigations` (`investigation_id`, `incident_id`, `analyst_id`, `started_at`, `status`, `conclusion`) VALUES (1, 1, 1, '2026-10-16 11:04:36', 'IN_PROGRESS', NULL);
INSERT INTO `investigations` (`investigation_id`, `incident_id`, `analyst_id`, `started_at`, `status`, `conclusion`) VALUES (2, 2, 2, '2026-10-16 11:04:36', 'ASSIGNED', NULL);
INSERT INTO `investigations` (`investigation_id`, `incident_id`, `analyst_id`, `started_at`, `status`, `conclusion`) VALUES (3, 3, 3, '2026-10-16 11:04:36', 'IN_PROGRESS', 'Suspicious process isolated for analysis');
INSERT INTO `investigations` (`investigation_id`, `incident_id`, `analyst_id`, `started_at`, `status`, `conclusion`) VALUES (4, 4, 1, '2026-10-16 11:04:36', 'COMPLETED', 'Outbound transfer reviewed and contained');
INSERT INTO `investigations` (`investigation_id`, `incident_id`, `analyst_id`, `started_at`, `status`, `conclusion`) VALUES (5, 5, 2, '2026-10-16 11:04:36', 'COMPLETED', 'Access attempt reviewed and closed');

-- Dumping data for table `incident_devices`
INSERT INTO `incident_devices` (`incident_id`, `device_id`, `impact_description`) VALUES (1, 1, 'Finance account targeted by repeated login failures');
INSERT INTO `incident_devices` (`incident_id`, `device_id`, `impact_description`) VALUES (2, 2, 'Employee received suspicious attachment');
INSERT INTO `incident_devices` (`incident_id`, `device_id`, `impact_description`) VALUES (3, 3, 'Suspicious executable detected on web server');
INSERT INTO `incident_devices` (`incident_id`, `device_id`, `impact_description`) VALUES (4, 3, 'Unusual outbound traffic from web server');
INSERT INTO `incident_devices` (`incident_id`, `device_id`, `impact_description`) VALUES (5, 1, 'Unrecognized access attempt involving finance PC');

-- Dumping data for table `incident_ips`
INSERT INTO `incident_ips` (`incident_id`, `ip_id`, `association_type`) VALUES (1, 1, 'SOURCE');
INSERT INTO `incident_ips` (`incident_id`, `ip_id`, `association_type`) VALUES (2, 2, 'SOURCE');
INSERT INTO `incident_ips` (`incident_id`, `ip_id`, `association_type`) VALUES (3, 3, 'RELATED');
INSERT INTO `incident_ips` (`incident_id`, `ip_id`, `association_type`) VALUES (4, 4, 'SOURCE');
INSERT INTO `incident_ips` (`incident_id`, `ip_id`, `association_type`) VALUES (5, 1, 'SOURCE');

-- Dumping data for table `incident_status_history`
INSERT INTO `incident_status_history` (`history_id`, `incident_id`, `old_status`, `new_status`, `changed_at`, `changed_by`) VALUES (1, 3, 'CONTAINED', 'RESOLVED', '2026-10-16 19:12:57', 'CyberShield dashboard');
INSERT INTO `incident_status_history` (`history_id`, `incident_id`, `old_status`, `new_status`, `changed_at`, `changed_by`) VALUES (2, 1, 'INVESTIGATING', 'RESOLVED', '2026-10-16 19:34:22', 'CyberShield dashboard');

SET FOREIGN_KEY_CHECKS = 1;
