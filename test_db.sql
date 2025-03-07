/*
 Navicat Premium Data Transfer

 Source Server         : 192.168.0.101_3306
 Source Server Type    : MySQL
 Source Server Version : 80039
 Source Host           : 10.9.130.189:3306
 Source Schema         : test_db

 Target Server Type    : MySQL
 Target Server Version : 80039
 File Encoding         : 65001

 Date: 02/03/2025 22:24:52
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for alive_hosts
-- ----------------------------
DROP TABLE IF EXISTS `alive_hosts`;
CREATE TABLE `alive_hosts`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(15) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `create_time` timestamp(0) NULL DEFAULT CURRENT_TIMESTAMP(0),
  `update_time` timestamp(0) NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0),
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `idx_ip`(`ip_address`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 7 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for host_cpe
-- ----------------------------
DROP TABLE IF EXISTS `host_cpe`;
CREATE TABLE `host_cpe`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `shr_id` int(0) NOT NULL,
  `cpe` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `shr_id`(`shr_id`, `cpe`) USING BTREE,
  CONSTRAINT `host_cpe_ibfk_1` FOREIGN KEY (`shr_id`) REFERENCES `scan_host_result` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 59 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for host_vuln_result
-- ----------------------------
DROP TABLE IF EXISTS `host_vuln_result`;
CREATE TABLE `host_vuln_result`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `shr_id` int(0) NOT NULL,
  `vuln_id` int(0) NOT NULL,
  `vulExist` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT '未验证',
  `cpe_id` int(0) NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `shr_id`(`shr_id`, `vuln_id`) USING BTREE,
  INDEX `host_vuln_cpe_fk`(`cpe_id`) USING BTREE,
  CONSTRAINT `host_vuln_result_ibfk_1` FOREIGN KEY (`shr_id`) REFERENCES `scan_host_result` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT,
  CONSTRAINT `host_vuln_cpe_fk` FOREIGN KEY (`cpe_id`) REFERENCES `host_cpe` (`id`) ON DELETE SET NULL ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 2101 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for open_ports
-- ----------------------------
DROP TABLE IF EXISTS `open_ports`;
CREATE TABLE `open_ports`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `shr_id` int(0) NOT NULL,
  `port` int(0) NOT NULL,
  `protocol` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `status` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `service_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `product` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  `version` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  `software_type` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `shr_id`(`shr_id`, `port`, `protocol`) USING BTREE,
  CONSTRAINT `open_ports_ibfk_1` FOREIGN KEY (`shr_id`) REFERENCES `scan_host_result` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 153 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for os_info
-- ----------------------------
DROP TABLE IF EXISTS `os_info`;
CREATE TABLE `os_info`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `shr_id` int(0) NOT NULL,
  `os_version` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `unique_shr_os`(`shr_id`, `os_version`) USING BTREE,
  CONSTRAINT `os_info_ibfk_1` FOREIGN KEY (`shr_id`) REFERENCES `scan_host_result` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 30 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for port_vuln_result
-- ----------------------------
DROP TABLE IF EXISTS `port_vuln_result`;
CREATE TABLE `port_vuln_result`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `shr_id` int(0) NOT NULL,
  `port_id` int(0) NOT NULL,
  `vuln_id` int(0) NOT NULL,
  `vulExist` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT '未验证',
  `cpe_id` int(0) NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `shr_id`(`shr_id`, `port_id`, `vuln_id`) USING BTREE,
  INDEX `port_id`(`port_id`) USING BTREE,
  INDEX `port_vuln_cpe_fk`(`cpe_id`) USING BTREE,
  CONSTRAINT `port_vuln_result_ibfk_1` FOREIGN KEY (`shr_id`) REFERENCES `scan_host_result` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT,
  CONSTRAINT `port_vuln_result_ibfk_2` FOREIGN KEY (`port_id`) REFERENCES `open_ports` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT,
  CONSTRAINT `port_vuln_cpe_fk` FOREIGN KEY (`cpe_id`) REFERENCES `host_cpe` (`id`) ON DELETE SET NULL ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 133 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for scan_host_result
-- ----------------------------
DROP TABLE IF EXISTS `scan_host_result`;
CREATE TABLE `scan_host_result`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `url` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  `ip` varchar(45) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `scan_time` datetime(0) NOT NULL,
  `scan_type` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  `alive` enum('true','false') CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'false' COMMENT '主机存活状态',
  `expire_time` datetime(0) NULL DEFAULT NULL COMMENT '主机存活状态过期时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `ip`(`ip`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 67 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for vuln
-- ----------------------------
DROP TABLE IF EXISTS `vuln`;
CREATE TABLE `vuln`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `vuln_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `vul_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `script` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  `CVSS` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `summary` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `vuln_type` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  `cpe_id` int(0) NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `vuln_id`(`vuln_id`) USING BTREE,
  INDEX `vuln_cpe_fk`(`cpe_id`) USING BTREE,
  CONSTRAINT `vuln_cpe_fk` FOREIGN KEY (`cpe_id`) REFERENCES `host_cpe` (`id`) ON DELETE SET NULL ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 2273 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for vulnerability
-- ----------------------------
DROP TABLE IF EXISTS `vulnerability`;
CREATE TABLE `vulnerability`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `nvd_cve_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `cpe` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `cvss2_nvd_base_score` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  `cvss2_nvd_vector` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  `cvss3_nvd_base_score` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  `cvss3_nvd_vector` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  `cwe_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  `cwe_name` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `reference_urls` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  `vuln_description` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `nvd_cve_id`(`nvd_cve_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

SET FOREIGN_KEY_CHECKS = 1;
