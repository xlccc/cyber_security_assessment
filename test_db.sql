/*
 Navicat Premium Data Transfer

 Source Server         : 10.9.130.61_3306
 Source Server Type    : MySQL
 Source Server Version : 80039
 Source Host           : 10.9.130.61:3306
 Source Schema         : test_db

 Target Server Type    : MySQL
 Target Server Version : 80039
 File Encoding         : 65001

 Date: 30/11/2024 12:18:12
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

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
) ENGINE = InnoDB AUTO_INCREMENT = 13 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for host_vuln_result
-- ----------------------------
DROP TABLE IF EXISTS `host_vuln_result`;
CREATE TABLE `host_vuln_result`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `shr_id` int(0) NOT NULL,
  `vuln_id` int(0) NOT NULL,
  `vulExist` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT '未验证',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `shr_id`(`shr_id`, `vuln_id`) USING BTREE,
  CONSTRAINT `host_vuln_result_ibfk_1` FOREIGN KEY (`shr_id`) REFERENCES `scan_host_result` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 61 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

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
) ENGINE = InnoDB AUTO_INCREMENT = 98 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

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
) ENGINE = InnoDB AUTO_INCREMENT = 19 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

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
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `shr_id`(`shr_id`, `port_id`, `vuln_id`) USING BTREE,
  INDEX `port_id`(`port_id`) USING BTREE,
  CONSTRAINT `port_vuln_result_ibfk_1` FOREIGN KEY (`shr_id`) REFERENCES `scan_host_result` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT,
  CONSTRAINT `port_vuln_result_ibfk_2` FOREIGN KEY (`port_id`) REFERENCES `open_ports` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 51 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

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
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `ip`(`ip`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 20 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

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
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `vuln_id`(`vuln_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 151 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

SET FOREIGN_KEY_CHECKS = 1;
