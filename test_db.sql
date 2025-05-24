/*
 Navicat Premium Data Transfer

 Source Server         : 192.168.0.101_3306
 Source Server Type    : MySQL
 Source Server Version : 80041
 Source Host           : 10.9.130.100:3306
 Source Schema         : test_db

 Target Server Type    : MySQL
 Target Server Version : 80041
 File Encoding         : 65001

 Date: 06/04/2025 17:03:43
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
) ENGINE = InnoDB AUTO_INCREMENT = 8 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

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
) ENGINE = InnoDB AUTO_INCREMENT = 448 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

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
  CONSTRAINT `host_vuln_cpe_fk` FOREIGN KEY (`cpe_id`) REFERENCES `host_cpe` (`id`) ON DELETE SET NULL ON UPDATE RESTRICT,
  CONSTRAINT `host_vuln_result_ibfk_1` FOREIGN KEY (`shr_id`) REFERENCES `scan_host_result` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 3020 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for level3_security_check_results
-- ----------------------------
DROP TABLE IF EXISTS `level3_security_check_results`;
CREATE TABLE `level3_security_check_results`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `shr_id` int(0) NOT NULL COMMENT '关联 scan_host_result 表的 ID',
  `item_id` int(0) NOT NULL COMMENT '检查项 ID',
  `description` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '检查项描述',
  `basis` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '判定依据',
  `command` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '待检查口令',
  `result` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '检查结果',
  `is_comply` enum('true','false','pending','half_true') CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'false' COMMENT '是否合规',
  `tmp_is_comply` enum('true','false','pending','half_true') CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'half_true' COMMENT '计算评分列',
  `recommend` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '建议',
  `important_level` enum('1','2','3') CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '重要程度',
  `check_time` datetime(0) NOT NULL COMMENT '检查时间',
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_shr_id`(`shr_id`) USING BTREE,
  INDEX `idx_item_id`(`item_id`) USING BTREE,
  INDEX `idx_check_time`(`check_time`) USING BTREE,
  CONSTRAINT `fk_level3_check_result_scan_host` FOREIGN KEY (`shr_id`) REFERENCES `scan_host_result` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 275 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

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
  `weak_username` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  `weak_password` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL,
  `password_verified` enum('true','false') CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT 'false',
  `verify_time` timestamp(0) NULL DEFAULT NULL,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `shr_id`(`shr_id`, `port`, `protocol`) USING BTREE,
  CONSTRAINT `open_ports_ibfk_1` FOREIGN KEY (`shr_id`) REFERENCES `scan_host_result` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 633 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

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
) ENGINE = InnoDB AUTO_INCREMENT = 138 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

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
  CONSTRAINT `port_vuln_cpe_fk` FOREIGN KEY (`cpe_id`) REFERENCES `host_cpe` (`id`) ON DELETE SET NULL ON UPDATE RESTRICT,
  CONSTRAINT `port_vuln_result_ibfk_1` FOREIGN KEY (`shr_id`) REFERENCES `scan_host_result` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT,
  CONSTRAINT `port_vuln_result_ibfk_2` FOREIGN KEY (`port_id`) REFERENCES `open_ports` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 2126 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

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
) ENGINE = InnoDB AUTO_INCREMENT = 133 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

ALTER TABLE `scan_host_result`
ADD COLUMN `group_id` INT DEFAULT NULL COMMENT '所属资产组ID',
ADD CONSTRAINT `fk_scan_host_group`
  FOREIGN KEY (`group_id`) REFERENCES `asset_group` (`id`)
  ON DELETE SET NULL ON UPDATE CASCADE;

-- ----------------------------
-- Table structure for security_check_results
-- ----------------------------
DROP TABLE IF EXISTS `security_check_results`;
CREATE TABLE `security_check_results`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `shr_id` int(0) NOT NULL COMMENT '关联 scan_host_result 表的 ID',
  `item_id` int(0) NOT NULL COMMENT '检查项 ID',
  `description` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '检查项描述',
  `basis` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '判定依据',
  `command` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '待检查口令',
  `result` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '检查结果',
  `is_comply` enum('true','false','pending','half_true') CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'false' COMMENT '是否合规',
  `tmp_is_comply` enum('true','false','pending','half_true') CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'half_true' COMMENT '计算评分列',
  `recommend` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '建议',
  `important_level` enum('1','2','3') CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '重要程度',
  `check_time` datetime(0) NOT NULL COMMENT '检查时间',
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_shr_id`(`shr_id`) USING BTREE,
  INDEX `idx_item_id`(`item_id`) USING BTREE,
  INDEX `idx_check_time`(`check_time`) USING BTREE,
  CONSTRAINT `fk_check_result_scan_host` FOREIGN KEY (`shr_id`) REFERENCES `scan_host_result` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 275 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for server_info
-- ----------------------------
DROP TABLE IF EXISTS `server_info`;
CREATE TABLE `server_info`  (
  `id` int(0) NOT NULL AUTO_INCREMENT,
  `shr_id` int(0) NOT NULL COMMENT '关联scan_host_result表的ID',
  `hostname` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '目标主机名',
  `arch` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '目标主机的架构',
  `cpu` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '目标主机cpu信息',
  `cpu_physical` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '目标主机物理cpu个数',
  `cpu_core` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '目标主机物理CPU核心数',
  `free_memory` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '目标主机空闲内存',
  `product_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '硬件型号',
  `version` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '目标主机版本信息',
  `os_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '操作系统名称',
  `is_internet` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '联网检测',
  `create_time` timestamp(0) NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` timestamp(0) NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_shr_id`(`shr_id`) USING BTREE,
  CONSTRAINT `fk_server_info_scan_host` FOREIGN KEY (`shr_id`) REFERENCES `scan_host_result` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 4 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '服务器信息表' ROW_FORMAT = Dynamic;

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
) ENGINE = InnoDB AUTO_INCREMENT = 5187 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;

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
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci ROW_FORMAT = Dynamic;


-- ----------------------------
-- Table structure for POC
-- ----------------------------
DROP TABLE IF EXISTS POC;
CREATE TABLE IF NOT EXISTS POC (
    ID INT AUTO_INCREMENT PRIMARY KEY,
    Vuln_id VARCHAR(100) UNIQUE,
    Vul_name VARCHAR(255) NOT NULL,
    Type VARCHAR(255),
    Description TEXT,
    Affected_infra VARCHAR(255) NOT NULL,
    Script_type ENUM('python', 'c/c++', 'yaml') NOT NULL DEFAULT 'python',
    Script TEXT,
    Timestamp TEXT NOT NULL,
    
    UNIQUE (Vuln_id, Vul_name),
    
    FOREIGN KEY (Type) REFERENCES VulnType(TypeName)
        ON UPDATE CASCADE
        ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO POC VALUES (19,'CVE-2019-11510','Pulse Secure 任意文件读取','代码注入','这是一个示例','0','python','','2024-05-12 12:54:23');
INSERT INTO POC VALUES (28,'CVE-2021-123324','SQL注入漏洞','SQL 注入','这是一个示例描述','0','c/c++','','2024-05-12 15:51:02');
INSERT INTO POC VALUES (29,'CVE-2020-15778','OpenSSH 操作系统命令注入漏洞','代码注入','OpenSSH 8.3p1及之前版本中的scp的scp.c文件存在操作系统命令注入漏洞。该漏洞即使在禁用ssh登录的情况下，但是允许使用scp传文件，而且远程服务器允许使用反引号(`)，可利用scp复制文件到远程服务器时，执行带有payload的scp命令，从而在后续利用中getshell。','OpenSSH','python','','2024-07-09 22:32:02');
INSERT INTO POC VALUES (30,'CVE-2016-3510','WebLogic T3 协议反序列化漏洞','代码注入','CVE-2016-3510漏洞是对CVE-2015-4852漏洞修复的绕过，攻击者在可以通过该漏洞实现远程命令执行。','WebLogic','python','Weblogic_CVE_2017_10271_RCE_test.py','2024-07-23 17:21:02');
INSERT INTO POC VALUES (31,'CVE-2018-6789','Exim 远程命令执行漏洞','远程代码执行 (RCE)','2018年2月，流行的开源邮件服务器Exim曝出了堆溢出漏洞（CVE-2018-6789），几乎影响了4.90.1之前的所有版本。可以利用该漏洞绕过各种缓解措施成功达成远程代码执行：','Exim','python','CVE_2018_6789.py','2024-07-23 21:39:02');
INSERT INTO POC VALUES (32,'CVE-2017-12617','Apache Tomcat PUT文件上传漏洞','远程代码执行 (RCE)','如果配置了默认servlet，则在9.0.1（Beta），8.5.23,8.0.47和7.0.82之前的所有Tomcat版本都包含所有操作系统上的潜在危险的远程执行代码（RCE）漏洞，CVE-2017-12617：远程代码执行漏洞。只需参数readonly设置为false或者使用参数readonly设置启用WebDAV servlet false。此配置将允许任何未经身份验证的用户上传文件（如WebDAV中所使用的）。只要JSP可以上传，然后就可以在服务器上执行。在一定条件下，攻击者可以利用这两个漏洞，获取用户服务器上 JSP 文件的源代码，或是通过精心构造的攻击请求，向用户服务器上传恶意JSP文件，通过上传的 JSP 文件 ，可在用户服务器上执行任意代码，从而导致数据泄露或获取服务器权限，存在高安全风险。','Apache Tomcat','python','CVE_2017_12617.py','2024-07-24 14:07:02');
INSERT INTO POC VALUES (33,'CVE-2017-12615','Apache Tomcat PUT 远程命令执行漏洞','远程代码执行 (RCE)','当 Tomcat 运行在 Windows 主机上，且启用了 HTTP PUT 请求方法（例如，将readonly 初始化参数由默认值设置为 false），攻击者将有可能可通过精心构造的攻击请求向服务器上传包含任意代码的 JSP 文件。之后，JSP 文件中的代码将能被服务器执行。','Apache Tomcat','python','CVE_2017_12615.py','2024-07-24 14:08:33');
INSERT INTO POC VALUES (34,'CVE-2017-10271','WebLogic XMLDecoder反序列化漏洞（CVE-2017-10271）','代码注入','Weblogic的WLS Security组件对外提供webservice服务，其中使用了XMLDecoder来解析用户传入的XML数据，在解析的过程中出现反序列化漏洞，导致可执行任意命令。','WebLogic','python','Weblogic_CVE_2017_10271_RCE_test.py','2024-07-24 15:51:33');
INSERT INTO POC VALUES (35,'CVE-2019-10149','Exim 远程代码执行漏洞','远程代码执行 (RCE)','在&nbsp;Exim versions 4.87 to 4.91（含）中发现了一个漏洞。 /src/deliver.c中的deliver_message（）函数中的收件人地址验证不正确可能导致远程命令执行。','Exim','python',NULL,'2024-07-25 16:51:30');
INSERT INTO POC VALUES (36,'CVE-2019-15107','Webmin <=1.920 password_change.cgi 远程命令执行漏洞','远程代码执行 (RCE)','Webmin是一套基于Web的用于类Unix操作系统中的系统管理工具。Webmin 1.920及之前版本中的password_change.cgi存在命令注入漏洞。该漏洞源于外部输入数据构造可执行命令过程中，网络系统或产品未正确过滤其中的特殊元素。攻击者可利用该漏洞执行非法命令。','Webmin','python',NULL,'2024-07-25 16:53:30');
INSERT INTO POC VALUES (37,'CVE-1234-test','Test Vulnerability','远程代码执行 (RCE)','This is a test vulnerability description.','0','python','','2024-07-20 18:51:06');

-- ----------------------------
-- Table structure for vulnType
-- ----------------------------
DROP TABLE IF EXISTS VulnType;
CREATE TABLE IF NOT EXISTS VulnType (
    ID INT AUTO_INCREMENT PRIMARY KEY,
    TypeName VARCHAR(255) UNIQUE NOT NULL -- 漏洞类型名称
);

INSERT IGNORE INTO VulnType (TypeName) VALUES 
('缓冲区溢出'),
('文件上传漏洞'),
('代码注入'),
('SQL 注入'),
('跨站脚本攻击 (XSS)'),
('权限提升'),
('拒绝服务攻击 (DoS)'),
('身份验证绕过'),
('路径遍历'),
('信息泄露'),
('跨站请求伪造 (CSRF)'),
('XML 外部实体注入 (XXE)'),
('远程代码执行 (RCE)'),
('会话劫持'),
('未经授权的访问'),
('其他类型');

-- 基线检查项基础表
CREATE TABLE `baseline_check_items` (
  `item_id` int NOT NULL COMMENT '检查项ID',
  `description` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '检查项描述',
  `basis` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '判定依据',
  `important_level` enum('1','2','3') CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '重要程度：1-低，2-中，3-高',
  PRIMARY KEY (`item_id`)
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '基线检查项基础表' ROW_FORMAT = Dynamic;

-- 插入基线检查项数据
INSERT INTO `baseline_check_items` VALUES 
(1, '检查口令生存周期', '<=90天', '3'),
(2, '检查口令最小长度', '>=8', '3'),
(3, '检查口令过期前警告天数', '>=30天', '3'),
(4, '检查设备密码复杂度策略', '至少包含1个大写字母、1个小写字母、1个数字、1个特殊字符', '3'),
(5, '检查是否存在空口令账号', '不存在空口令账号', '3'),
(6, '检查是否设置除root之外UID为0的用户', '普通用户的UID全为非0', '2'),
(7, '检查/etc/csh.cshrc中的用户umask设置', '=027 或 =077', '2'),
(8, '检查/etc/bashrc中的用户umask设置', '=027 或 =077', '2'),
(9, '检查/etc/profile中的用户umask设置', '=027 或 =077', '2'),
(10, '检查/etc/xinetd.conf文件权限', '<=600', '2'),
(11, '检查/etc/group文件权限', '<=644', '2'),
(12, '检查/etc/shadow文件权限', '<=400', '2'),
(13, '检查/etc/services文件权限', '<=644', '2'),
(14, '检查/etc/security目录权限', '<=600', '2'),
(15, '检查/etc/passwd文件权限', '<=644', '2'),
(16, '检查/etc/rc6.d目录权限', '<=750', '2'),
(17, '检查/etc/rc0.d目录权限', '<=750', '2'),
(18, '检查/etc/rc1.d目录权限', '<=750', '2'),
(19, '检查/etc/xinetd.conf文件权限', '<=750', '2'),
(20, '检查/etc目录权限', '<=750', '2'),
(21, '检查/etc/rc4.d目录权限', '<=750', '2'),
(22, '检查/etc/rc5.d目录权限', '<=750', '2'),
(23, '检查/etc/rc3.d目录权限', '<=750', '2'),
(24, '检查/etc/rc.d/init.d目录权限', '<=750', '2'),
(25, '检查/tmp目录权限', '<=750', '2'),
(26, '检查/etc/grub.conf文件权限', '<=600', '2'),
(27, '检查/etc/grub/grub.conf文件权限', '<=600', '2'),
(28, '检查/etc/lilo.conf文件权限', '<=600', '2'),
(29, '检查/etc/passwd的文件属性', '是否设置了i属性', '2'),
(30, '检查/etc/shadow的文件属性', '设置i属性', '2'),
(31, '检查/etc/group的文件属性', '设置i属性', '2'),
(32, '检查/etc/gshadow的文件属性', '设置i属性', '2'),
(33, '检查用户目录缺省访问权限设置', '=027', '3'),
(34, '检查是否设置ssh登录前警告Banner', '/etc/ssh/sshd_config 是否开启 Banner', '1'),
(35, '检查e-ng是否配置远程日志功能', '查找配置文件是否有相应行', '1'),
(36, 'rsyslog是否配置远程日志功能', '查找配置文件是否有相应行', '1'),
(37, 'syslog是否配置远程日志功能', '查找配置文件是否有相应行', '1'),
(38, 'syslog_ng是否配置安全事件日志', '查找配置文件是否有相应行', '1'),
(39, 'rsyslog_safe是否配置安全事件日志', '查找配置文件是否有相应行', '1'),
(40, 'rsyslog_safe是否配置安全事件日志', '查找配置文件是否有相应行', '1'),
(41, '检查/var/log/cron日志文件是否other用户不可写', 'other用户不可写', '1'),
(42, '检查/var/log/secure日志文件是否other用户不可写', 'other用户不可写', '1'),
(43, '检查/var/log/messages日志文件是否other用户不可写', 'other用户不可写', '1'),
(44, '检查/var/log/boot.log日志文件是否other用户不可写', 'other用户不可写', '1'),
(45, '检查/var/log/mail日志文件是否other用户不可写', 'other用户不可写', '1'),
(46, '检查/var/log/spooler日志文件是否other用户不可写', 'other用户不可写', '1'),
(47, '检查/var/log/localmessages日志文件是否other用户不可写', 'other用户不可写', '1'),
(48, '检查/var/log/maillog日志文件是否other用户不可写', 'other用户不可写', '1'),
(49, '是否对登录进行日志记录', 'last检查', '3'),
(50, '是否对su命令进行日志记录', '基于Debian或者RPM访问不同的文件', '1'),
(51, '检查系统openssh安全配置', '/etc/ssh/sshd_config中的Protocol配置值为2', '2'),
(52, '检查SNMP服务是否在运行', '查看是否存在SNMP进程', '2'),
(53, '检查是否已修改snmp默认团体字', '检查是否已修改snmp默认团体字', '2'),
(54, '是否配置ssh协议', '根据22号端口是否开放检测是否配置ssh协议', '3'),
(55, '由于telnet明文传输，所以应该禁止telnet协议', '根据23号端口是否开放检测是否配置telnet协议', '3'),
(56, '检查是否在运行ftp', '判断相应的服务是否后台运行', '2'),
(57, '检查是否禁止root用户登录ftp', '/etc/vsftpd/ftpusers文件中包含root用户即为禁止了', '2'),
(58, '检查是否禁止匿名用户登录FTP', '/etc/vsftpd/vsftpd.conf文件中是否存在anonymous_enable=NO配置', '3'),
(59, '检查是否设置命令行界面超时退出', '开启TMOUT且TMOUNT<=600秒', '3'),
(60, '检查是否设置系统引导管理器密码', '系统引导管理器（GRUB2、GRUB 或 LILO）应设置密码', '1'),
(61, '检查系统coredump设置', '在文件/etc/security/limits.conf中配置* hard core 0 和 * soft core 0', '2'),
(62, '检查历史命令设置', 'HISTFILESIZE 和 HISTSIZE 的值 <= 5', '1'),
(63, '检查是否使用PAM认证模块禁止wheel组之外的用户su为root', '在 /etc/pam.d/su 文件中配置: \n  auth sufficient pam_rootok.so \n  auth required pam_wheel.so group=wheel', '3'),
(64, '检查是否对系统账户进行登录限制', '请手动检查文件文件/etc/passwd，/etc/shadow，并使用命令：usermod -s /sbin/nologin username', '1'),
(65, '检查密码重复使用次数限制', '>=5', '2'),
(66, '检查账户认证失败次数限制', '登录失败限制可以使用pam_tally或pam.d，请手工检测/etc/pam.d/system-auth、/etc/pam.d/passwd、/etc/pam.d/common-auth文件。', '1'),
(67, '检查是否关闭绑定多ip功能', '/etc/host.conf中设置 multi off', '1'),
(68, '检查是否限制远程登录IP范围', '请手工查看/etc/hosts.allow和/etc/hosts.deny两个文件', '1'),
(69, '检查别名文件', '请手工查看/etc/aliases和/etc/mail/aliases两个文件', '1'),
(70, '检查重要文件是否存在suid和sgid权限', '重要文件应该不存在suid和sgid权限', '1'),
(71, '检查是否配置定时自动屏幕锁定（适用于图形化界面）', '在屏幕上面的面板中，打开"系统"-->"首选项"-->"屏幕保护程序"', '1'),
(72, '检查系统内核参数配置', '=1', '2'),
(73, '检查是否按组进行账号管理', '请手工查看/etc/group等文件', '1'),
(74, '检查root用户的path环境变量内容', '不包含（.和..）的路径', '2'),
(75, '检查系统是否禁用ctrl+alt+del组合键', '禁用Ctrl+Alt+Delete组合键重启系统', '2'),
(76, '检查是否关闭系统信任机制', '关闭系统信任机制', '3'),
(77, '检查系统磁盘分区使用率', '系统磁盘分区使用率均<=80%', '1'),
(78, '检查是否删除了潜在危险文件', '删除潜在危险文件，包括hosts.equiv文件 .rhosts文件和 .netrc 文件', '3'),
(79, '检查是否配置用户所需最小权限', '配置用户所需最小权限,/etc/passwd为644；/etc/group为644；/etc/shadow为600', '2'),
(80, '检查是否关闭数据包转发功能', '对于不做路由功能的系统，应该关闭数据包转发功能', '1'),
(81, '检查是否使用NTP（网络时间协议）保持时间同步', '检查ntp服务是否开启，若开启则需配置NTP服务器地址', '1'),
(82, '检查NFS（网络文件系统）服务设置', '如果需要NFS服务，需要限制能够访问NFS服务的IP范围；如果没有必要，需要停止NFS服务', '1'),
(83, '检查是否设置ssh成功登陆后Banner', '设置ssh成功登陆后Banner', '1'),
(84, '检查FTP用户上传的文件所具有的权限', '检查是否安装vsftpd或者pure-ftpd，且上传权限设置正确', '1'),
(85, '是否更改默认的ftp登陆警告Banner', '需要自己检查自定义的banner', '1'),
(86, '为了保证信息安全的可靠性，需要检查可执行文件的拥有者属性', '所有含有"s"属性的文件，把不必要的"s"属性去掉，或者把不用的直接删除。', '1'),
(87, '检查是否更改默认的telnet登录警告Banner', '请手动检查修改文件/etc/issue 和/etc/issue.net中的内容', '1'),
(88, '检查是否限制FTP用户登录后能访问的目录', '应该限制FTP用户登录后能访问的目录', '1'),
(89, '检查内核版本是否处于CVE-2021-43267漏洞影响版本', '内核版本不在5.10和5.14.16之间', '3');



DROP TABLE IF EXISTS `level3_security_check_items`;
CREATE TABLE `level3_security_check_items`  (
  `item_id` int(0) NOT NULL COMMENT '检查项ID',
  `description` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '检查项描述',
  `basis` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '判定依据',
  `important_level` enum('1','2','3') CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '重要程度：1-低，2-中，3-高',
  PRIMARY KEY (`item_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '等级保护三级安全检查项基础表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of level3_security_check_items
-- ----------------------------
INSERT INTO `level3_security_check_items` VALUES (1, '应在网络边界或区域之间根据访问控制策略设置访问控制规则，默认情况下除允许通信外受控接口拒绝所有通信', '防火墙应处于开启状态', '3');
INSERT INTO `level3_security_check_items` VALUES (2, '应删除多余或无效的访问控制规则，优化访问控制列表，并保证访问控制规则数量最小化', '防火墙规则应配置有效且完整', '3');
INSERT INTO `level3_security_check_items` VALUES (3, '应对源地址、目的地址、源端口、目的端口和协议等进行检查，以允许/拒绝数据包进出。', '防火墙应能检查源地址、目的地址、端口和协议信息', '3');
INSERT INTO `level3_security_check_items` VALUES (4, '应能根据会话状态信息为进出数据流提供明确的允许/拒绝访问能力', '会话状态访问控制机制应正确配置', '3');
INSERT INTO `level3_security_check_items` VALUES (5, '应对进出网络的数据流实现基于应用协议和应用内容的访问控制', '应配置基于应用协议和内容的访问控制规则', '3');
INSERT INTO `level3_security_check_items` VALUES (6, '应在关键网络节点处检测、防止或限制从外部发起的网络攻击行为', '应安装并启动IDS/IPS/WAF等防护工具', '3');
INSERT INTO `level3_security_check_items` VALUES (7, '应在关键网络节点处检测、防止或限制从内部发起的网络攻击行为', '应安装并启动IDS/IPS/WAF等防护工具', '3');
INSERT INTO `level3_security_check_items` VALUES (8, '应采取技术措施对网络行为进行分析实现对网络攻击特别是新型网络攻击行为的分析', '应运行网络行为分析系统服务', '3');
INSERT INTO `level3_security_check_items` VALUES (9, '当检测到攻击行为时，记录攻击源IP、攻击类型、攻击目标、攻击时间，在发生严重入侵事件时应提供报警', '应具备攻击行为记录和报警能力', '3');
INSERT INTO `level3_security_check_items` VALUES (10, '应在关键网络节点处对恶意代码进行检测和清除，并维护恶意代码防护机制的升级和更新', '应安装恶意代码防护软件', '3');
INSERT INTO `level3_security_check_items` VALUES (11, '应在关键网络节点处对垃圾邮件进行检测和防护，并维护垃圾邮件防护机制的升级和更新', '应安装邮件服务器并开启垃圾邮件防护', '3');

SET FOREIGN_KEY_CHECKS = 1;


-- ----------------------------
-- 资产组的表
-- ----------------------------
CREATE TABLE `asset_group` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `group_name` VARCHAR(255) NOT NULL UNIQUE COMMENT '资产组名称',
  `description` TEXT DEFAULT NULL COMMENT '资产组描述',
  `create_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `update_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;