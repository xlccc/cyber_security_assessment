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


SET FOREIGN_KEY_CHECKS = 1;