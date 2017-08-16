/*
Navicat MySQL Data Transfer

Source Server         : localhost
Source Server Version : 50515
Source Host           : 127.0.0.1:3306
Source Database       : test

Target Server Type    : MYSQL
Target Server Version : 50515
File Encoding         : 65001

Date: 2017-08-07 22:43:07
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for syspermission
-- ----------------------------
DROP TABLE IF EXISTS `syspermission`;
CREATE TABLE `syspermission` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `available` bit(1) DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  `parentId` bigint(20) DEFAULT NULL,
  `parentIds` varchar(255) DEFAULT NULL,
  `permission` varchar(255) DEFAULT NULL,
  `resourceType` enum('menu','button') DEFAULT NULL,
  `url` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of syspermission
-- ----------------------------
INSERT INTO `syspermission` VALUES ('1', '', '用户管理', '0', '0/', 'userInfo:view', 'menu', 'userInfo/userList');
INSERT INTO `syspermission` VALUES ('2', '', '用户添加', '1', '0/1', 'userInfo:add', 'button', 'userInfo/userAdd');
INSERT INTO `syspermission` VALUES ('3', '', '用户删除', '1', '0/1', 'userInfo:del', 'button', 'userInfo/userDel');

-- ----------------------------
-- Table structure for sysrole
-- ----------------------------
DROP TABLE IF EXISTS `sysrole`;
CREATE TABLE `sysrole` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `available` bit(1) DEFAULT NULL,
  `description` varchar(255) DEFAULT NULL,
  `role` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of sysrole
-- ----------------------------
INSERT INTO `sysrole` VALUES ('1', '', '管理员', 'admin');
INSERT INTO `sysrole` VALUES ('2', '', 'VIP会员', 'vip');

-- ----------------------------
-- Table structure for sysrolepermission
-- ----------------------------
DROP TABLE IF EXISTS `sysrolepermission`;
CREATE TABLE `sysrolepermission` (
  `roleId` bigint(20) NOT NULL,
  `permissionId` bigint(20) NOT NULL,
  KEY `FK_pn90qffgw1e6lo1xhw964qadf` (`roleId`),
  KEY `FK_qr3wmwfxapktvdv5g6d4mbtta` (`permissionId`),
  CONSTRAINT `FK_pn90qffgw1e6lo1xhw964qadf` FOREIGN KEY (`roleId`) REFERENCES `sysrole` (`id`),
  CONSTRAINT `FK_qr3wmwfxapktvdv5g6d4mbtta` FOREIGN KEY (`permissionId`) REFERENCES `syspermission` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of sysrolepermission
-- ----------------------------
INSERT INTO `sysrolepermission` VALUES ('1', '1');
INSERT INTO `sysrolepermission` VALUES ('1', '2');

-- ----------------------------
-- Table structure for sysuserrole
-- ----------------------------
DROP TABLE IF EXISTS `sysuserrole`;
CREATE TABLE `sysuserrole` (
  `uid` bigint(20) NOT NULL,
  `roleId` bigint(20) NOT NULL,
  KEY `FK_io5ssq2ol6uqcx9nll8gfnm4n` (`uid`),
  KEY `FK_suwqmd7mystg1lwv8o4ffxaag` (`roleId`),
  CONSTRAINT `FK_io5ssq2ol6uqcx9nll8gfnm4n` FOREIGN KEY (`uid`) REFERENCES `userinfo` (`uid`),
  CONSTRAINT `FK_suwqmd7mystg1lwv8o4ffxaag` FOREIGN KEY (`roleId`) REFERENCES `sysrole` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of sysuserrole
-- ----------------------------
INSERT INTO `sysuserrole` VALUES ('1', '1');
INSERT INTO `sysuserrole` VALUES ('1', '2');

-- ----------------------------
-- Table structure for userinfo
-- ----------------------------
DROP TABLE IF EXISTS `userinfo`;
CREATE TABLE `userinfo` (
  `uid` bigint(20) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  `username` varchar(255) DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `salt` varchar(255) DEFAULT NULL,
  `state` tinyint(4) NOT NULL,
  PRIMARY KEY (`uid`),
  UNIQUE KEY `UK_45fvrme4q2wy85b1vbf55hm6s` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of userinfo
-- ----------------------------
INSERT INTO `userinfo` VALUES ('1', '管理员', 'admin', 'd3c59d25033dbf980d29554025c23a75', '8d78869f470951332959580424d4bf4f', '0');
