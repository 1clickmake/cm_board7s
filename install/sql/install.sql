--
-- 테이블 구조 `cm_board` 
--

DROP TABLE IF EXISTS `cm_board`;
CREATE TABLE `cm_board` (
  `board_num` int(11) NOT NULL auto_increment,
  `group_id` varchar(255) NOT NULL default '',
  `board_id` varchar(255) NOT NULL default '',
  `notice_chk` tinyint(4) NOT NULL DEFAULT '0' COMMENT '공지 1',
  `reply_chk` tinyint(4) NOT NULL DEFAULT '0' COMMENT '댓글허용 1',
  `comment_chk` tinyint(4) NOT NULL DEFAULT '0' COMMENT '코멘트등록1',
  `secret_chk` tinyint(4) NOT NULL DEFAULT '0' COMMENT '비밀글체크',
  `category` varchar(255) NOT NULL default '',
  `parent_num` int(11) NOT NULL DEFAULT '0',
  `reply_depth` int(11) NOT NULL DEFAULT '0',
  `reply_order` int(11) NOT NULL DEFAULT '0',
  `thread_id` int(11) NOT NULL DEFAULT '0',
  `user_id` varchar(255) NOT NULL default '',
  `email` varchar(255) NOT NULL default '',
  `name` varchar(255) NOT NULL default '',
  `password` varchar(255) NOT NULL default '',
  `title` varchar(255) NOT NULL default '',
  `tags` varchar(255) NOT NULL default '',
  `content` text NOT NULL,
  `ip` varchar(255) NOT NULL default '',
  `view_count` int(11) NOT NULL DEFAULT '0' COMMENT 'hit 수',
  `good` int(11) NOT NULL DEFAULT '0' COMMENT '종아요',
  `bad` int(11) NOT NULL DEFAULT '0' COMMENT '싫어요',
  `reg_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `update_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `add_col_1` varchar(255) NOT NULL default '',
  `add_col_2` varchar(255) NOT NULL default '',
  `add_col_3` varchar(255) NOT NULL default '',
  `add_col_4` varchar(255) NOT NULL default '',
  `add_col_5` varchar(255) NOT NULL default '',
  `add_col_6` varchar(255) NOT NULL default '',
  `add_col_7` varchar(255) NOT NULL default '',
  `add_col_8` varchar(255) NOT NULL default '',
  `add_col_9` varchar(255) NOT NULL default '',
  `add_col_10` varchar(255) NOT NULL default '',
  PRIMARY KEY  (`board_num`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 테이블 구조 `cm_board_comment`
--

DROP TABLE IF EXISTS `cm_board_comment`;
CREATE TABLE `cm_board_comment` (
  `comment_id` int(11) NOT NULL auto_increment,
  `board_id` varchar(255) NOT NULL default '',
  `board_num` int(11) NOT NULL DEFAULT '0',
  `user_id` varchar(255) NOT NULL default '',
  `name` varchar(255) NOT NULL default '',
  `email` varchar(255) NOT NULL default '',
  `password` varchar(255) NOT NULL default '',
  `content` text NOT NULL,
  `ip` varchar(255) NOT NULL default '',
  `reg_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `update_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY  (`comment_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 테이블 구조 `cm_board_file`
--

DROP TABLE IF EXISTS `cm_board_file`;
CREATE TABLE `cm_board_file` (
  `file_id` int(11) NOT NULL auto_increment,
  `board_id` varchar(255) NOT NULL default '',
  `board_num` int(11) NOT NULL DEFAULT '0',
  `original_filename` varchar(255) NOT NULL default '',
  `stored_filename` varchar(255) NOT NULL default '',
  `file_size` int(11) NOT NULL DEFAULT '0',
  `file_type` varchar(255) NOT NULL default '',
  `reg_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY  (`file_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 테이블 구조 `cm_board_group`
--

DROP TABLE IF EXISTS `cm_board_group`;
CREATE TABLE `cm_board_group` (
  `group_id` varchar(255) NOT NULL default '',
  `group_name` varchar(255) NOT NULL default '',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY  (`group_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 테이블 구조 `cm_board_list`
--

DROP TABLE IF EXISTS `cm_board_list`;
CREATE TABLE `cm_board_list` (
  `board_id` varchar(255) NOT NULL default '',
  `board_name` varchar(255) NOT NULL default '',
  `group_id` varchar(255) NOT NULL default '',
  `group_name` varchar(255) NOT NULL default '',
  `board_skin` varchar(255) NOT NULL default 'basic',
  `board_category` text NOT NULL,
  `write_lv` int(11) NOT NULL default '0',
  `list_lv` int(11) NOT NULL default '0',
  `view_lv` int(11) NOT NULL default '0',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY  (`board_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


--
-- 테이블 구조 `cm_config`
--

DROP TABLE IF EXISTS `cm_config`;
-- 사이트 설정 정보를 저장하는 테이블
-- 주요 사이트 설정, SNS 링크, API 키 등을 관리
CREATE TABLE `cm_config` (
  `id` int(11) NOT NULL auto_increment,
  `admin_id` varchar(255) NOT NULL default '',
  `site_title` varchar(255) NOT NULL default '',
  `representative_name` varchar(255) NOT NULL default '' COMMENT '대표자명',
  `contact_number` varchar(255) NOT NULL default '' COMMENT '고객센터',
  `fax_number` varchar(255) NOT NULL default '' COMMENT 'fax',
  `admin_email` varchar(255) NOT NULL default '',
  `business_address` text NOT NULL COMMENT '사업장 주소',
  `operating_hours` text NOT NULL COMMENT '운영시간',
  `privacy_manager` varchar(255) NOT NULL default '' COMMENT '개인정보보호 책임자',
  `business_reg_no` varchar(255) NOT NULL default '' COMMENT '사업자번호',
  `online_sales_no` varchar(255) NOT NULL default '' COMMENT '통신판매신고번호',
  `business_type` varchar(255) NOT NULL default '' COMMENT '업태',
  `business_category` varchar(255) NOT NULL default '' COMMENT '종목',
  `bank_name` varchar(255) NOT NULL default '' COMMENT '입금계좌 은행명',
  `account_holder` varchar(255) NOT NULL default '' COMMENT '입금계좌 예금주',
  `account_number` varchar(255) NOT NULL default '' COMMENT '입금계좌 계좌번호',
  `add_meta` text NOT NULL COMMENT '추가 메타 태그 (head 태그 내에 추가될 메타 태그)',
  `add_js` text NOT NULL COMMENT '추가 JavaScript 코드 (페이지 하단에 추가될 스크립트 코드)',
  `template_id` varchar(255) NOT NULL default '' COMMENT '사용 중인 템플릿 ID',
  `shop_template_id` varchar(255) NOT NULL default '' COMMENT '쇼핑몰 템플릿 ID',
  `ip_access` text NOT NULL COMMENT '접근가능 IP',
  `ip_block` text NOT NULL COMMENT '접근차단 IP',
  `google_email` varchar(255) NOT NULL default '' COMMENT '구글계정 이메일',
  `google_appkey` varchar(255) NOT NULL default '' COMMENT 'Gmail App Key',
  `recaptcha_site_key` varchar(255) NOT NULL default '' COMMENT '구글캡챠 사이트키',
  `recaptcha_secret_key` varchar(255) NOT NULL default '' COMMENT '구글캡챠 시크릿키',
  `google_map_iframe_src` text NOT NULL COMMENT '구글 지도 iframe src',
  `cf_original_lang` varchar(255) NOT NULL default 'KO' COMMENT '사이트 기본 언어',
  `deepl_api_use` tinyint(4) NOT NULL default '0' COMMENT 'DeepL 사용1',
  `deepl_api_key` varchar(255) NOT NULL default '' COMMENT 'DeepL API Key',
  `deepl_api_plan` varchar(255) NOT NULL default '' COMMENT 'DeepL API 플랜',
  `pwa_use` tinyint(4) NOT NULL default '0' COMMENT 'PWA 사용1',
  `pwa_vapid_public_key` varchar(255) NOT NULL default '' COMMENT 'PWA VAPID 공개 키',
  `pwa_vapid_private_key` varchar(255) NOT NULL default '' COMMENT 'PWA VAPID 비공개 키',
  `sns_facebook` varchar(255) NOT NULL default '' COMMENT '페이스북 SNS 링크',
  `sns_x` varchar(255) NOT NULL default '' COMMENT 'X(트위터) SNS 링크',
  `sns_kakao` varchar(255) NOT NULL default '' COMMENT '카카오톡 SNS 링크',
  `sns_naver` varchar(255) NOT NULL default '' COMMENT '네이버 블로그/카페 링크',
  `sns_line` varchar(255) NOT NULL default '' COMMENT '라인 SNS 링크',
  `sns_pinterest` varchar(255) NOT NULL default '' COMMENT '핀터레스트 SNS 링크',
  `sns_linkedin` varchar(255) NOT NULL default '' COMMENT '링크드인 SNS 링크',
  `cf_add_sub_1` varchar(255) NOT NULL default '' COMMENT '여분필드 1 제목 (사용자 정의 필드)',
  `cf_add_con_1` varchar(255) NOT NULL default '' COMMENT '여분필드 1 내용 (사용자 정의 값)',
  `cf_add_sub_2` varchar(255) NOT NULL default '' COMMENT '여분필드 2 제목 (사용자 정의 필드)',
  `cf_add_con_2` varchar(255) NOT NULL default '' COMMENT '여분필드 2 내용 (사용자 정의 값)',
  `cf_add_sub_3` varchar(255) NOT NULL default '' COMMENT '여분필드 3 제목 (사용자 정의 필드)',
  `cf_add_con_3` varchar(255) NOT NULL default '' COMMENT '여분필드 3 내용 (사용자 정의 값)',
  `cf_add_sub_4` varchar(255) NOT NULL default '' COMMENT '여분필드 4 제목 (사용자 정의 필드)',
  `cf_add_con_4` varchar(255) NOT NULL default '' COMMENT '여분필드 4 내용 (사용자 정의 값)',
  `cf_add_sub_5` varchar(255) NOT NULL default '' COMMENT '여분필드 5 제목 (사용자 정의 필드)',
  `cf_add_con_5` varchar(255) NOT NULL default '' COMMENT '여분필드 5 내용 (사용자 정의 값)',
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


--
-- 테이블 구조 `cm_contact`
--

DROP TABLE IF EXISTS `cm_contact`;
CREATE TABLE `cm_contact` (
  `id` int(11) NOT NULL auto_increment,
  `name`  varchar(255) NOT NULL default '',
  `email`  varchar(255) NOT NULL default '',
  `phone`  varchar(255) NOT NULL default '',
  `subject`  varchar(255) NOT NULL default '',
  `message` text NOT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `read_chk` tinyint(4) NOT NULL default '0',
  `read_chk_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 테이블 구조 `cm_content`
--

DROP TABLE IF EXISTS `cm_content`;
CREATE TABLE `cm_content` (
  `id` int(11) NOT NULL auto_increment,
  `co_id` varchar(255) NOT NULL default '',
  `co_subject` varchar(255) NOT NULL default '',
  `co_content` longtext NOT NULL,
  `co_editor` tinyint(4) NOT NULL default '0' COMMENT '에디터선택 0 기본',
  `co_width` int(11) NOT NULL default '1' COMMENT 'width = 1 = full',
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


--
-- 테이블 구조 `cm_menu`
--

DROP TABLE IF EXISTS `cm_menu`;
CREATE TABLE `cm_menu` (
  `menu_id` int(11) NOT NULL auto_increment,
  `parent_id` int(11) NOT NULL default '1',
  `menu_name` varchar(100) NOT NULL,
  `menu_url` varchar(255) NOT NULL default '',
  `menu_icon` varchar(255) NOT NULL default '',
  `target_blank` tinyint(1) DEFAULT 0,
  `is_disabled` tinyint(1) DEFAULT 0,
  `menu_level` tinyint(4) NOT NULL default '0' COMMENT '메뉴의 중첩 레벨 (1부터 무제한)',
  `sort_order` int(4) NOT NULL default '0' COMMENT '동일 상위 메뉴 내 출력 순서',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY  (`menu_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


--
-- 테이블 구조 `cm_point`
--

DROP TABLE IF EXISTS `cm_point`;
CREATE TABLE `cm_point` (
  `id` int(11) NOT NULL auto_increment,
  `user_id` varchar(255) NOT NULL default '' COMMENT '회원 아이디',
  `point` int(11) NOT NULL default '0' COMMENT '포인트',
  `description` varchar(255) NOT NULL default '' COMMENT '포인트 지급/삭제 사유',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP  COMMENT '등록일',
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


--
-- 테이블 구조 `cm_popup`
--

DROP TABLE IF EXISTS `cm_popup`;
CREATE TABLE `cm_popup` (
  `po_id` int(11) NOT NULL auto_increment,
  `po_title` varchar(255) NOT NULL default '' COMMENT '팝업제목',
  `po_content` text NOT NULL COMMENT '팝업내용',
  `po_top` int(11) NOT NULL default '0'  COMMENT '상단위치',
  `po_left` int(11) NOT NULL default '0'  COMMENT '좌측위치',
  `po_width` int(11) NOT NULL default '0'  COMMENT '가로사이즈',
  `po_height` int(11) NOT NULL default '0'  COMMENT '세로사이즈',
  `po_start_date` date NOT NULL  COMMENT '시작일',
  `po_end_date` date NOT NULL  COMMENT '종료일',
  `po_cookie_time` int(11) NOT NULL default '24' COMMENT '쿠키 유지시간(시간)',
  `po_url` varchar(255) NOT NULL default '' COMMENT '팝업 URL',
  `po_target` varchar(255) NOT NULL default '' COMMENT '_blank' COMMENT '타겟(_blank, _self)',
  `po_use` tinyint(4) NOT NULL default '0' COMMENT '사용여부(1:사용, 0:미사용)',
  `po_reg_date` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP  COMMENT '등록일',
  PRIMARY KEY  (`po_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8  COMMENT='팝업레이어 관리';


--
-- 테이블 구조 `cm_users`
--

DROP TABLE IF EXISTS `cm_users`;
CREATE TABLE `cm_users` (
  `user_no` int(11) NOT NULL auto_increment COMMENT '순번',
  `user_id`  varchar(255) NOT NULL default '' COMMENT '회원아이디',
  `user_name`  varchar(255) NOT NULL default '' COMMENT '이름',
  `user_password`  varchar(255) NOT NULL default '' COMMENT '패스워드',
  `user_email`  varchar(255) NOT NULL default '' COMMENT '이메일',
  `user_hp`  varchar(255) NOT NULL default '' COMMENT '휴대폰',
  `user_lv` int(11) NOT NULL default '0' COMMENT '회원레벨',
  `user_point` int(11) NOT NULL default '0',
  `user_block` int(11) NOT NULL default '0' COMMENT '회원차단1',
  `user_block_date` datetime NULL COMMENT '차단일자',
  `user_leave` int(11) NOT NULL default '0' COMMENT '회원탈퇴1',
  `user_leave_date` datetime NULL COMMENT '회원탈퇴일',
  `user_recommend` varchar(255) NOT NULL default '',
  `created_at`  datetime NOT NULL DEFAULT CURRENT_TIMESTAMP  COMMENT '가입일',
  `today_login` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP  COMMENT '로그인 시간',
  PRIMARY KEY  (`user_no`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


--
-- 테이블 구조 `cm_visit`
--

DROP TABLE IF EXISTS `cm_visit`;
CREATE TABLE `cm_visit` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `ip_address`  varchar(255) NOT NULL default '',
  `ip_country`  varchar(255) NOT NULL default '',
  `ip_countryCode`  varchar(255) NOT NULL default '',
  `ip_city`  varchar(255) NOT NULL default '',
  `ip_isp`  varchar(255) NOT NULL default '',
  `visit_time`  datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ,
  `user_agent` text DEFAULT NULL,
  `referer` text DEFAULT NULL,
  `visit_count` int(11) NOT NULL default '1',
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 테이블 구조 `cm_email_log`
--

DROP TABLE IF EXISTS `cm_email_log`;
CREATE TABLE IF NOT EXISTS `cm_email_log` (
  `log_id` int(11) NOT NULL AUTO_INCREMENT,
  `sender_id` varchar(255) NOT NULL DEFAULT '' COMMENT '발송자 ID',
  `recipient_type` enum('all','level','individual') NOT NULL COMMENT '수신자 타입',
  `recipients` text NOT NULL COMMENT '수신자 목록 (JSON)',
  `subject` varchar(255) NOT NULL DEFAULT '' COMMENT '이메일 제목',
  `content` longtext NOT NULL COMMENT '이메일 내용',
  `attachments` text NOT NULL COMMENT '첨부파일 목록 (JSON)',
  `success_count` int(11) NOT NULL DEFAULT 0 COMMENT '성공 발송 수',
  `fail_count` int(11) NOT NULL DEFAULT 0 COMMENT '실패 발송 수',
  `error_messages` text COMMENT '오류 메시지 (JSON)',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '발송 시간',
  PRIMARY KEY (`log_id`),
  KEY `idx_sender_id` (`sender_id`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='이메일 발송 로그'; 

--
-- 테이블의 덤프 데이터 `cm_board_list`
--

INSERT INTO `cm_board_list` (`board_id`, `board_name`, `group_id`, `group_name`, `board_skin`, `board_category`, `write_lv`, `list_lv`, `view_lv`, `created_at`) VALUES
('gallery', 'gallery', 'community', '커뮤니티', 'gallery', '', 2, 2, 2, NOW()),
('notice', '공지사항', 'community', '커뮤니티', 'basic', '', 2, 2, 2, NOW());



--
-- 테이블의 덤프 데이터 `cm_board_group`
--

INSERT INTO `cm_board_group` (`group_id`, `group_name`, `created_at`) VALUES
('community',	'커뮤니티',	NOW());

--
-- 테이블의 덤프 데이터 `cm_menu`
--

INSERT INTO `cm_menu` (`menu_id`, `parent_id`, `menu_name`, `menu_url`, `menu_icon`, `target_blank`, `is_disabled`, `menu_level`, `sort_order`, `created_at`, `updated_at`) VALUES
(6, 0, 'menu1', '', '<i class=\"bi bi-bank\"></i>', 1, 0, 1, 1, NOW(), NOW()),
(20, 18, 'menu2-1-1', '', '', 0, 0, 3, 1, NOW(), NOW()),
(21, 18, 'menu2-1-2', '', '', 0, 0, 3, 2, NOW(), NOW()),
(22, 0, 'notice', './board/list.php?board=notice', '', 0, 0, 1, 1, NOW(), NOW());
(23, 0, 'gallery', './board/list.php?board=gallery', '', 0, 0, 1, 1, NOW(), NOW());

--
-- 테이블의 덤프 데이터 `cm_users`
--

INSERT INTO `cm_users` (`user_no`, `user_id`, `user_name`, `user_password`, `user_email`, `user_hp`, `user_lv`, `user_point`, `user_block`, `user_block_date`, `user_leave`, `user_leave_date`, `user_recommend`, `created_at`, `today_login`) VALUES
(1, '', '', '', '', '', 10, 0, 0, NULL, 0, NULL, '', NOW(), NOW());


--
-- 테이블의 덤프 데이터 `cm_config`
--

INSERT INTO `cm_config` (`id`, `admin_id`, `cf_original_lang`, `site_title`, `admin_email`, `contact_number`, `fax_number`, `add_meta`, `add_js`, `template_id`, `shop_template_id`, `ip_access`, `ip_block`, `recaptcha_site_key`, `recaptcha_secret_key`, `google_map_iframe_src`, `deepl_api_use`, `deepl_api_key`, `deepl_api_plan`, `pwa_use`, `pwa_vapid_public_key`, `pwa_vapid_private_key`, `business_reg_no`, `online_sales_no`, `representative_name`, `privacy_manager`, `business_address`, `business_type`, `business_category`, `operating_hours`, `bank_name`, `account_holder`, `account_number`, `sns_facebook`, `sns_x`, `sns_kakao`, `sns_naver`, `sns_line`, `sns_pinterest`, `sns_linkedin`, `cf_add_sub_1`, `cf_add_con_1`, `cf_add_sub_2`, `cf_add_con_2`, `cf_add_sub_3`, `cf_add_con_3`, `cf_add_sub_4`, `cf_add_con_4`, `cf_add_sub_5`, `cf_add_con_5`, `updated_at`) VALUES
(1,	'',	'KO',	'CM_BOARD',	'',	'',	'',	'',	'',	'basic', 'shop_basic',	'',	'',	'',	'',	'',	0,	'',	'free',	0,	'',	'',	'',	'',	'',	'',	'',	'',	'',	'',	'',	'',	'',	'',	'',	'',	'',	'',	'',	'',	'',	'',	'',	'', '',	'',	'',	'',	'',	'',	NOW());


--
-- 테이블 구조 `cm_order`
--

DROP TABLE IF EXISTS `cm_order`;
CREATE TABLE `cm_order` (
  `order_id` int(11) NOT NULL auto_increment,
  `user_id` varchar(255) NOT NULL default '',
  `payment_id` varchar(255) NOT NULL default '',
  `subscription_id` varchar(255) NOT NULL default '',
  `payment_type` varchar(50) NOT NULL default 'payment' COMMENT 'payment or subscription',
  `amount` decimal(10,2) NOT NULL default '0.00',
  `currency` varchar(10) NOT NULL default 'USD',
  `status` varchar(50) NOT NULL default 'pending',
  `payer_id` varchar(255) NOT NULL default '',
  `payer_email` varchar(255) NOT NULL default '',
  `payer_name` varchar(255) NOT NULL default '',
  `description` text NOT NULL,
  `plan_id` varchar(255) NOT NULL default '',
  `plan_name` varchar(255) NOT NULL default '',
  `plan_interval` varchar(50) NOT NULL default '',
  `plan_amount` decimal(10,2) NOT NULL default '0.00',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ,
  PRIMARY KEY  (`order_id`),
  KEY `payment_id` (`payment_id`),
  KEY `subscription_id` (`subscription_id`),
  KEY `user_id` (`user_id`),
  KEY `status` (`status`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;