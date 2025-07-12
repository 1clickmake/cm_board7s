<?php
define('_CMBOARD_', true);

// XSS 방지를 위한 함수
function clean_xss_tags($str) {
    $str = preg_replace('#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i', '', $str);
    return $str;
}

if (file_exists($_SERVER['DOCUMENT_ROOT'] .'/data/config.php')) {
	require_once $_SERVER['DOCUMENT_ROOT'] .'/data/config.php';
}else{
	
		// 데이터베이스 설정 파일이 없으면 설치 페이지로 리다이렉트
	if (!file_exists($_SERVER['DOCUMENT_ROOT'] .'/data/config.php')) {
		header('Location: install/index.php');
		exit;
	}

	// 설정 파일이 있더라도 데이터베이스 연결이 안되면 설치 페이지로 리다이렉트
	try {
		define('_CM_', true);
		require_once $_SERVER['DOCUMENT_ROOT'] .'/data/config.php';

		$db = CM_DB::getInstance();
	} catch (Exception $e) {
		header('Location: install/index.php');
		exit;
	}
}

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}


$scheme = isset($_SERVER['REQUEST_SCHEME']) ? $_SERVER['REQUEST_SCHEME'] : (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http');
$host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : $_SERVER['SERVER_NAME'];
$domain_url = $scheme . '://' . $host;

$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
$host = $_SERVER['HTTP_HOST'];
$request_uri = $_SERVER['REQUEST_URI'];
$current_url = $protocol . $host . $request_uri;

define('CM_PATH', $_SERVER['DOCUMENT_ROOT']);
define('CM_URL', $domain_url);

require_once(CM_PATH.'/config.php');//상수 선언
require_once(CM_LIB_PATH.'/common.lib.php'); // 공통 라이브러리

//관리자 환경설정
$sql = "SELECT * FROM `cm_config` WHERE `id` = :id";
$params_is = [':id' => 1]; // ':이름' => 값 형태
$config = sql_fetch($sql, $params_is);

// common.php 파일을 수정할 필요가 없도록 확장합니다.
$extend_file = array();
$tmp = dir(CM_EXTEND_PATH);
while ($entry = $tmp->read()) {
    // php 파일만 include 함
    if (preg_match("/(\.php)$/i", $entry))
        $extend_file[] = $entry;
}

if(!empty($extend_file) && is_array($extend_file)) {
    natsort($extend_file);

    foreach($extend_file as $file) {
        include_once(CM_EXTEND_PATH.'/'.$file);
    }
    unset($file);
}
unset($extend_file);


//회원설정
$is_admin = false;
$is_member = false;
$is_guest = true;
if(isset($_SESSION['user_id']) && $_SESSION['user_id'] !==""){
	$sql = "SELECT * FROM `cm_users` WHERE `user_id` = :user_id";
	$params = [':user_id' => $_SESSION['user_id']]; // ':이름' => 값 형태
	$member = sql_fetch($sql, $params);
	
	$is_guest = false;
	$is_member = true;
	
	if($config['admin_id'] == $member['user_id']){
		$is_admin = 'super';
	}
}

if ($is_admin != 'super') {
    // 접근가능 IP
    $ip_access = trim($config['ip_access']);
    if ($ip_access) {
        $is_ip_access = false;
        $pattern = explode("\n", $ip_access);
        for ($i=0; $i<count($pattern); $i++) {
            $pattern[$i] = trim($pattern[$i]);
            if (empty($pattern[$i]))
                continue;

            $pattern[$i] = str_replace(".", "\.", $pattern[$i]);
            $pattern[$i] = str_replace("+", "[0-9\.]+", $pattern[$i]);
            $pat = "/^{$pattern[$i]}$/";
            $is_ip_access = preg_match($pat, $_SERVER['REMOTE_ADDR']);
            if ($is_ip_access)
                break;
        }
        if (!$is_ip_access)
            die ("<meta charset=utf-8>접근이 가능하지 않습니다.");
    }

    // 접근차단 IP
    $is_ip_block = false;
    $pattern = explode("\n", trim($config['ip_block']));
    for ($i=0; $i<count($pattern); $i++) {
        $pattern[$i] = trim($pattern[$i]);
        if (empty($pattern[$i])){
            continue;
		}
        $pattern[$i] = str_replace(".", "\.", $pattern[$i]);
        $pattern[$i] = str_replace("+", "[0-9\.]+", $pattern[$i]);
        $pat = "/^{$pattern[$i]}$/";
        $is_ip_block = preg_match($pat, $_SERVER['REMOTE_ADDR']);
        if ($is_ip_block)
            die ("<meta charset=utf-8>접근 불가합니다.");
    }
	
	// 방문자 기록
	include_once(CM_LIB_PATH.'/visit_functions.php');
	get_visit();
}


//템플릿 관련 상수
define('CM_TEMPLATE_PATH', CM_PATH.'/template/community/'.$config['template_id']);
define('CM_TEMPLATE_URL', CM_URL.'/template/community/'.$config['template_id']);
define('CM_NAV_SKIN_PATH', CM_PATH.'/skin/nav/nav1');
define('CM_NAV_SKIN_URL', CM_URL.'/skin/nav/nav1');
define('CM_SLIDE_SKIN_PATH', CM_PATH.'/skin/slider/slider1/slider.php');

//쇼핑몰 템플릿 상수
define('CM_SHOP_TEMPLATE_PATH', CM_PATH.'/template/shop/'.$config['shop_template_id']);
define('CM_SHOP_TEMPLATE_URL', CM_URL.'/template/shop/'.$config['shop_template_id']);