<?php
include_once('./_common.php');

$cm_title = "로그아웃";

// 로그인 상태 확인
if (!isset($_SESSION['user_id'])) {
    alert('이미 로그아웃 되었습니다.', CM_URL);
    exit;
}

// 세션 데이터 초기화
$_SESSION = array();

// 세션 쿠키 삭제
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time()-3600, '/');
}

// 세션 파괴
clearAllSessionData();

// 로그인 페이지로 리다이렉트
alert('로그아웃 되었습니다.', CM_URL);
exit;