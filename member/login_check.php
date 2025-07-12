<?php
include_once('./_common.php');

$cm_title = "로그인 검사";

// XSS 방지를 위한 입력값 필터링
$user_id = isset($_POST['user_id']) ? clean_xss_tags($_POST['user_id']) : '';
$user_password = isset($_POST['user_password']) ? clean_xss_tags($_POST['user_password']) : '';

// 입력값 검증
if (!$user_id || !$user_password) {
    die(json_encode(['status' => 'error', 'message' => '아이디와 비밀번호를 모두 입력해주세요.'], JSON_UNESCAPED_UNICODE));
}

// SQL Injection 방지를 위한 prepared statement 사용
$sql = "SELECT * FROM `cm_users` WHERE `user_id` = :user_id";
$params = [':user_id' => $user_id];
$member = sql_fetch($sql, $params);

if(isset($member['user_leave']) && $member['user_leave'] === 1){
	echo json_encode([
        'status' => 'error',
        'message' => '회원님은 '.$member['user_leave_date'].'에 탈퇴한 이력이 있으므로 로그인하실 수 없습니다.'
    ], JSON_UNESCAPED_UNICODE); exit;
}

if(isset($member['user_block']) && $member['user_block'] === 1){
	echo json_encode([
        'status' => 'error',
        'message' => '회원님은 '.$member['user_block_date'].'에 홈페이지 접속 차단 되어 로그인하실 수 없습니다.'
    ], JSON_UNESCAPED_UNICODE); exit;
}

// 로그인 시도 기록
$login_attempts = isset($_SESSION['login_attempts']) ? $_SESSION['login_attempts'] : 0;
$last_attempt_time = isset($_SESSION['last_attempt_time']) ? $_SESSION['last_attempt_time'] : 0;

// 로그인 시도 제한 (5회 실패시 15분 대기)
if ($login_attempts >= 5 && (time() - $last_attempt_time) < 900) {
    die(json_encode(['status' => 'error', 'message' => '로그인 시도가 너무 많습니다. 15분 후에 다시 시도해주세요.'], JSON_UNESCAPED_UNICODE));
}

if ($member && password_verify($user_password, $member['user_password'])) {
    
    // 세션 보안 설정
    session_regenerate_id(true); // 세션 ID 재생성
    
    // 로그인 시도 초기화
    $login_attempts = 0;
    $last_attempt_time = 0;
	
	// 로그인 성공 시 세션 생성
	$ssData = [
		'user_id' => $member['user_id'],
		'user_name' => $member['user_name'],
		'user_no' => $member['user_no'],
		'last_activity' => time(),
		'ip_address' => $_SERVER['REMOTE_ADDR'],
		'login_attempts' => $login_attempts,
		'last_attempt_time' => $last_attempt_time
	];
	setSessionData($ssData);
	
    // today_login 시간 업데이트
    $update_data = array(
        'today_login' => date('Y-m-d H:i:s')
    );
    $where = array(
        'user_no' => $member['user_no']
    );
    process_data_update('cm_users', $update_data, $where);
    
    // 로그인 성공 응답
    echo json_encode([
        'status' => 'success',
        'message' => '로그인되었습니다.',
        'redirect' => CM_URL
    ], JSON_UNESCAPED_UNICODE);
} else {
    // 로그인 실패 처리
    $_SESSION['login_attempts'] = $login_attempts + 1;
    $_SESSION['last_attempt_time'] = time();
    
    echo json_encode([
        'status' => 'error',
        'message' => '아이디 또는 비밀번호가 일치하지 않습니다.'
    ], JSON_UNESCAPED_UNICODE);
}

// 세션 보안을 위한 헤더 설정
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('X-Content-Type-Options: nosniff');
