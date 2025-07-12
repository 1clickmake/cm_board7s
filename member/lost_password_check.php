<?php
include_once('./_common.php');

header('Content-Type: application/json');

$response = array(
    'status' => 'error1',
    'message' => ''
);

$user_id = isset($_POST['user_id']) ? clean_xss_tags($_POST['user_id']) : '';
$user_email = isset($_POST['user_email']) ? clean_xss_tags($_POST['user_email']) : '';

if (empty($user_id) || empty($user_email)) {
    $response['message'] = '아이디와 이메일을 모두 입력해주세요.';
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
    exit;
}

$sql = " SELECT * FROM cm_users WHERE user_id = '{$user_id}' AND user_email = '{$user_email}'  ";
$mb = sql_fetch($sql);

if (!$mb) {
	$response['status'] = 'error';
    $response['message'] = '아이디 또는 이메일이 일치하지 않습니다.';
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
    exit;
}

if(isset($mb['user_leave']) && $mb['user_leave'] === 1){
	$response['status'] = 'error';
    $response['message'] = '회원님은 '.$mb['user_leave_date'].'에 탈퇴한 이력이 있습니다.';
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
    exit;
}

if(isset($mb['user_block']) && $mb['user_block'] === 1){
	$response['status'] = 'error';
    $response['message'] = '회원님은 '.$mb['user_block_date'].'에 홈페이지 접속 차단이 되어 있습니다.';
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
    exit;
}

// 임시 비밀번호 생성 (8자리 랜덤 문자열)
$temp_password = substr(str_shuffle('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'), 0, 8);

// 임시 비밀번호 해시 처리
$hashed_temp_password = password_hash($temp_password, PASSWORD_DEFAULT);

// 데이터베이스에 임시 비밀번호 저장
try {
	
	$update_data = [
		'user_password' => $hashed_temp_password
	];

	$whereConditions = [
        'user_id' => $user_id,
        'user_email' => $user_email
    ];
		
	process_data_update('cm_users', $update_data, $whereConditions);
	
	$response['status'] = 'success';
	$response['message'] = '임시 비밀번호가 생성되었습니다.';
	$response['temp_password'] = $temp_password;


} catch (PDOException $e) {
	$response['status'] = 'error';
	$response['message'] = '임시 비밀번호 발행중 오류가 발생했습니다';
	$errorMessage = mb_convert_encoding($e->getMessage(), 'UTF-8', 'auto');
	error_log("임시 비밀번호 오류: " . $errorMessage);
}

echo json_encode($response, JSON_UNESCAPED_UNICODE);