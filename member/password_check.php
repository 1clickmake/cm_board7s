<?php
include_once('./_common.php');

header('Content-Type: application/json');

$response = array(
    'status' => 'error',
    'message' => ''
);

if (!$is_member) {
    $response['message'] = '회원만 이용하실 수 있습니다.';
    echo json_encode($response);
    exit;
}

$user_id = isset($_POST['user_id']) ? clean_xss_tags($_POST['user_id']) : '';
$user_password = isset($_POST['user_password']) ? $_POST['user_password'] : '';

if (empty($user_id) || empty($user_password)) {
    $response['message'] = '필수 입력값이 누락되었습니다.';
    echo json_encode($response);
    exit;
}

$sql = " select user_password from cm_users where user_id = '{$user_id}' and user_leave = 0 ";
$mb = sql_fetch($sql);

if (!$mb) {
    $response['message'] = '회원정보가 존재하지 않습니다.';
    echo json_encode($response);
    exit;
}

if (!password_verify($user_password, $mb['user_password'])) {
    $response['message'] = '비밀번호가 일치하지 않습니다.';
    echo json_encode($response);
    exit;
}

$response['status'] = 'success';
$response['message'] = '비밀번호가 확인되었습니다.';

echo json_encode($response);
