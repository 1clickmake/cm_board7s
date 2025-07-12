<?php
include_once('./_common.php'); // member 폴더 기준 _common.php 경로

header('Content-Type: application/json');

$response = array(
    'status' => 'error',
    'message' => ''
);

if (!$is_member) {
    $response['message'] = '로그인 후 이용해주세요.';
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
    exit;
}

// 현재 로그인한 회원 정보
$user_id = $member['user_id']; // _common.php 에서 $member 배열에 로그인한 사용자 정보가 있다고 가정


if (empty($user_id)) {
    $response['message'] = '회원 정보를 찾을 수 없습니다.';
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
    exit;
}

// 회원정보 탈퇴 처리
    if (!$is_member) {
        $response['message'] = '회원만 이용하실 수 있습니다';
        echo json_encode($response, JSON_UNESCAPED_UNICODE);
        exit;
    }



    // 업데이트할 데이터 준비
    $update_data = [
        'user_lv' => 0,
        'user_leave' => 1,
        'user_leave_date' => date('Y-m-d H:i:s')
    ];


    // 데이터 업데이트
    try {
        $sql = "UPDATE cm_users SET ";
        $params = [];
        foreach ($update_data as $key => $value) {
            $sql .= "{$key} = :{$key}, ";
            $params[":{$key}"] = $value;
        }
        $sql = rtrim($sql, ", ");
        $sql .= " WHERE user_id = :user_id";
        $params[':user_id'] = $user_id;

        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
		
		// 세션 데이터 초기화
		$_SESSION = array();

		// 세션 쿠키 삭제
		if (isset($_COOKIE[session_name()])) {
			setcookie(session_name(), '', time()-3600, '/');
		}

		// 세션 파괴
		clearAllSessionData();

        $response['status'] = 'success';
        $response['message'] = '회원탈퇴가 완료되었습니다.';
    } catch (PDOException $e) {
        $response['message'] = '회원탈퇴 중 오류가 발생했습니다';
		$errorMessage = mb_convert_encoding($e->getMessage(), 'UTF-8', 'auto');
        error_log("회원탈퇴 오류: " . $errorMessage);
    }
	
	// JSON 응답 출력
echo json_encode($response, JSON_UNESCAPED_UNICODE);
exit;