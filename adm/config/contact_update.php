<?php
include_once './_common.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
	// POST 방식이 아닌 접근은 허용하지 않습니다.
	alert('잘못된 접근 방식입니다.');
}

// 폼에서 넘어온 데이터.
$action = $_POST['action'] ?? '';
$id = $_POST['id'] ?? '';


// 업데이트 모드 처리
if($action === "update"){

	$contactData = [
		'read_chk' => 1,
		'read_chk_date' => date('Y-m-d H:i:s')
	];

	$whereConditions = [
		'id' => $id
	];

	$updateResult = process_data_update('cm_contact', $contactData, $whereConditions);

	// 결과 확인
	if ($updateResult !== false) {
		echo json_encode(['success' => true, 'message' => '읽음 처리 되었습니다.' ], JSON_UNESCAPED_UNICODE);
	} else {
		// 실패함수 내부에서 오류 로그는 남겼을 겁니다)
		echo json_encode(['success' => false, 'message' => '데이터 오류.'], JSON_UNESCAPED_UNICODE);
	}

}