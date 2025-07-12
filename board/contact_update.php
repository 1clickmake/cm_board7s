<?php
include_once './_common.php';

// JSON 응답을 위한 헤더 설정
header('Content-Type: application/json');

// POST 요청인지 확인
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Invalid request method.']);
    exit;
}

// 데이터 가져오기 및 기본적인 유효성 검사
$name = isset($_POST['name']) ? trim($_POST['name']) : '';
$email = isset($_POST['email']) ? trim($_POST['email']) : '';
$phone = isset($_POST['phone']) ? trim($_POST['phone']) : '';
$subject = isset($_POST['subject']) ? trim($_POST['subject']) : '';
$message = isset($_POST['message']) ? trim($_POST['message']) : '';

if (empty($name) || empty($email) || empty($phone) || empty($subject) || empty($message)) {
    echo json_encode(['success' => false, 'message' => '모든 항목은 필수로 입력해주세요.'], JSON_UNESCAPED_UNICODE);
    exit;
}

// 삽입할 데이터 준비
    $contactData = [
        'name' => $name,
        'email' => $email,
		'phone' => $phone,
        'subject' => $subject,
        'message' => $message,
		'created_at' => date('Y-m-d H:i:s')
    ];

    // 데이터 삽입 함수 호출
    $insert_result = process_data_insert('cm_contact', $contactData);

    // 삽입 결과 확인
    if ($insert_result !== false) {
        $response['success'] = true;
        $response['message'] = '상담글이 등록되었습니다. 빠른 시간내에 답변드리겠습니다.';

    } else {
		$response['success'] = false;
        $response['message'] = '상담글 처리 중 오류가 발생했습니다1';
    }
	
// JSON 응답 출력
echo json_encode($response, JSON_UNESCAPED_UNICODE);
exit;