<?php
include_once './_common.php';

// JSON 응답 헤더
header('Content-Type: application/json');

// PHP 에러 출력 비활성화
ini_set('display_errors', 0);
error_reporting(E_ALL);

// 응답 초기화
$response = [
    'status' => 'error',
    'message' => '',
    'field' => ''
];

// AJAX 요청 확인
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $response['message'] = '올바른 접근 방식이 아닙니다';
    echo json_encode($response);
    exit;
}

// 입력값 검증
$board_id = isset($_POST['board_id']) ? trim($_POST['board_id']) : '';
$board_num = isset($_POST['board_num']) ? intval($_POST['board_num']) : 0;
$email = isset($_POST['email']) ? trim($_POST['email']) : '';
$input_password = isset($_POST['password']) ? trim($_POST['password']) : '';

if (empty($board_id)) {
    $response['message'] = '게시판 ID가 누락되었습니다';
    echo json_encode($response);
    exit;
}

if ($board_num <= 0) {
    $response['message'] = '게시글 번호가 유효하지 않습니다';
    echo json_encode($response);
    exit;
}

if (empty($input_password)) {
    $response['message'] = '비밀번호를 입력해주세요';
    $response['field'] = 'password';
    echo json_encode($response);
    exit;
}

if (!$is_member && empty($email)) {
    $response['message'] = '이메일을 입력해주세요';
    $response['field'] = 'email';
    echo json_encode($response);
    exit;
}

if (!$is_member && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $response['message'] = '유효한 이메일 주소를 입력해주세요';
    $response['field'] = 'email';
    echo json_encode($response);
    exit;
}

try {
    // 게시글 정보 가져오기
    $stmt = $pdo->prepare("SELECT email, password, user_id FROM cm_board WHERE board_id = :board_id AND board_num = :board_num");
    $stmt->execute([
        ':board_id' => $board_id,
        ':board_num' => $board_num
    ]);
    
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$result) {
        $response['message'] = '게시글을 찾을 수 없습니다';
        echo json_encode($response);
        exit;
    }
    
    // 회원일 경우 본인 글 여부 확인
    if ($is_member && !$is_admin) {
        if ($result['user_id'] && $result['user_id'] != $member['user_id']) {
            $response['message'] = '본인의 글만 수정/삭제할 수 있습니다';
            echo json_encode($response);
            exit;
        }
    }
    
    // 비회원일 경우 이메일과 비밀번호 확인
    if (!$is_member) {
        if ($result['email'] !== $email) {
            $response['message'] = '이메일이 일치하지 않습니다';
            $response['field'] = 'email';
            echo json_encode($response);
            exit;
        }
    }
    
    // 비밀번호 확인
    if (password_verify($input_password, $result['password'])) {
        $response['status'] = 'success';
    } else {
        $response['message'] = '비밀번호가 일치하지 않습니다';
        $response['field'] = 'password';
    }
    
} catch (PDOException $e) {
    $response['message'] = '서버 오류가 발생했습니다';
    $response['field'] = '';
    error_log("비밀번호 검증 오류: " . $e->getMessage() . " | Board ID: $board_id, Board Num: $board_num, Email: $email");
} finally {
    echo json_encode($response);
    exit;
}