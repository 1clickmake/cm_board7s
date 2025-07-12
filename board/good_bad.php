<?php
include_once './_common.php'; // 경로에 맞게 _common.php 또는 common.php 등을 인클루드

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['status' => 'error', 'message' => '잘못된 요청 방식입니다.']);
    exit;
}

$board_id = $_POST['board_id'] ?? '';
$board_num = isset($_POST['board_num']) ? (int)$_POST['board_num'] : 0;
$action = $_POST['action'] ?? ''; // 'good' or 'bad'
$ip_address = $_SERVER['REMOTE_ADDR'];

if (empty($board_id) || $board_num <= 0 || !in_array($action, ['good', 'bad'])) {
    echo json_encode(['status' => 'error', 'message' => '필수 정보가 누락되었습니다.']);
    exit;
}

// 세션에 투표 기록 확인 및 저장
if (!isset($_SESSION['voted_posts'])) {
    $_SESSION['voted_posts'] = [];
}
if (!isset($_SESSION['voted_posts_ip'])) {
    $_SESSION['voted_posts_ip'] = [];
}

$session_key_post = $board_id . '_' . $board_num;
$session_key_ip_post = $ip_address . '_' . $board_id . '_' . $board_num;

if (isset($_SESSION['voted_posts'][$session_key_post]) || isset($_SESSION['voted_posts_ip'][$session_key_ip_post])) {
    $voted_action = $_SESSION['voted_posts'][$session_key_post] ?? $_SESSION['voted_posts_ip'][$session_key_ip_post];
    $message = "이미 ";
    if ($voted_action === 'good') {
        $message .= "'좋아요'";
    } elseif ($voted_action === 'bad') {
        $message .= "'싫어요'";
    } else {
        $message .= "투표";
    }
    $message .= " 하셨습니다.";
    echo json_encode(['status' => 'error', 'message' => $message]);
    exit;
}


$column_to_update = ($action === 'good') ? 'good' : 'bad';

global $pdo; // common.php 등에서 $pdo 객체가 설정되어 있다고 가정

try {
    $pdo->beginTransaction();

    // 게시물 존재 확인 및 현재 good/bad 카운트 가져오기 (선택적)
    $sql_check = "SELECT good, bad FROM cm_board WHERE board_id = :board_id AND board_num = :board_num";
    $stmt_check = $pdo->prepare($sql_check);
    $stmt_check->bindParam(':board_id', $board_id, PDO::PARAM_STR);
    $stmt_check->bindParam(':board_num', $board_num, PDO::PARAM_INT);
    $stmt_check->execute();
    $post_counts = $stmt_check->fetch(PDO::FETCH_ASSOC);

    if (!$post_counts) {
        $pdo->rollBack();
        echo json_encode(['status' => 'error', 'message' => '게시물을 찾을 수 없습니다. (board_id: '.$board_id.', board_num: '.$board_num.')']);
        exit;
    }

    $sql_update = "UPDATE cm_board SET {$column_to_update} = {$column_to_update} + 1 WHERE board_id = :board_id AND board_num = :board_num";
    $stmt_update = $pdo->prepare($sql_update);
    $stmt_update->bindParam(':board_id', $board_id, PDO::PARAM_STR);
    $stmt_update->bindParam(':board_num', $board_num, PDO::PARAM_INT);
    $stmt_update->execute();

    $pdo->commit();

    // 투표 기록 세션에 저장
    $_SESSION['voted_posts'][$session_key_post] = $action;
    $_SESSION['voted_posts_ip'][$session_key_ip_post] = $action;

    // 업데이트된 카운트 다시 가져오기
    $stmt_check->execute(); // 다시 실행하여 최신 값 가져오기
    $updated_counts = $stmt_check->fetch(PDO::FETCH_ASSOC);

    echo json_encode(['status' => 'success', 'good' => (int)$updated_counts['good'], 'bad' => (int)$updated_counts['bad']]);

} catch (PDOException $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log("Good/Bad Update Error: " . $e->getMessage());
    echo json_encode(['status' => 'error', 'message' => '데이터베이스 오류가 발생했습니다.']);
}
