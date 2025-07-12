<?php
include_once '../_common.php';
header('Content-Type: application/json');

$boardId = $_GET['board_id'] ?? '';

if (empty($boardId)) {
    echo json_encode(['error' => '게시판 ID가 누락되었습니다.']);
    exit;
}

try {
    $sql = "SELECT * FROM cm_board_list WHERE board_id = :board_id";
    $params = [':board_id' => $boardId];
    $board = sql_fetch($sql, $params);

    if ($board) {
        echo json_encode($board);
    } else {
        echo json_encode(['error' => '게시판을 찾을 수 없습니다.']);
    }
} catch (Exception $e) {
    echo json_encode(['error' => '데이터 조회 중 오류가 발생했습니다: ' . $e->getMessage()]);
}
?>