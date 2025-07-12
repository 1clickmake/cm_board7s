<?php
include_once '../_common.php';

header('Content-Type: application/json');

if (!isset($_POST['co_id']) || empty($_POST['co_id'])) {
    echo json_encode(['error' => 'ID가 전달되지 않았습니다.']);
    exit;
}

$co_id = trim($_POST['co_id']);

try {
    // 현재 수정 중인 ID인 경우 제외
    $exclude_id = isset($_POST['current_id']) ? intval($_POST['current_id']) : 0;
    
    $sql = "SELECT COUNT(*) as cnt FROM cm_content WHERE co_id = :co_id";
    if ($exclude_id > 0) {
        $sql .= " AND id != :exclude_id";
    }
    
    $stmt = $pdo->prepare($sql);
    $stmt->bindParam(':co_id', $co_id, PDO::PARAM_STR);
    if ($exclude_id > 0) {
        $stmt->bindParam(':exclude_id', $exclude_id, PDO::PARAM_INT);
    }
    $stmt->execute();
    
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    echo json_encode(['exists' => ($row['cnt'] > 0)]);
} catch (PDOException $e) {
    echo json_encode(['error' => '데이터베이스 오류가 발생했습니다.']);
}
?> 