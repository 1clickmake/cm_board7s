<?php
include_once '../_common.php';

header('Content-Type: application/json');

try {
    // 현재 사용 중인 ID 중 가장 큰 값을 찾음
    $sql = "SELECT MAX(CAST(co_id AS UNSIGNED)) as max_id FROM cm_content WHERE co_id REGEXP '^[0-9]+$'";
    $stmt = $pdo->query($sql);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    
    $max_id = $result['max_id'] ?? 0;
    
    // 다음 ID 생성 (10단위)
    $next_id = ceil(($max_id + 1) / 10) * 10;
    
    // 생성된 ID가 이미 존재하는지 확인
    $check_sql = "SELECT COUNT(*) as cnt FROM cm_content WHERE co_id = :co_id";
    $check_stmt = $pdo->prepare($check_sql);
    $check_stmt->bindParam(':co_id', $next_id, PDO::PARAM_STR);
    $check_stmt->execute();
    $check_result = $check_stmt->fetch(PDO::FETCH_ASSOC);
    
    // 이미 존재하는 경우 다음 10단위로 증가
    while ($check_result['cnt'] > 0) {
        $next_id += 10;
        $check_stmt->bindParam(':co_id', $next_id, PDO::PARAM_STR);
        $check_stmt->execute();
        $check_result = $check_stmt->fetch(PDO::FETCH_ASSOC);
    }
    
    echo json_encode([
        'success' => true,
        'next_id' => $next_id
    ]);
} catch (PDOException $e) {
    echo json_encode([
        'success' => false,
        'error' => '데이터베이스 오류가 발생했습니다.'
    ]);
}
?> 