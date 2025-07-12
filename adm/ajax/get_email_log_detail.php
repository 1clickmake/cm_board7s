<?php
include_once '../_common.php';

$log_id = isset($_GET['log_id']) ? (int)$_GET['log_id'] : 0;

if ($log_id <= 0) {
    echo json_encode(['success' => false, 'message' => '잘못된 로그 ID입니다.']);
    exit;
}

// 로그 정보 조회
$sql = "SELECT * FROM cm_email_log WHERE log_id = :log_id";
$params = [':log_id' => $log_id];
$log = sql_fetch($sql, $params);

if (!$log) {
    echo json_encode(['success' => false, 'message' => '로그를 찾을 수 없습니다.']);
    exit;
}

// JSON 데이터 파싱
$recipients = json_decode($log['recipients'], true);
$attachments = json_decode($log['attachments'], true);
$error_messages = json_decode($log['error_messages'], true);

// HTML 생성
$html = '
<div class="row">
    <div class="col-md-6">
        <h6>기본 정보</h6>
        <table class="table table-sm">
            <tr><td><strong>발송자:</strong></td><td>' . htmlspecialchars($log['sender_id']) . '</td></tr>
            <tr><td><strong>수신자 타입:</strong></td><td>' . htmlspecialchars($log['recipient_type']) . '</td></tr>
            <tr><td><strong>제목:</strong></td><td>' . htmlspecialchars($log['subject']) . '</td></tr>
            <tr><td><strong>발송 시간:</strong></td><td>' . get_formatDate($log['created_at'], 'Y-m-d H:i:s') . '</td></tr>
            <tr><td><strong>성공:</strong></td><td><span class="badge bg-success">' . $log['success_count'] . '</span></td></tr>
            <tr><td><strong>실패:</strong></td><td><span class="badge bg-danger">' . $log['fail_count'] . '</span></td></tr>
        </table>
    </div>
    <div class="col-md-6">
        <h6>수신자 목록</h6>
        <div style="max-height: 200px; overflow-y: auto;">
            <table class="table table-sm">
                <thead>
                    <tr>
                        <th>이름</th>
                        <th>이메일</th>
                    </tr>
                </thead>
                <tbody>';

foreach ($recipients as $recipient) {
    $html .= '<tr>
        <td>' . htmlspecialchars($recipient['name'] ?? '') . '</td>
        <td>' . htmlspecialchars($recipient['email']) . '</td>
    </tr>';
}

$html .= '</tbody></table></div></div>';

// 첨부파일 정보
if (!empty($attachments)) {
    $html .= '<div class="row mt-3">
        <div class="col-12">
            <h6>첨부파일</h6>
            <ul class="list-group">';
    
    foreach ($attachments as $attachment) {
        $html .= '<li class="list-group-item">' . htmlspecialchars($attachment['name']) . '</li>';
    }
    
    $html .= '</ul></div></div>';
}

// 오류 메시지
if (!empty($error_messages)) {
    $html .= '<div class="row mt-3">
        <div class="col-12">
            <h6>오류 메시지</h6>
            <div class="alert alert-danger">
                <ul class="mb-0">';
    
    foreach ($error_messages as $error) {
        $html .= '<li>' . htmlspecialchars($error) . '</li>';
    }
    
    $html .= '</ul></div></div></div>';
}

// 이메일 내용
$html .= '<div class="row mt-3">
    <div class="col-12">
        <h6>이메일 내용</h6>
        <div class="border p-3 bg-light" style="max-height: 300px; overflow-y: auto;">
            ' . $log['content'] . '
        </div>
    </div>
</div>';

echo json_encode([
    'success' => true,
    'html' => $html
]);
?> 