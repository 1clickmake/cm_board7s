<?php
include_once './_common.php';

// 파일 ID 확인
$boardId = isset($_GET['board']) ? $_GET['board'] : '';
$file_id = isset($_GET['file_id']) ? intval($_GET['file_id']) : 0;

if ($file_id <= 0) {
    echo "<script>alert('유효하지 않은 파일입니다.'); history.back();</script>";
    exit;
}

try {
    // 파일 정보 가져오기
    $stmt = $pdo->prepare("
        SELECT original_filename, stored_filename, file_type
        FROM cm_board_file
        WHERE file_id = :file_id
    ");
    $stmt->bindParam(':file_id', $file_id);
    $stmt->execute();
    
    $file = $stmt->fetch();
    
    if (!$file) {
        echo "<script>alert('존재하지 않는 파일입니다.'); history.back();</script>";
        exit;
    }
    
	// 파일 업로드 관련 설정
	$upload_dir = CM_DATA_PATH.'/board/'.$boardId.'/';
		
    $file_path = $upload_dir . $file['stored_filename'];
    
    if (!file_exists($file_path)) {
        echo "<script>alert('파일이 서버에 존재하지 않습니다.'); history.back();</script>";
        exit;
    }
    
    // 파일 다운로드를 위한 헤더 설정
    header('Content-Description: File Transfer');
    header('Content-Type: ' . $file['file_type']);
    header('Content-Disposition: attachment; filename="' . $file['original_filename'] . '"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($file_path));
    
    // 출력 버퍼 비우기
    ob_clean();
    flush();
    
    // 파일 읽어서 출력
    readfile($file_path);
    exit;
    
} catch (PDOException $e) {
    echo "<script>alert('오류가 발생했습니다: " . $e->getMessage() . "'); history.back();</script>";
    exit;
}