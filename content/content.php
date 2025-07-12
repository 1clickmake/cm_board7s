<?php
include_once './_common.php';

if (empty($_GET['co_id'])) {
	alert('유효하지 않은 페이지입니다.');
}

$contentId = $_GET['co_id'];

try {
    // 게시글 정보 가져오기
    $sql = "SELECT * FROM cm_content WHERE co_id = :co_id ";
    $params = [
        ':co_id' => $contentId
    ];
    
    $content = sql_fetch($sql, $params);
    
    if (!$content) {
        alert('존재하지 않는 페이지 입니다.');
    }
	
} catch (PDOException $e) {
    echo "<script>alert('오류가 발생했습니다: " . $e->getMessage() . "'); history.back();</script>";
    exit;
}

//스킨경로
$cm_title = $content['co_subject'];
include_once CM_PATH.'/head.php';

echo "<div class='container my-5' style='min-height: 600px;'>".$content['co_content']."</div>";

include_once CM_PATH.'/tail.php';
?>