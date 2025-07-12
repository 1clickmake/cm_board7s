<?php
include_once './_common.php';
include_once CM_BOARD_PATH.'/board.lib.php';
include_once CM_PATH.'/head.php';

if ($boardNum <= 0) {
    echo "<script>alert('유효하지 않은 게시글입니다.'); history.back();</script>";
    exit;
}

try {
	
	if (!$is_member) {
		$email_sql = "SELECT email FROM cm_board WHERE board_id = :board_id AND board_num = :board_num";
		$email_params = [
			':board_id' => $board_id,
			':board_num' => $board_num
		];
		$post = sql_fetch($email_sql, $email_params);
		// 세션 또는 GET/POST로 전달된 이메일 검증
	}

    // 게시글 정보 가져오기
    $sql = "SELECT * FROM cm_board WHERE board_id = :board_id AND board_num = :board_num";
    $params = [
        ':board_id' => $boardId,
        ':board_num' => $boardNum
    ];
    
    $write = sql_fetch($sql, $params);
    
    if (!$write) {
        echo "<script>alert('존재하지 않는 게시글입니다.'); location.href='list.php?board={$boardId}';</script>";
        exit;
    }
    
    // 첨부파일 목록 가져오기
    $file_sql = "SELECT * FROM cm_board_file 
                 WHERE board_id = :board_id AND board_num = :board_num 
                 ORDER BY file_id ASC";
    $file_params = [
        ':board_id' => $boardId,
        ':board_num' => $boardNum
    ];
    $files = sql_all_list($file_sql, $file_params);
    
} catch (PDOException $e) {
    echo "<script>alert('오류가 발생했습니다: " . $e->getMessage() . "'); history.back();</script>";
    exit;
}

//css 경로
echo '<link rel="stylesheet" href="'.CM_TEMPLATE_URL.'/skin/board_skin/'.$bo['board_skin'].'/board.css?ver='.time().'">';

//스킨경로
$bo_title = "게시글 수정";
$writeBtn = "수정";
$formAction = CM_BOARD_URL."/edit_update.php";
include_once CM_TEMPLATE_PATH.'/skin/board_skin/'.$bo['board_skin'].'/write.skin.php';

echo '<script>
var recaptcha_site = ' . json_encode($recaptcha_site) . ';
var recaptcha_secret = ' . json_encode($recaptcha_secret) . ';
</script>';
echo '<script src="' . CM_URL . '/js/board.write.js?ver=' . time() . '"></script>';

include_once CM_PATH.'/tail.php';