<?php
include_once './_common.php';
include_once CM_BOARD_PATH.'/board.lib.php';
include_once CM_PATH.'/head.php';

if ($boardNum <= 0) {
	alert('유효하지 않은 게시글입니다.');
}

//게시물 보기 접근 제한
if($bo['view_lv'] > 1 ){
	if(!$is_admin ){
		if($is_guest || $member['user_lv'] < $bo['view_lv']){
			alert('목록을 볼 권한이 없습니다.');
		}
	}
}

try {
    // 게시글 정보 가져오기
    $sql = "SELECT * FROM cm_board WHERE board_id = :board_id AND board_num = :board_num";
    $params = [
        ':board_id' => $boardId,
        ':board_num' => $boardNum
    ];
    
    $view = sql_fetch($sql, $params);
    
    if (!$view) {
        echo "<script>alert('존재하지 않는 게시글입니다.'); location.href='list.php?board={$boardId}';</script>";
        exit;
    }
	
	//비밀글일때
	if(isset($view['secret_chk']) && $view['secret_chk'] == 1){
		if(!$is_admin){
			if($view['user_id'] !== $member['user_id']){
				alert('비밀글은 관리자와 작성한 회원만 볼 수 있습니다.');
			}
		}
	}
	
	// 조회수 증가
	if($view['ip'] !== $ip){
		$update_data = ['view_count' => $view['view_count'] + 1];
		$where_conditions = [
			'board_id' => $boardId,
			'board_num' => $boardNum
		];
		process_data_update('cm_board', $update_data, $where_conditions);
	}
    
    // 첨부파일 목록 가져오기
    $file_sql = "SELECT * FROM cm_board_file 
                 WHERE board_id = :board_id AND board_num = :board_num AND file_type NOT LIKE '%image/%'
                 ORDER BY file_id ASC";
    $file_params = [
        ':board_id' => $boardId,
        ':board_num' => $boardNum
    ];
    $files = sql_all_list($file_sql, $file_params);
	
	//게시글 첨부 이미지 보기
	$file_image_view = get_board_file_image_view($boardId, $boardNum );
	
	
	// 코멘트 목록 가져오기
	$comment_page = isset($_GET['comment_page']) ? (int)$_GET['comment_page'] : 1;
	$comment_limit = 10;
	$comment_offset = ($comment_page - 1) * $comment_limit;

	// 댓글 테이블 존재 여부 확인
	$table_exists = false;
	try {
		$check_table = $pdo->query("SHOW TABLES LIKE 'cm_board_comment'");
		$table_exists = $check_table->rowCount() > 0;
	} catch (Exception $e) {
		error_log("댓글 테이블 확인 오류: " . $e->getMessage());
		$table_exists = false;
	}

	if (!$table_exists) {
		// 댓글 테이블이 없으면 빈 결과로 처리
		$comment_count = 0;
		$total_pages = 0;
		$comments = [];
	} else {
		// 전체 댓글 수 가져오기
		$comment_count_sql = "SELECT COUNT(*) as cnt FROM cm_board_comment 
							 WHERE board_id = :board_id AND board_num = :board_num";
		$comment_count_params = [
			':board_id' => $boardId,
			':board_num' => $boardNum
		];
		$comment_count = sql_fetch($comment_count_sql, $comment_count_params)['cnt'];

		// 페이지네이션 계산
		$total_pages = ceil($comment_count / $comment_limit);
		$start_page = max(1, $comment_page - 2);
		$end_page = min($total_pages, $comment_page + 2);

		// 댓글 목록 가져오기
		$comment_sql = "SELECT * FROM cm_board_comment 
						WHERE board_id = :board_id AND board_num = :board_num 
						ORDER BY comment_id DESC
						LIMIT :limit OFFSET :offset";
		$comment_params = [
			':board_id' => $boardId,
			':board_num' => $boardNum,
			':limit' => (int)$comment_limit,
			':offset' => (int)$comment_offset
		];

		// 디버깅을 위한 로그 추가
		error_log("Comment Query: " . $comment_sql);
		error_log("Comment Params: " . print_r($comment_params, true));

		$comments = sql_all_list($comment_sql, $comment_params);

		// 디버깅을 위한 로그 추가
		error_log("Comments Result: " . print_r($comments, true));

		// 댓글 목록이 비어있는지 확인
		if ($comments === false) {
			error_log("Error fetching comments: " . print_r(error_get_last(), true));
			$comments = [];
		}
	}
    
} catch (PDOException $e) {
    echo "<script>alert('오류가 발생했습니다: " . $e->getMessage() . "'); history.back();</script>";
    exit;
}

//css 경로
echo '<link rel="stylesheet" href="'.CM_TEMPLATE_URL.'/skin/board_skin/'.$bo['board_skin'].'/board.css?ver='.time().'">';

//스킨경로
$bo_title = "게시글 보기";
include_once CM_TEMPLATE_PATH.'/skin/board_skin/'.$bo['board_skin'].'/view.skin.php';

echo '<script>
const boardId 	= ' . json_encode($boardId) . ';
const boardNum	= ' . json_encode($boardNum) . ';
const comment_page	= ' . json_encode($comment_page) . ';
const is_member	= ' . json_encode($is_member) . ';
const comment_chk	= ' . json_encode($view['comment_chk']) . ';
</script>';
echo '<script src="' . CM_URL . '/js/board.view.js?ver=' . time() . '"></script>';
include_once CM_PATH.'/tail.php';