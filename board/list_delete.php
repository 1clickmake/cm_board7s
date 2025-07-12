<?php
include_once './_common.php';

// 관리자 또는 해당 게시판 관리 권한 확인 로직 (필요시 추가)
/*
if (!$is_admin && !check_board_auth($board_id, 'delete')) {
    alert('삭제 권한이 없습니다.');
    exit;
}
*/

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    alert('잘못된 접근입니다.', CM_URL);
    exit;
}

$selected_posts = $_POST['selected_posts'] ?? [];
$board_id = $_POST['board_id'] ?? '';
$page = $_POST['current_page'] ?? 1; // list.skin.php에서 current_page로 전달

if (empty($board_id)) {
    alert('게시판 ID가 지정되지 않았습니다.', CM_URL);
    exit;
}

if (empty($selected_posts) || !is_array($selected_posts)) {
    alert('삭제할 게시물을 선택해주세요.');
}

$deleted_count = 0;
$error_count = 0;

// content 컬럼명은 실제 cm_board 테이블의 에디터 내용이 저장된 컬럼명으로 변경해야 합니다.
// 게시판 설정을 통해 content 컬럼명을 가져오거나, 기본값을 사용할 수 있습니다.
// 예: $board_info = get_board($board_id); $content_column = $board_info['bo_content_col'] ?? 'content';
// 여기서는 'content'를 기본값으로 사용합니다. 실제 환경에 맞게 수정해주세요.
$content_column = 'content'; 

foreach ($selected_posts as $board_num_str) {
    $board_num = (int)$board_num_str;
    if ($board_num > 0) {
        if (delete_board_post_fully($board_num, $board_id, $content_column)) {
            $deleted_count++;
        } else {
            $error_count++;
            error_log("Failed to delete post: board_id={$board_id}, board_num={$board_num}");
        }
    }
}

$message = "총 {$deleted_count}개의 게시물을 삭제했습니다.";
if ($error_count > 0) $message .= "\\n{$error_count}개 게시물 삭제에 실패했습니다. (로그 확인 필요)";

alert($message, CM_BOARD_URL . "/list.php?board=" . urlencode($board_id) . "&page=" . $page);
?>