<?php
include_once './_common.php';
include_once CM_BOARD_PATH . '/board.lib.php';
$cm_title = $bo['board_name'];
include_once CM_PATH . '/head.php';

// 게시물 리스트 접근 제한
if ($bo['list_lv'] > 1) {
    if (!$is_admin) {
        if ($is_guest || $member['user_lv'] < $bo['list_lv']) {
            alert('목록을 볼 권한이 없습니다.');
        }
    }
}

// 공지글 출력
$sqlNot = "SELECT * FROM cm_board WHERE board_id = :board_id AND reply_depth = '0' AND notice_chk = '1' ORDER BY board_num DESC";
$params_notice = [  // 변수명 충돌 방지
    ':board_id' => $boardId
];
$notice_posts = sql_all_list($sqlNot, $params_notice);

// 검색 조건 설정
$search_conditions = [
    ['field' => 'board_id', 'operator' => '=', 'value' => $boardId ?? ''],
    ['field' => 'notice_chk', 'operator' => '<>', 'value' => '1']
];

// 검색어가 있는 경우에만 검색 조건 추가
if (!empty($_GET['search_keyword'])) {
    $search_field = $_GET['search_field'] ?? 'title';

    switch ($search_field) {
        case 'title':
            $search_conditions[] = ['field' => 'title', 'operator' => 'LIKE', 'value' => $_GET['search_keyword']];
            break;
        case 'content':
            $search_conditions[] = ['field' => 'content', 'operator' => 'LIKE', 'value' => $_GET['search_keyword']];
            break;
        case 'category':
            $search_conditions[] = ['field' => 'category', 'operator' => 'LIKE', 'value' => $_GET['search_keyword']];
            break;
        case 'name':
            $search_conditions[] = ['field' => 'name', 'operator' => 'LIKE', 'value' => $_GET['search_keyword']];
            break;
        case 'title_content':
            $search_conditions[] = ['field' => 'title', 'operator' => 'LIKE', 'value' => $_GET['search_keyword']];
            $search_conditions[] = ['field' => 'content', 'operator' => 'LIKE', 'value' => $_GET['search_keyword']];
            break;
        default:
            $search_conditions[] = ['field' => $search_field, 'operator' => 'LIKE', 'value' => $_GET['search_keyword']];
            break;
    }
}

$per_page = $bo['page_rows'] ?? 30; // 게시판 설정의 페이지당 게시물 수 또는 기본값 30

$result = sql_board_list('cm_board', [
    'page' => $_GET['page'] ?? 1,
    'per_page' => $per_page,
    'order_by' => 'thread_id',
    'order_dir' => 'DESC',
    'debug' => false,
    'search' => $search_conditions
]);

$rows = $result['list'];
$total_pages = $result['total_pages'];
$page = $result['current_page'];
$total_rows = $result['total_rows'];

// 목록 번호 계산
$start_number = $total_rows - ($page - 1) * $per_page;

// 검색 조건이 있는지 확인
$has_search = !empty($_GET['search_keyword']);

// 게시글별 아이콘 생성 함수
function get_post_icons($list, $boardId) {
    $icons = [];
    
    // 첨부파일 아이콘
    if ($list['file_count'] > 0) {
        $icons[] = '<i class="fas fa-paperclip post-icon post-icon-attach" title="첨부파일"></i>';
    }
    
    // 비밀글 아이콘
    if ($list['secret_chk'] == 1) {
        $icons[] = '<i class="fas fa-lock post-icon post-icon-secret" title="비밀글"></i>';
    }
    
    // 댓글 수 아이콘
    if (isset($list['comment_count']) && $list['comment_count'] > 0) {
        $icons[] = '<i class="fas fa-comment-dots post-icon post-icon-comment" title="댓글 ' . $list['comment_count'] . '개"></i>';
    }
    
    // NEW 아이콘 (24시간 이내)
    $post_time = strtotime($list['reg_date']);
    $current_time = time();
    $time_diff = $current_time - $post_time;
    if ($time_diff <= 86400) { // 24시간 = 86400초
        $icons[] = '<span class="post-badge post-badge-new">N</span>';
    }
    
    return implode('', $icons);
}

echo '<link rel="stylesheet" href="'.CM_TEMPLATE_URL.'/skin/board_skin/'.$bo['board_skin'].'/board.css?ver='.time().'">';
include_once CM_TEMPLATE_PATH . '/skin/board_skin/' . $bo['board_skin'] . '/list.skin.php';
echo "<script src=\"" . CM_URL . "/js/board.list.js?ver=" . time() . "\"></script>";
include_once CM_PATH . '/tail.php';