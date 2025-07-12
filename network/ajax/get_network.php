<?php
include_once('./_common.php');

if (!$is_member) {
    die(json_encode(['error' => '회원만 이용 가능합니다.']));
}

$user_id = $member['user_id'];
$level = isset($_GET['level']) ? (int)$_GET['level'] : 1;
$parent_id = isset($_GET['parent_id']) ? $_GET['parent_id'] : $user_id;

if ($level > 10) {
    die(json_encode(['error' => '최대 10단계까지만 조회 가능합니다.']));
}

$sql = "SELECT user_id, user_name, user_lv, user_point, created_at 
        FROM cm_users 
        WHERE user_recommend = :parent_id 
        ORDER BY created_at DESC";

$params = [':parent_id' => $parent_id];
$result = sql_all_list($sql, $params);

if ($result === false) {
    die(json_encode(['error' => '데이터를 불러오는데 실패했습니다.']));
}

$network = [];
foreach ($result as $row) {
    $network[] = [
        'user_id' => $row['user_id'],
        'user_name' => $row['user_name'],
        'user_lv' => $row['user_lv'],
        'user_point' => $row['user_point'],
        'created_at' => $row['created_at']
    ];
}

die(json_encode(['success' => true, 'data' => $network]));
?> 