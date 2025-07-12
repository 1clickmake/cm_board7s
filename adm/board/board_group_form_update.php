<?php
include_once './_common.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    alert('잘못된 접근 방식입니다.');
}

// 폼에서 넘어온 데이터.
$action = $_POST['action'] ?? '';
$groupId = $_POST['group_id'] ?? '';
$groupName = $_POST['group_name'] ?? '';

// 삭제 모드 처리
if ($action === 'delete') {
    if (empty($groupId)) {
        echo json_encode(['error' => '그룹 ID가 누락되었습니다.'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    
    // 해당 그룹에 속한 게시판이 있는지 확인
    $boardCount = sql_fetch("SELECT COUNT(*) as cnt FROM cm_board_list WHERE group_id = :group_id", [':group_id' => $groupId]);
    if ($boardCount['cnt'] > 0) {
        echo json_encode(['error' => '해당 그룹에 속한 게시판이 있어 삭제할 수 없습니다.'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    
    $deleteResult = process_data_delete('cm_board_group', ['group_id' => $groupId]);
    if ($deleteResult !== false) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['error' => '삭제 중 오류가 발생했습니다.'], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// insert , update 간단한 데이터 유효성 검사 (추가 작성가능)
if (empty($groupId) || empty($groupName)) {
    alert('필수 입력 값이 누락되었습니다.');
}

if (!preg_match('/^[a-zA-Z0-9!@#$%^&*()_+=\-\[\]{};\':\\"\\|,.<>\/?~]*$/', $groupId)) {
    alert('그룹 아이디 형식이 올바르지 않습니다. 영문, 숫자, 기호만 사용 가능합니다.');
}

// 업데이트 모드 처리
if ($action === 'update') {
	
    $groupData = [
        'group_name' => $groupName
    ];
    
    $whereConditions = [
        'group_id' => $groupId
    ];
    
    $updateResult = process_data_update('cm_board_group', $groupData, $whereConditions);
    
    if ($updateResult !== false) {
        alert('그룹 수정이 완료되었습니다.', './board_group_list.php');
    } else {
        alert('그룹 수정 중 오류가 발생했습니다.');
    }
} else {
    // 신규 등록 처리
    $groupData = [
        'group_id' => $groupId,
        'group_name' => $groupName
    ];

    $insertResult = process_data_insert('cm_board_group', $groupData);

    if ($insertResult !== false) {
        alert('그룹 생성이 완료되었습니다.', './board_group_list.php');
    } else {
        alert('그룹 생성 중 오류가 발생했습니다.');
    }
}
