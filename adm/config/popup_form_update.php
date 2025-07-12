<?php
include_once './_common.php';
// CSRF 토큰 검증 (예시 - 실제로는 세션에 저장된 토큰과 비교해야 함)
// if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
// echo '<script>alert("잘못된 접근입니다. (CSRF 토큰 오류)"); location.href="popup_list.php";</script>';
// exit;
// }

// POST 데이터 확인
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo '<script>alert("잘못된 접근입니다."); location.href="popup_list.php";</script>';
    exit;
}

// HTML Purifier 라이브러리 로드 (예시 - 실제 경로에 맞게 수정)
// require_once '/path/to/htmlpurifier/library/HTMLPurifier.auto.php';
// $config = HTMLPurifier_Config::createDefault();
// $purifier = new HTMLPurifier($config);

// 모드 확인 (insert, update, delete)
$mode = isset($_POST['mode']) ? $_POST['mode'] : '';

if (!in_array($mode, ['insert', 'update', 'delete'])) {
    echo '<script>alert("잘못된 요청입니다."); location.href="popup_list.php";</script>';
    exit;
}

// 팝업 상태값 초기화
$po_use = isset($_POST['po_use']) ? 1 : 0;

try {
    // 삭제 처리
    if ($mode === 'delete') {
        if (!isset($_POST['po_id']) || empty($_POST['po_id'])) {
			alert("삭제할 팝업을 선택해주세요.");
        }
        
        $po_id = intval($_POST['po_id']);
		
		//에디터 이미지 삭제
		$editorDir = CM_DATA_PATH.'/popup';
		process_editor_image_delete('cm_popup', 'po_content', ['po_id' => $po_id], $editorDir);
		
		//데이터 삭제
		$deleteResult = process_data_delete('cm_popup', ['po_id' => $po_id]);
        
        if ($deleteResult !== false) {
			// 성공
			alert('팝업이 삭제되었습니다.', './popup_list.php');
		} else {
			// 실패 (함수 내부에서 오류 로그는 남겼을 겁니다)
			alert('팝업 삭제중 오류가 발생했습니다.');
		}
    }
    
    // 등록 또는 수정 처리
    // 필수 입력 데이터 검증
    if (!isset($_POST['po_title']) || empty($_POST['po_title'])) {
        alert('팝업 제목을 입력해주세요.');
    }
    
    $po_title = trim($_POST['po_title']);
    // $po_content = isset($_POST['po_content']) ? trim($_POST['po_content']) : '';
    // po_content는 HTML이므로, XSS 방지를 위해 HTML Purifier 사용 (예시)
    $po_content_raw = isset($_POST['po_content']) ? $_POST['po_content'] : '';
    // $po_content = $purifier->purify($po_content_raw); // HTML Purifier 사용 시
    $po_content = $po_content_raw; // HTML Purifier 미사용 시 임시 (보안 취약)
    // 만약 HTML을 허용하지 않으려면 strip_tags 또는 htmlspecialchars 사용
    // $po_content = strip_tags($po_content_raw);

    $po_top = isset($_POST['po_top']) ? intval($_POST['po_top']) : 0;
    $po_left = isset($_POST['po_left']) ? intval($_POST['po_left']) : 0;
    $po_width = isset($_POST['po_width']) ? intval($_POST['po_width']) : 400;
    $po_height = isset($_POST['po_height']) ? intval($_POST['po_height']) : 400;
    $po_start_date = isset($_POST['po_start_date']) ? $_POST['po_start_date'] : date('Y-m-d');
    $po_end_date = isset($_POST['po_end_date']) ? $_POST['po_end_date'] : date('Y-m-d', strtotime('+7 days'));
    $po_cookie_time = isset($_POST['po_cookie_time']) ? intval($_POST['po_cookie_time']) : 24;
    $po_url = isset($_POST['po_url']) ? trim($_POST['po_url']) : '';
    $po_target = (isset($_POST['po_target']) && $_POST['po_target'] === '_self') ? '_self' : '_blank';

    // 추가 유효성 검사 (예시)
    if (!empty($po_url) && !filter_var($po_url, FILTER_VALIDATE_URL)) {
        alert('유효하지 않은 URL 형식입니다.');
    }
    
    // 시작일이 종료일보다 늦을 경우 체크
    if (strtotime($po_start_date) > strtotime($po_end_date)) {
		alert('종료일은 시작일보다 이후여야 합니다');
    }
	
	// 배열의 키는 데이터베이스 테이블의 컬럼 이름과 같아야 합니다.
	$popData = [
		'po_title' => $po_title,
		'po_content' => $po_content,
		'po_top' => $po_top,
		'po_left' => $po_left,
		'po_width' => $po_width,
		'po_height' => $po_height,
		'po_start_date' => $po_start_date,
		'po_end_date' => $po_end_date,
		'po_cookie_time' => $po_cookie_time,
		'po_url' => $po_url,
		'po_target' => $po_target,
		'po_use' => $po_use
	];

    if ($mode === 'insert') {
        // 신규 등록

		//  process_data_insert 함수를 호출하여 데이터 삽입 시도
		$insertResult = process_data_insert('cm_popup', $popData);
		
		// 결과 확인
		if ($insertResult !== false) {
			// 성공
			alert('팝업이 등록되었습니다.', './popup_form.php?po_id='.$insertResult);
		} else {
			// 실패 (함수 내부에서 오류 로그는 남겼을 겁니다)
			alert('팝업 등록중 오류가 발생했습니다.');
		}
		
    } else if ($mode === 'update') {
        // 수정
        if (!isset($_POST['po_id']) || empty($_POST['po_id'])) {
            alert('수정할 팝업을 선택해주세요.');
        }
        
        $po_id = intval($_POST['po_id']);

		$whereConditions = [
			'po_id' => $po_id
		];

		$updateResult = process_data_update('cm_popup', $popData, $whereConditions);

		// 결과 확인
		if ($updateResult !== false) {
			// 성공
			alert('팝업이 수정되었습니다.', 'popup_form.php?po_id='.$po_id);
		} else {
			// 실패 (함수 내부에서 오류 로그는 남겼을 겁니다)
			alert('팝업 수정중 오류가 발생했습니다.');
		}
    }

} catch (PDOException $e) {
    alert('팝업 수정중 오류가 발생했습니다.' . $e->getMessage());
}
?>