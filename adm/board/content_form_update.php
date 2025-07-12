<?php
include_once './_common.php';

// 작업 타입 검증
if (!isset($_POST['w']) || !in_array($_POST['w'], ['insert', 'update', 'delete'])) {
    alert('잘못된 접근입니다.', './content_list.php');
    exit;
}

$w = $_POST['w'];
$id = isset($_POST['id']) ? intval($_POST['id']) : 0;

// 삭제 작업 처리
if ($w == 'delete') {
    try {
        // 삭제 전 내용 확인
        $sql = "SELECT co_id FROM cm_content WHERE id = :id";
        $stmt = $pdo->prepare($sql);
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->execute();
        
        if ($stmt->rowCount() === 0) {
            throw new Exception('존재하지 않는 내용입니다.');
        }
		
		//에디터 이미지 삭제
		$editorDir = CM_DATA_PATH.'/content';
		process_editor_image_delete('cm_content', 'co_content', ['id' => $id], $editorDir);

        //데이터 삭제
		$deleteResult = process_data_delete('cm_content', ['id' => $id]);
        
        if ($deleteResult !== false) {
			// 성공
			alert('내용이 삭제되었습니다.', './content_list.php');
		} else {
			// 실패 (함수 내부에서 오류 로그는 남겼을 겁니다)
			alert('내용 삭제중 오류가 발생했습니다.', './content_list.php');
		}
		
    } catch (Exception $e) {
        alert($e->getMessage(), './content_list.php');
        exit;
    }
}

// insert, update 작업을 위한 데이터 검증
$co_id = isset($_POST['co_id']) ? trim($_POST['co_id']) : '';
$co_subject = isset($_POST['co_subject']) ? trim($_POST['co_subject']) : '';
$co_content = isset($_POST['co_content']) ? trim($_POST['co_content']) : '';
$co_editor = isset($_POST['co_editor']) ? intval($_POST['co_editor']) : 0;
$co_width = isset($_POST['co_width']) ? intval($_POST['co_width']) : 0;

// 필수 입력값 검증
if (empty($co_id) || empty($co_subject) || empty($co_content)) {
    alert('필수 입력값이 누락되었습니다.', './content_form.php' . ($w == 'update' ? '?id=' . $id : ''));
    exit;
}

try {
    // 데이터 준비
    $data = [
        'co_id' => $co_id,
        'co_subject' => $co_subject,
        'co_content' => $co_content,
        'co_editor' => $co_editor,
        'co_width' => $co_width
    ];

    if ($w == 'insert') {
        // ID 중복 체크
        $sql = "SELECT COUNT(*) as cnt FROM cm_content WHERE co_id = :co_id";
        $stmt = $pdo->prepare($sql);
        $stmt->bindParam(':co_id', $co_id, PDO::PARAM_STR);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($row['cnt'] > 0) {
            throw new Exception('이미 사용 중인 ID입니다.');
        }

        // 신규 등록
        $result = process_data_insert('cm_content', $data);
        if ($result === false) {
            throw new Exception('데이터 저장 중 오류가 발생했습니다.');
        }
		$idx = $result;
        $message = '내용이 등록되었습니다.';
    } else {
        // 수정 시 ID 중복 체크 (현재 ID 제외)
        $sql = "SELECT COUNT(*) as cnt FROM cm_content WHERE co_id = :co_id AND id != :id";
        $stmt = $pdo->prepare($sql);
        $stmt->bindParam(':co_id', $co_id, PDO::PARAM_STR);
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($row['cnt'] > 0) {
            throw new Exception('이미 사용 중인 ID입니다.');
        }

        // 수정
        $whereConditions = ['id' => $id];
        $result = process_data_update('cm_content', $data, $whereConditions);
        if ($result === false) {
            throw new Exception('데이터 수정 중 오류가 발생했습니다.');
        }
		$idx = $id;
        $message = '내용이 수정되었습니다.';
    }

    // 성공 메시지 출력 후 목록으로 이동
    alert($message, './content_form.php?id='.$idx);

} catch (Exception $e) {
    alert($e->getMessage(), './content_form.php' . ($w == 'update' ? '?id=' . $id : ''));
    exit;
}



