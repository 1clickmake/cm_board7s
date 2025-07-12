<?php
include_once './_common.php';

// GET 파라미터 검증
$boardId = filter_input(INPUT_GET, 'board', FILTER_SANITIZE_SPECIAL_CHARS);
$boardNum = filter_input(INPUT_GET, 'id', FILTER_SANITIZE_NUMBER_INT);

if (empty($boardId) || empty($boardNum)) {
    alert('잘못된 접근입니다.');
}

try {
    // 1. 게시글 정보 조회
    $sql = "SELECT * FROM cm_board WHERE board_id = :board_id AND board_num = :board_num";
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['board_id' => $boardId, 'board_num' => $boardNum]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        alert('존재하지 않는 게시글입니다.');
    }


    // 3. 트랜잭션 시작
    $pdo->beginTransaction();

    // 4. 첨부파일 정보 조회
    $sql = "SELECT * FROM cm_board_file WHERE board_id = :board_id AND board_num = :board_num";
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['board_id' => $boardId, 'board_num' => $boardNum]);
    $files = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // 5. 첨부파일 삭제
    if (!empty($files)) {
        // 파일 정보 삭제
        if (process_file_delete('cm_board_file', ['board_id' => $boardId, 'board_num' => $boardNum]) === false) {
            throw new Exception("파일 정보 삭제 실패");
        }

        // 실제 파일 삭제
        foreach ($files as $file) {
            $file_path = CM_DATA_PATH.'/board/'.$boardId.'/'.$file['stored_filename'];
            if (file_exists($file_path)) {
                unlink($file_path);
            }
        }
    }
	
    // 6. 게시글 삭제
	/*에디터 이미지 삭제*/
	$editorDir = CM_DATA_PATH.'/board/'.$boardId.'/editor';
	process_editor_image_delete('cm_board', 'content', ['board_id' => $boardId, 'board_num' => $boardNum], $editorDir);
	
    if (process_data_delete('cm_board', ['board_id' => $boardId, 'board_num' => $boardNum]) === false) {
        throw new Exception("게시글 삭제 실패");
    }

    // 7. 트랜잭션 커밋
    $pdo->commit();
    
    // 8. 성공 메시지와 함께 목록으로 이동
    alert('게시글이 삭제되었습니다.', "list.php?board={$boardId}");

} catch (Exception $e) {
    // 오류 발생시 롤백
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    alert($e->getMessage());
}