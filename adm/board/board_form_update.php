<?php
include_once './_common.php';

function rm_rf($file)
{
    if (file_exists($file)) {
        if (is_dir($file)) {
            $handle = opendir($file);
            while ($filename = readdir($handle)) {
                if ($filename != '.' && $filename != '..') {
                    rm_rf($file . '/' . $filename);
                }
            }
            closedir($handle);

            @chmod($file, 0755);
            @rmdir($file);
        } else {
            @chmod($file, 0644);
            @unlink($file);
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
	// POST 방식이 아닌 접근은 허용하지 않습니다.
	alert('잘못된 접근 방식입니다.');
}

// 폼에서 넘어온 데이터.
$action = $_POST['action'] ?? '';
$groupId = $_POST['group_id'] ?? '';
$boardId = $_POST['board_id'] ?? '';
$boardName = $_POST['board_name'] ?? '';
$board_skin = $_POST['board_skin'] ?? '';
$board_category = $_POST['board_category'] ?? '';
$write_lv = $_POST['write_lv'] ?? 0;
$list_lv = $_POST['list_lv'] ?? 0;
$view_lv = $_POST['view_lv'] ?? 0;

// 삭제 처리
if ($action === 'delete') {

	if (empty($boardId)) {
		echo json_encode(['error' => '게시판 ID가 누락되었습니다.'], JSON_UNESCAPED_UNICODE);
		exit;
	}

	try {
		// 트랜잭션 시작
		global $pdo;
		$pdo->beginTransaction();

		// 1. 게시판 관련 파일 삭제
		$boardPath = CM_DATA_PATH.'/board/'.$boardId;
		if (is_dir($boardPath)) {
			// 재귀적으로 디렉토리와 파일 삭제
			function deleteDirectory($dir) {
				if (!file_exists($dir)) {
					return true;
				}
				
				if (!is_dir($dir)) {
					return unlink($dir);
				}
				
				$files = array_diff(scandir($dir), array('.', '..'));
				foreach ($files as $file) {
					$path = $dir . DIRECTORY_SEPARATOR . $file;
					if (is_dir($path)) {
						deleteDirectory($path);
					} else {
						if (is_writable($path)) {
							unlink($path);
						} else {
							chmod($path, 0777);
							unlink($path);
						}
					}
				}
				
				if (is_writable($dir)) {
					return rmdir($dir);
				} else {
					chmod($dir, 0777);
					return rmdir($dir);
				}
			}
			
			try {
				if (!deleteDirectory($boardPath)) {
					// 디렉토리가 여전히 존재하는지 확인
					if (is_dir($boardPath)) {
						// 강제로 권한 변경 후 삭제 시도
						chmod($boardPath, 0777);
						if (!rmdir($boardPath)) {
							throw new Exception('게시판 디렉토리 삭제 실패 (권한 문제)');
						}
					}
				}
			} catch (Exception $e) {
				error_log('디렉토리 삭제 오류: ' . $e->getMessage());
				throw new Exception('게시판 디렉토리 삭제 실패: ' . $e->getMessage());
			}
		}

		// 2. 게시판 파일 테이블 데이터 삭제
		$deleteFiles = process_data_delete('cm_board_file', ['board_id' => $boardId]);
		if ($deleteFiles === false) {
			throw new Exception('게시판 파일 데이터 삭제 실패');
		}

		// 3. 게시판 댓글 삭제
		$deleteComments = process_data_delete('cm_board_comment', ['board_id' => $boardId]);
		if ($deleteComments === false) {
			throw new Exception('게시판 댓글 삭제 실패');
		}

		// 4. 게시판 글 삭제
		$deletePosts = process_data_delete('cm_board', ['board_id' => $boardId]);
		if ($deletePosts === false) {
			throw new Exception('게시판 글 삭제 실패');
		}

		// 5. 게시판 설정 삭제
		$deleteBoard = process_data_delete('cm_board_list', ['board_id' => $boardId]);
		if ($deleteBoard === false) {
			throw new Exception('게시판 설정 삭제 실패');
		}

		// 모든 작업이 성공적으로 완료되면 커밋
		$pdo->commit();
		echo json_encode(['success' => true], JSON_UNESCAPED_UNICODE);

	} catch (Exception $e) {
		// 오류 발생 시 롤백
		if (isset($pdo)) {
			$pdo->rollBack();
		}
		echo json_encode(['error' => '삭제 중 오류가 발생했습니다?: ' . $e->getMessage()], JSON_UNESCAPED_UNICODE);
	}
	exit;
}



// insert , update 간단한 데이터 유효성 검사 (추가 작성가능)
if (empty($groupId) || empty($boardId) || empty($boardName) || empty($board_skin)) {
	// 필수 값이 비어있으면 오류 처리
	alert('필수 입력 값이 누락되었습니다.');
}

if (!preg_match('/^[a-zA-Z0-9!@#$%^&*()_+=\-\[\]{};\':\\"\\|,.<>\/?~]*$/', $boardId)) {
	alert('게시판 아이디 형식이 올바르지 않습니다. 영문, 숫자, 기호만 사용 가능합니다.');
}

//그룹이름 
$sql = "SELECT * FROM `cm_board_group` WHERE `group_id` = :group_id";
$params = [':group_id' => $groupId]; // ':이름' => 값 형태
$gr = sql_fetch($sql, $params);

// 업데이트 모드 처리
if($action === "update"){

	$boardData = [
		'group_id' => $groupId,
		'group_name' => $gr['group_name'],
		'board_name' => $boardName,
		'board_skin' => $board_skin,
		'board_category' => $board_category,
		'write_lv' => $write_lv,
		'list_lv' => $list_lv,
		'view_lv' => $view_lv
	];

	$whereConditions = [
		'board_id' => $boardId
	];

	$updateResult = process_data_update('cm_board_list', $boardData, $whereConditions);

	// 결과 확인
	if ($updateResult !== false) {
		// 성공
		alert('게시판  수정이 완료되었습니다.', './board_list.php');
	} else {
		// 실패 (함수 내부에서 오류 로그는 남겼을 겁니다)
		alert('게시판 수정 중 오류가 발생했습니다.');
	}

}else{
	// 배열의 키는 데이터베이스 테이블의 컬럼 이름과 같아야 합니다.
	$boardData = [
		'group_id' => $groupId,
		'group_name' => $gr['group_name'],
		'board_id' => $boardId,
		'board_name' => $boardName,
		'board_skin' => $board_skin,
		'board_category' => $board_category,
		'write_lv' => $write_lv,
		'list_lv' => $list_lv,
		'view_lv' => $view_lv,
		// created_at 컬럼은 DB에서 CURRENT_TIMESTAMP로 자동 입력되므로 여기에 포함시키지 않아도 됩니다.
	];

	//  process_data_insert 함수를 호출하여 데이터 삽입 시도
	$insertResult = process_data_insert('cm_board_list', $boardData);

	// 결과 확인
	if ($insertResult !== false) {
		// 성공
		alert('게시판 생성이 완료되었습니다.', './board_list.php');
	} else {
		// 실패 (함수 내부에서 오류 로그는 남겼을 겁니다)
		alert('게시판 생성 중 오류가 발생했습니다.');
	}
}
