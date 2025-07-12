<?php
include_once './_common.php';

// POST 데이터 확인 
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	
	if($recaptcha_site && $recaptcha_secret){
		// reCAPTCHA 검증
		if (empty($_POST['g-recaptcha-response'])) {
			alert('캡챠 인증이 필요합니다.');
		}

		$recaptcha_response = $_POST['g-recaptcha-response'];
		$verify = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret={$recaptcha_secret}&response={$recaptcha_response}");
		$captcha_success = json_decode($verify);

		if ($captcha_success->success == false) {
			alert('캡챠 인증에 실패했습니다.');
		}
	}

    // 필수 입력값 검증
    $board_id = filter_input(INPUT_POST, 'board_id', FILTER_SANITIZE_SPECIAL_CHARS);
    
    // 회원/비회원에 따른 필수 항목 검증
    if ($is_member) {
        // 회원인 경우 필수 항목
        $required_fields = ['board_id', 'user_id', 'title', 'content'];
    } else {
        // 비회원인 경우 필수 항목
        $required_fields = ['board_id', 'email', 'name', 'password', 'title', 'content'];
    }
    
    $missing_fields = [];
    foreach ($required_fields as $field) {
        if (empty($_POST[$field])) {
            $missing_fields[] = $field;
        }
    }
    
    if (!empty($missing_fields)) {
        alert('다음 필수 항목을 입력해 주세요: ' . implode(', ', $missing_fields));
    }

    // 입력값 필터링
    if ($is_member) {
        // 회원인 경우 회원 정보 사용
        $email = filter_var($member['user_email'], FILTER_SANITIZE_EMAIL);
        $name = filter_var($member['user_name'], FILTER_SANITIZE_SPECIAL_CHARS);
        $user_id = $member['user_id'];
        
        // 회원 비밀번호는 이미 해시된 값으로 DB에 저장되어 있으므로 그대로 사용
        // 실제 비밀번호 값은 필요 없으며, 회원 인증은 세션으로 처리
        $password =  $member['user_password'];
    } else {
        // 비회원인 경우 입력값 사용
        $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
        $name = filter_input(INPUT_POST, 'name', FILTER_SANITIZE_SPECIAL_CHARS);
        $user_id = 0; // 비회원은 user_id = 0
        
        // 비밀번호 해시 처리
        $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
    }

    $title = filter_input(INPUT_POST, 'title', FILTER_SANITIZE_SPECIAL_CHARS);
    $content = $_POST['content']; // HTML 내용은 별도 보안 처리
    $tags = filter_input(INPUT_POST, 'tags', FILTER_SANITIZE_SPECIAL_CHARS);
	$category = isset($_POST['category']) ? $_POST['category'] : '';
    $notice_chk = isset($_POST['notice_chk']) ? 1 : 0;
	$secret_chk = isset($_POST['secret_chk']) ? 1 : 0;
	$reply_chk = isset($_POST['reply_chk']) ? 1 : 0;
	$comment_chk = isset($_POST['comment_chk']) ? 1 : 0;
    $ip = $_SERVER['REMOTE_ADDR'];
	
	

    try {
        // 스팸 필터 처리
        include_once './write_update_spam_filter.php';
        
        // XSS 방지를 위한 HTML 퍼지 처리
        // 여기에 HTML Purifier 등의 라이브러리를 사용하는 코드를 추가
        
        // 트랜잭션 시작
        $pdo->beginTransaction();

        // 1. 게시글 데이터 insert
        $bo = get_board($board_id);
        
        // 답변글 처리
        $parent_num = filter_input(INPUT_POST, 'parent_num', FILTER_VALIDATE_INT);
        $reply_depth = 0;
        $reply_order = 0;
        $thread_id = 0;

        if ($parent_num) {
            // 부모 게시글 정보 조회
            $parent_sql = "SELECT reply_depth, reply_order, thread_id, board_num FROM cm_board WHERE board_num = :parent_num";
            $parent_stmt = $pdo->prepare($parent_sql);
            $parent_stmt->execute([':parent_num' => $parent_num]);
            $parent = $parent_stmt->fetch();

            if ($parent) {
                error_log("Reply post: parent_num = {$parent_num}, parent_reply_depth = {$parent['reply_depth']}, parent_reply_order = {$parent['reply_order']}, parent_thread_id = {$parent['thread_id']}");

                $reply_depth = $parent['reply_depth'] + 1;
                // 부모 게시글의 thread_id가 0이면 부모의 board_num을 사용, 아니면 부모의 thread_id 사용
                $thread_id = ($parent['thread_id'] == 0) ? $parent['board_num'] : $parent['thread_id'];

                // 새로운 답글이 삽입될 위치의 reply_order 계산: 부모 게시글의 reply_order 바로 다음
                $new_reply_order = $parent['reply_order'] + 1;

                // 해당 thread_id 내에서, 새로운 답글의 위치(new_reply_order)보다 크거나 같은 모든 글들의 reply_order를 1 증가시킴
                $order_update_sql = "UPDATE cm_board SET reply_order = reply_order + 1 WHERE thread_id = :thread_id AND reply_order >= :new_order_threshold";
                $order_update_stmt = $pdo->prepare($order_update_sql);
                $order_update_stmt->execute([':thread_id' => $thread_id, ':new_order_threshold' => $new_reply_order]);

                // 새로운 답글에 할당될 reply_order
                $reply_order = $new_reply_order;

                error_log("Reply post: thread_id = {$thread_id}, Calculated new reply_order = {$reply_order}, Update SQL executed.");

            } else {
                 // 부모 게시글이 없는 경우 (오류 상황), 새로운 게시글처럼 처리하거나 오류 처리
                 // 여기서는 새로운 게시글처럼 처리 (혹시 모를 경우)
                 $parent_num = 0; // 부모 없음으로 설정
                 $reply_depth = 0;
                 $reply_order = 0;
                 // thread_id는 아래에서 설정
            }
        }
        
        // 새로운 게시글이거나 부모가 없던 경우 thread_id 설정
        if (!$parent_num) {
             // 게시글 등록 후 board_num을 thread_id로 사용해야 하므로, 초기값 0으로 두고 insert 후에 업데이트
             $thread_id = 0; 
        }

        $boardData = [
            'group_id' => $bo['group_id'],
            'board_id' => $board_id,
			'notice_chk' => $notice_chk,
			'reply_chk' => $reply_chk,
			'comment_chk' => $comment_chk,
            'secret_chk' => $secret_chk,
			'category' => $category,
			'parent_num' => $parent_num ?: 0,  // parent_num이 0이면 0 설정
            'reply_depth' => $reply_depth,
            'reply_order' => $reply_order,
			'thread_id' => $thread_id,
            'user_id' => $user_id,
            'email' => $email,
            'name' => $name,
            'title' => $parent_num ? 'RE: ' . $title : $title,
            'content' => $content,
            'tags' => $tags,
            'ip' => $ip,
			'view_count' => 0,
			'good' => 0,
			'bad' => 0,
            'reg_date' => date('Y-m-d H:i:s'),
			'update_date' => date('Y-m-d H:i:s')
        ];
        
        // 비회원인 경우에만 비밀번호 저장
        if ($is_member || !empty($password)) {
            $boardData['password'] = $password;
        }
		
		for ($col=1 ; $col <= 10; $col++){
			$boardData['add_col_'.$col] = isset($_POST['add_col_'.$col]) ? $_POST['add_col_'.$col] : '';
		}

        $board_num = process_data_insert('cm_board', $boardData);
        if ($board_num === false) {
            throw new Exception("게시글 등록 실패");
        }

        // 새로운 게시글인 경우 board_num을 thread_id로 업데이트
        if (!$parent_num || $thread_id === 0) {
             $update_thread_sql = "UPDATE cm_board SET thread_id = :board_num WHERE board_num = :board_num";
             $update_thread_stmt = $pdo->prepare($update_thread_sql);
             $update_thread_stmt->execute([':board_num' => $board_num]);
        }

        // 2. 파일 업로드 처리
        if (!empty($_FILES['files']['name'][0])) {
            $upload_dir = CM_DATA_PATH.'/board/'.$board_id.'/';
            
            // 업로드 디렉토리 생성
            if (!file_exists($upload_dir) && !mkdir($upload_dir, 0777, true)) {
                throw new Exception("업로드 디렉토리 생성 실패");
            }

            // 허용된 파일 확장자 목록
            $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'txt'];
            
            // 전체 파일 크기 제한 (50MB)
            $total_size = 0;
            foreach ($_FILES['files']['size'] as $size) {
                $total_size += $size;
            }
            if ($total_size > 50 * 1024 * 1024) {
                throw new Exception("전체 파일 크기가 너무 큽니다. 최대 50MB까지 허용됩니다.");
            }

            // 파일 개수 제한 (10개)
            if (count($_FILES['files']['name']) > 10) {
                throw new Exception("최대 10개의 파일만 업로드할 수 있습니다.");
            }
            
            // 각 파일 처리
            for ($i = 0; $i < count($_FILES['files']['name']); $i++) {
                $filename = basename($_FILES['files']['name'][$i]);
                $file_ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
                
                // 허용된 파일 형식 검사
                $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'hwp', 'zip'];
                if (!in_array($file_ext, $allowed_extensions)) {
                    throw new Exception("허용되지 않는 파일 형식입니다: " . $file_ext);
                }
                
                // 개별 파일 크기 제한 (20MB)
                if ($_FILES['files']['size'][$i] > 20 * 1024 * 1024) {
                    throw new Exception("파일 크기가 너무 큽니다. 최대 20MB까지 허용됩니다.");
                }

                $tmp_name = $_FILES['files']['tmp_name'][$i];
                $stored_filename = uniqid() . '_' . bin2hex(random_bytes(8)) . '.' . $file_ext;
                $upload_file_path = $upload_dir . $stored_filename;

                // 파일 업로드
                if (move_uploaded_file($tmp_name, $upload_file_path)) {
                    // 이미지 파일인 경우 리사이징 및 압축 적용
                    if (in_array($file_ext, ['jpg', 'jpeg', 'png', 'gif'])) {
                        if (function_exists('resize_and_compress_image')) {
                            $resize_result = resize_and_compress_image($upload_file_path, 1000, 80);
                            if ($resize_result) {
                                error_log("이미지 리사이징 완료: {$filename}");
                            } else {
                                error_log("이미지 리사이징 실패: {$filename}");
                            }
                        }
                    }
                    
                    $fileData = [
                        'board_id' => $board_id,
                        'board_num' => $board_num,
                        'original_filename' => $filename,
                        'stored_filename' => $stored_filename,
                        'file_size' => $_FILES['files']['size'][$i],
                        'file_type' => $_FILES['files']['type'][$i],
                        'reg_date' => date('Y-m-d H:i:s')
                    ];

                    try {
                        // 파일 정보 저장 전 테이블 구조 확인
                        $checkTable = $pdo->query("SHOW TABLES LIKE 'cm_board_file'");
                        if ($checkTable->rowCount() === 0) {
                            throw new Exception("파일 정보 테이블이 존재하지 않습니다.");
                        }

                        // 테이블 컬럼 확인
                        $columns = $pdo->query("SHOW COLUMNS FROM cm_board_file")->fetchAll(PDO::FETCH_COLUMN);
                        error_log("테이블 컬럼: " . print_r($columns, true));

                        $file_id = process_file_insert('cm_board_file', $fileData);
                        if ($file_id === false) {
                            throw new Exception("파일 정보 저장 실패");
                        }
                        $uploaded_files[] = $filename;
                    } catch (Exception $e) {
                        // 파일 삭제 및 예외 발생
                        if (file_exists($upload_file_path)) {
                            unlink($upload_file_path);
                        }
                        error_log("파일 업로드 실패 상세: " . $e->getMessage() . " (파일: {$filename})");
                        error_log("파일 데이터: " . print_r($fileData, true));
                        throw new Exception("파일 정보 저장 실패: " . $e->getMessage());
                    }
                } else {
                    throw new Exception("파일 업로드 실패");
                }
            }

            // 업로드된 파일 목록 로깅
            if (!empty($uploaded_files)) {
                error_log("Uploaded files for board {$board_id}, post {$board_num}: " . implode(', ', $uploaded_files));
            }
        }

        // 트랜잭션 커밋 
        $pdo->commit();
        
        // 성공 메시지와 함께 게시글 보기 페이지로 이동
        alert('게시글이 등록되었습니다.', get_board_url('view', $board_id, $board_num));

    } catch (Exception $e) {
        // 오류 발생시 롤백
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        alert($e->getMessage());
    }
} else {
    // POST 요청이 아닌 경우 목록으로 리다이렉트
    header('Location: ' . get_board_url('list', $board_id));
    exit;
} 