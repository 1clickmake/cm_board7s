<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 직접 접근 방지 

/**
 * 모바일 기기 접속 여부를 확인합니다.
 *
 * @return bool 모바일 기기 접속 시 true, PC 접속 시 false 반환
 */
function is_mobile() { // : bool 제거
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

    // 모바일 기기 패턴
    $mobile_patterns = [
        'iPhone', 'iPod', 'iPad', 'Android', 'webOS', 'BlackBerry',
        'IEMobile', 'Opera Mini', 'Mobile', 'Mobile Safari',
        'Windows Phone', 'Symbian', 'Nokia', 'SonyEricsson',
        'LG', 'Samsung', 'HTC', 'Motorola', 'Nexus'
    ];

    // 모바일 기기 패턴 확인
    foreach ($mobile_patterns as $pattern) {
        if (stripos($user_agent, $pattern) !== false) {
            return true;
        }
    }

    // 모바일 브라우저 헤더 확인
    if (isset($_SERVER['HTTP_X_WAP_PROFILE']) ||
        isset($_SERVER['HTTP_PROFILE']) ||
        (isset($_SERVER['HTTP_ACCEPT']) &&
         strpos($_SERVER['HTTP_ACCEPT'], 'text/vnd.wap.wml') !== false)) {
        return true;
    }

    return false;
}

// 변수 또는 배열의 이름과 값을 얻어냄. print_r() 함수의 변형
function print_r2($var) {
    ob_start();
    print_r($var);
    $str = ob_get_contents();
    ob_end_clean();
    $str = htmlspecialchars($str); // 먼저 HTML 특수문자 처리
    $str = str_replace(" ", "&nbsp;", $str); // 공백을 &nbsp;로 변경
    echo nl2br("<span style='font-family:Tahoma, 굴림; font-size:9pt;'>".$str."</span>");
}

/**
 * 현재 실행 중인 파일의 이름을 반환합니다.
 *
 * @return string 현재 파일명 (확장자 제외), 실패 시 빈 문자열 반환
 */
function get_current_filename() { // : string 제거
    $urlPath = $_SERVER['PHP_SELF'];
    return !empty($urlPath) ? pathinfo(basename($urlPath), PATHINFO_FILENAME) : '';
}

/**
 * 현재 실행 중인 폴더의 이름을 반환합니다.
 *
 * @return string 현재 파일명 (확장자 제외), 실패 시 빈 문자열 반환
 */
function get_First_FolderName($url) {
    $parsed_url = parse_url($url);
    if (!isset($parsed_url['path'])) return '';

    $parts = array_filter(explode('/', $parsed_url['path'])); // array_values 제거
    return isset($parts[0]) ? $parts[0] : '';
}

function is_AllowedFolder() {
    $allowed_folders = ['board', 'adm', 'member'];

    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
    $host = $_SERVER['HTTP_HOST'];
    $request_uri = $_SERVER['REQUEST_URI'];
    $current_url = $protocol . $host . $request_uri;

    $first_folder = get_First_FolderName($current_url);

    return in_array($first_folder, $allowed_folders);
}

// 휴대폰번호의 숫자만 취한 후 중간에 하이픈(-)을 넣는다.
function get_hyphen_hp_number(string $hp) { // : string 제거
    $hp = preg_replace("/[^0-9]/", "", $hp);
    return preg_replace("/([0-9]{3})([0-9]{3,4})([0-9]{4})$/", "\\1-\\2-\\3", $hp);
}

/**
 * 문자열에서 숫자만 추출하여 반환하는 함수
 */
function get_only_number(string $str) { // : string 제거
    return preg_replace('/[^0-9]/', '', $str);
}

/**
 * 날짜를 원하는 형식으로 출력
 * $dates = "2015-01-15 13:24:25"; 				//날짜 일때
 * get_formatDate($dates, 'Y년 m월 d일 K요일'); 	// 출력 : 2015년 01월 15일 목요일
 * get_formatDate($dates, 'K'); 				// 출력 :  목
 * get_formatDate($dates, 'H:i:s (K)'); 		// 출력 :  13:24:25 (목)
 */

function get_formatDate($date, $format = 'Y-m-d H:i:s') {
    $dateTime = new DateTime($date);

    // 한글 요일 매핑 배열 (0: 일요일, 1: 월요일 ... 6: 토요일)
    $koreanWeekdays = ['일', '월', '화', '수', '목', '금', '토'];
    $dayOfWeek = (int)$dateTime->format('w'); // 0~6 숫자로 요일 추출
    $koreanWeekday = $koreanWeekdays[$dayOfWeek];

    // 형식 문자열에 "K"가 포함된 경우 한글 요일로 치환
    $format = str_replace('K', $koreanWeekday, $format);

    return $dateTime->format($format);
}


/**
 * 특정 디렉토리 안의 폴더 목록을 반환하는 함수
 *
 * @param string $directory 폴더 목록을 읽을 디렉토리 경로
 * @return array|false 폴더 목록 (배열) 또는 오류 발생 시 false
 */
function getSubdirectories(string $directory) { // : array|false 제거
    if (!is_dir($directory)) {
        error_log("디렉토리 '$directory'가 존재하지 않습니다.");
        return false;
    }

    $subdirectories = [];
    $items = scandir($directory);

    if ($items === false) {
        error_log("디렉토리 '$directory'를 읽는 데 실패했습니다.");
        return false;
    }

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }

        $path = $directory . '/' . $item;
        if (is_dir($path)) {
            $subdirectories[] = $item;
        }
    }

    return $subdirectories;
}


/**
 * 게시판 URL을 생성합니다.
 *
 * @param string $fileName  URL을 생성할 PHP 파일명 (예: view, write)
 * @param string $board     게시판 이름
 * @param string $board_id  (선택 사항) 특정 게시물 ID
 * @return string 생성된 게시판 URL, board 또는 fileName이 비어있으면 CM_URL 반환
 */
function get_board_url(string $fileName, string $board_id, string $board_num = '') { // : string 제거
    if (empty($board_id) || empty($fileName)) {
        return CM_URL;
    }

	// $board_num 숫자가 아닌 경우 CM_URL 반환
    if (!empty($board_num) && !ctype_digit($board_num)) {
        return CM_URL;
    }

    $href = CM_BOARD_URL . "/" . $fileName . ".php?board=" . $board_id;
    if (!empty($board_num)) {
        $href .= "&id=" . $board_num;
    }

    return $href;
}

//게시판정보
function get_board(string $board_id){
	if (!empty($board_id)) {
		$sql = "SELECT * FROM `cm_board_list` WHERE `board_id` = :board_id";
		$params = [
			':board_id' => $board_id
		];
		return sql_fetch($sql, $params);
	}else{
		return false;
	}
}

//회원정보
function get_member($user_id){
	if (!empty($user_id)) {
		$sql = "SELECT * FROM `cm_users` WHERE `user_id` = :user_id";
		$params = [
			':user_id' => $user_id
		];
		return sql_fetch($sql, $params);
	}else{
		return false;
	}
}


//포인트 지급, 차감
function get_UserPoint($user_id, $point, $description, $action) {

	global $pdo;

    if (empty($user_id) || $point <= 0 || empty($description) || !in_array($action, ['add', 'cut'])) {
        throw new InvalidArgumentException("잘못된 입력입니다. 모든 필드를 확인해주세요.");
    }

    try {
        // 트랜잭션 시작
        $pdo->beginTransaction();

        // 회원 존재 확인
        $stmt = $pdo->prepare("SELECT user_point FROM cm_users WHERE user_id = :user_id");
        $stmt->execute(['user_id' => $user_id]);
        $user = $stmt->fetch();

        if (!$user) {
            throw new InvalidArgumentException("존재하지 않는 회원 아이디입니다.");
        }

        if ($action === 'add') {
            // 포인트 지급: cm_point에 내역 추가 및 cm_users의 user_point 증가
            $stmt = $pdo->prepare("INSERT INTO cm_point (user_id, point, description) VALUES (:user_id, :point, :description)");
            $stmt->execute([
                'user_id' => $user_id,
                'point' => $point,
                'description' => $description
            ]);

            $stmt = $pdo->prepare("UPDATE cm_users SET user_point = user_point + :point WHERE user_id = :user_id");
            $stmt->execute([
                'point' => $point,
                'user_id' => $user_id
            ]);
        } elseif ($action === 'cut') {
            // 포인트 차감: cm_point에서 해당 포인트 내역 삭제
            $stmt = $pdo->prepare("DELETE FROM cm_point WHERE user_id = :user_id AND point = :point AND description = :description");
            $stmt->execute([
                'user_id' => $user_id,
                'point' => $point,
                'description' => $description
            ]);

			$stmt = $pdo->prepare("UPDATE cm_users SET user_point = user_point - :point WHERE user_id = :user_id");
            $stmt->execute([
                'point' => $point,
                'user_id' => $user_id
            ]);

            // 삭제된 행이 없으면 예외 발생
            if ($stmt->rowCount() === 0) {
                throw new InvalidArgumentException("삭제할 포인트 내역이 없습니다.");
            }
        }

        // 트랜잭션 커밋
        $pdo->commit();
        return true;
    } catch (Throwable $e) {
        // 오류 발생 시 롤백
        $pdo->rollBack();
        throw $e;
    }
}

/**
 * 알림 메시지를 표시하고 페이지를 이동합니다.
 *
 * @param string      $message      표시할 알림 메시지
 * @param string|null $redirect_url (선택 사항) 이동할 URL, null이면 이전 페이지로 이동
 * @return void
 */
function alert(string $message, $redirect_url = null) { // ?string 제거, : void 제거
    $escaped_message = json_encode($message);

    echo '<script>';
    echo 'alert(' . $escaped_message . ');';

    if (!empty($redirect_url)) {
        echo 'window.location.href = ' . json_encode($redirect_url) . ';';
    } else {
        echo 'history.back();';
    }

    echo '</script>';
    exit;
}


/**
 * 데이터를 데이터베이스 테이블에 삽입합니다.
 *
 * @param string $tableName 삽입할 테이블 이름
 * @param array  $data      삽입할 데이터 (연관 배열, 컬럼명 => 값)
 * @return string|false 삽입된 레코드의 ID, 실패 시 false 반환
 */
function process_data_insert(string $tableName, array $data) { // : string|false 제거
    global $pdo;

    if (empty($data)) {
        error_log("process_data_insert: 삽입할 데이터가 비어 있습니다.");
        return false;
    }

    $columns = array_keys($data);
    $placeholders = implode(', ', array_map(function($col) { // fn() 제거
        return ":" . $col;
    }, $columns));
    $columnSql = implode(', ', array_map(function($col) { // fn() 제거
        return "`" . str_replace("`", "``", $col) . "`";
    }, $columns));

    $sql = "INSERT INTO `" . str_replace("`", "``", $tableName) . "` ({$columnSql}) VALUES ({$placeholders})";

    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute($data);
        return $pdo->lastInsertId();
    } catch (PDOException $e) {
        error_log("process_data_insert 오류 ({$tableName}): " . $e->getMessage() . " SQL: " . $sql . " DATA: " . json_encode($data));
        return false;
    }
}

/**
 * 파일 메타데이터를 삽입합니다.
 *
 * @param string $tableName 삽입할 테이블 이름
 * @param array  $data      삽입할 데이터 (연관 배열)
 * @return string|false 삽입된 레코드의 ID, 실패 시 false 반환
 */
function process_file_insert(string $tableName, array $data) { // : string|false 제거
    global $pdo;

    if (empty($data)) {
        error_log("process_file_insert: 삽입할 데이터가 비어 있습니다.");
        return false;
    }

    try {
        // 데이터베이스 연결 확인
        if (!$pdo) {
            error_log("process_file_insert: 데이터베이스 연결이 설정되지 않았습니다.");
            return false;
        }

        // SQL 쿼리 생성
        $columns = array_keys($data);
        $placeholders = implode(', ', array_map(function($col) { // fn() 제거
            return ":" . $col;
        }, $columns));
        $columnSql = implode(', ', array_map(function($col) { // fn() 제거
            return "`" . str_replace("`", "``", $col) . "`";
        }, $columns));

        $sql = "INSERT INTO `" . str_replace("`", "``", $tableName) . "` ({$columnSql}) VALUES ({$placeholders})";

        error_log("SQL Query: " . $sql);
        error_log("Parameters: " . print_r($data, true));

        // 쿼리 실행
        $stmt = $pdo->prepare($sql);
        $result = $stmt->execute($data);

        if ($result === false) {
            $error = $stmt->errorInfo();
            error_log("process_file_insert 실패: " . print_r($error, true));
            return false;
        }

        // 삽입된 ID 확인
        $file_id = $pdo->lastInsertId();
        if ($file_id === false) {
            error_log("process_file_insert: lastInsertId 실패");
            return false;
        }

        error_log("파일 정보 저장 성공 - ID: " . $file_id);
        return $file_id;
    } catch (PDOException $e) {
        error_log("process_file_insert PDO 오류: " . $e->getMessage());
        error_log("PDO 오류 코드: " . $e->getCode());
        return false;
    } catch (Exception $e) {
        error_log("process_file_insert 일반 오류: " . $e->getMessage() . " SQL: " . $sql . " DATA: " . json_encode($data));
        return false;
    }
}

/**
 * 데이터베이스 테이블의 데이터를 업데이트합니다.
 *
 * @param string $tableName      업데이트할 테이블 이름
 * @param array  $data           업데이트할 데이터 (연관 배열, 컬럼명 => 값)
 * @param array  $whereConditions 업데이트 조건 (연관 배열, 컬럼명 => 값)
 * @return bool 업데이트 성공 시 true, 실패 시 false 반환
 */
function process_data_update(string $tableName, array $data, array $whereConditions) { // : bool 제거
    global $pdo;

    if (empty($data) || empty($whereConditions)) {
        error_log("process_data_update: 업데이트할 데이터 또는 조건이 비어 있습니다.");
        return true; // 데이터나 조건이 비어있으면 성공으로 처리
    }

    $setParts = array_map(function($col) { // fn() 제거
        return "`" . str_replace("`", "``", $col) . "` = :" . $col;
    }, array_keys($data));
    $setSql = implode(', ', $setParts);

    $whereParts = [];
    $whereData = [];
    foreach ($whereConditions as $col => $value) {
        $placeholder = ":where_" . $col;
        $whereParts[] = "`" . str_replace("`", "``", $col) . "` = " . $placeholder;
        $whereData[$placeholder] = $value;
    }
    $whereSql = implode(' AND ', $whereParts);

    $sql = "UPDATE `" . str_replace("`", "``", $tableName) . "` SET {$setSql} WHERE {$whereSql}";

    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute(array_merge($data, $whereData));
        return true; // 업데이트 성공 여부와 관계없이 true 반환
    } catch (PDOException $e) {
        error_log("process_data_update 오류 ({$tableName}): " . $e->getMessage() . " SQL: " . $sql . " DATA: " . json_encode($data) . " WHERE: " . json_encode($whereConditions));
        return false;
    }
}

/**
 * 파일 메타데이터를 업데이트합니다. (process_data_update() 래퍼 함수)
 *
 * @param string $tableName      업데이트할 테이블 이름
 * @param array  $data           업데이트할 데이터 (연관 배열)
 * @param array  $whereConditions 업데이트 조건 (연관 배열)
 * @return bool 업데이트 성공 시 true, 실패 시 false 반환
 */
function process_file_update(string $tableName, array $data, array $whereConditions) { // : bool 제거
    return process_data_update($tableName, $data, $whereConditions);
}

/**
 * 데이터베이스 테이블의 데이터를 삭제합니다.
 *
 * @param string $tableName      삭제할 테이블 이름
 * @param array  $whereConditions 삭제 조건 (연관 배열, 컬럼명 => 값)
 * @return bool 삭제 성공 시 true, 실패 시 false 반환
 */
function process_data_delete(string $tableName, array $whereConditions) { // : bool 제거
    global $pdo;

    if (empty($whereConditions)) {
        error_log("process_data_delete: 삭제 조건이 비어 있습니다.");
        return true; // 조건이 비어있으면 성공으로 처리
    }

    $whereParts = [];
    $whereData = [];
    foreach ($whereConditions as $col => $value) {
        $placeholder = ":where_" . $col;
        $whereParts[] = "`" . str_replace("`", "``", $col) . "` = " . $placeholder;
        $whereData[$placeholder] = $value;
    }
    $whereSql = implode(' AND ', $whereParts);

    $sql = "DELETE FROM `" . str_replace("`", "``", $tableName) . "` WHERE {$whereSql}";

    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute($whereData);
        return true; // 삭제 성공 여부와 관계없이 true 반환
    } catch (PDOException $e) {
        error_log("process_data_delete 오류 ({$tableName}): " . $e->getMessage() . " SQL: " . $sql . " WHERE: " . json_encode($whereConditions));
        return false;
    }
}

/**
 * 파일 메타데이터를 삭제합니다. (process_data_delete() 래퍼 함수)
 *
 * @param string $tableName      삭제할 테이블 이름
 * @param array  $whereConditions 삭제 조건 (연관 배열)
 * @return bool 삭제 성공 시 true, 실패 시 false 반환
 */
function process_file_delete(string $tableName, array $whereConditions) { // : bool 제거
    return process_data_delete($tableName, $whereConditions);
}

/**
 * 특정 게시물 및 관련 데이터(댓글, 첨부파일, 에디터 이미지)를 모두 삭제합니다.
 *
 * @param int    $board_num 삭제할 게시물 번호
 * @param string $board_id  게시판 ID
 * @param string $content_column_name 게시물 내용이 저장된 컬럼명 (에디터 이미지 삭제용)
 * @return bool 성공 시 true, 실패 시 false
 */
function delete_board_post_fully(int $board_num, string $board_id, string $content_column_name = 'content') { // : bool 제거
    global $pdo;

    // board_id 유효성 검사 (테이블명/경로에 사용되므로 중요)
    if (empty($board_id) || !preg_match('/^[a-zA-Z0-9_.-]+$/', $board_id)) {
        error_log("Invalid board_id for deletion: {$board_id}");
        return false;
    }
    if (!defined('CM_DATA_PATH') || !defined('CM_DATA_URL')) {
        error_log("CM_DATA_PATH or CM_DATA_URL not defined.");
        return false;
    }

    try {
        $pdo->beginTransaction();

        // 1. 에디터 이미지 삭제 (DB에서 게시물 내용 조회 후 파일 삭제)
        $editor_dir = CM_DATA_PATH . '/board/' . $board_id . '/editor/';
        $editor_delete_result = process_editor_image_delete(
            'cm_board', // 게시판 테이블명
            $content_column_name, // 게시물 내용 컬럼명
            ['board_num' => $board_num, 'board_id' => $board_id], // WHERE 조건
            $editor_dir // 에디터 이미지 실제 경로
        );

        if (!$editor_delete_result['success']) {
            error_log("Failed to delete editor images for board_num {$board_num}, board_id {$board_id}: " . $editor_delete_result['message']);
            // 에디터 이미지 삭제 실패 시에도 로그만 남기고 계속 진행 (필요시 롤백 및 false 반환)
        }

        // 2. 댓글 삭제 (cm_board_comment)
        $stmt_comments = $pdo->prepare("DELETE FROM cm_board_comment WHERE board_num = :board_num AND board_id = :board_id");
        $stmt_comments->execute([':board_num' => $board_num, ':board_id' => $board_id]);

        // 3. 첨부 파일 삭제 (물리적 파일 및 cm_board_file DB 레코드)
        $stmt_files = $pdo->prepare("SELECT stored_filename FROM cm_board_file WHERE board_num = :board_num AND board_id = :board_id"); // 'bf_file'을 'stored_filename'으로 변경
        $stmt_files->execute([':board_num' => $board_num, ':board_id' => $board_id]);
        $files_to_delete = $stmt_files->fetchAll(PDO::FETCH_ASSOC);

        $board_files_dir = CM_DATA_PATH . '/board/' . $board_id . '/';
        foreach ($files_to_delete as $file) {
            $file_path = $board_files_dir . $file['stored_filename']; // 'bf_file'을 'stored_filename'으로 변경
            if (file_exists($file_path) && is_file($file_path)) {
                if (!unlink($file_path)) {
                    error_log("Failed to delete physical file: {$file_path}");
                    // 파일 삭제 실패 시에도 로그만 남기고 계속 진행 (필요시 롤백)
                }
            }
        }
        $stmt_delete_db_files = $pdo->prepare("DELETE FROM cm_board_file WHERE board_num = :board_num AND board_id = :board_id");
        $stmt_delete_db_files->execute([':board_num' => $board_num, ':board_id' => $board_id]);

        // 4. 게시물 본문 삭제 (cm_board)
        $stmt_post = $pdo->prepare("DELETE FROM cm_board WHERE board_num = :board_num AND board_id = :board_id");
        $stmt_post->execute([':board_num' => $board_num, ':board_id' => $board_id]);

        $pdo->commit();
        return true;

    } catch (Exception $e) { // PDOException 포함 모든 예외 처리
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log("Error during full deletion of board post {$board_num} from board {$board_id}: " . $e->getMessage());
        return false;
    }
}

/**
 * Summernote 에디터 이미지 처리 및 저장
 *
 * @param array $fileInfo 업로드된 파일 정보($_FILES 배열)
 * @param string $board 게시판 이름
 * @return string|false 저장된 이미지 URL 또는 실패 시 false
 */
function process_editor_image_upload(array $fileInfo, string $dataname) { // 반환 타입 제거
    // 업로드 오류 확인
    if (!isset($fileInfo['error']) || $fileInfo['error'] !== UPLOAD_ERR_OK) {
        error_log("이미지 업로드 오류: " . ($fileInfo['error'] ?? '알 수 없음'));
        return false;
    }

    // 파일 정보 추출
    $tmp_name = $fileInfo['tmp_name'];
    $original_filename = $fileInfo['name'];
    $file_type = $fileInfo['type'];

    // 허용된 이미지 타입인지 확인
    $allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!in_array($file_type, $allowed_types)) {
         error_log("업로드 오류: 허용되지 않는 파일 타입 ({$file_type})");
         return false;
    }

    // 파일 확장자 추출
    $file_ext = strtolower(pathinfo($original_filename, PATHINFO_EXTENSION));

    // 저장 경로 설정
	if($dataname == "popup" || $dataname == "content"){
		$upload_dir = CM_DATA_PATH . '/' . $dataname . '/';
		$upload_url = CM_DATA_URL . '/' . $dataname ;
	}else{
		$upload_dir = CM_DATA_PATH . '/board/' . $dataname . '/editor/';
		$upload_url = CM_DATA_URL . '/board/' . $dataname . '/editor';
	}

    // 디렉토리 생성 (필요시)
    if (!file_exists($upload_dir) && !mkdir($upload_dir, 0777, true)) {
        error_log("업로드 오류: 디렉토리 생성 실패");
        return false;
    }

    // 고유 파일명 생성
    // PHP 7.0 미만 환경을 위한 random_bytes 폴리필
    if (!function_exists('random_bytes')) {
        function random_bytes($length) {
            if (function_exists('openssl_random_pseudo_bytes')) {
                return openssl_random_pseudo_bytes($length);
            }
            // 최후의 수단, 보안에 취약할 수 있으므로 권장하지 않음
            $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
            $randomString = '';
            for ($i = 0; $i < $length; $i++) {
                $randomString .= $chars[mt_rand(0, strlen($chars) - 1)];
            }
            return $randomString;
        }
    }
    $stored_filename = uniqid() . '_' . bin2hex(random_bytes(8)) . '.' . $file_ext;
    $upload_file_path = $upload_dir . $stored_filename;

    // 파일 저장
    if (move_uploaded_file($tmp_name, $upload_file_path)) {
        // 이미지 리사이징 및 압축 적용
        if (function_exists('resize_and_compress_image')) {
            $resize_result = resize_and_compress_image($upload_file_path, 1000, 80);
            if ($resize_result) {
                error_log("에디터 이미지 리사이징 완료: {$original_filename}");
            } else {
                error_log("에디터 이미지 리사이징 실패: {$original_filename}");
            }
        }
        
        // URL 생성 및 반환
        if (!defined('CM_DATA_URL')) {
             error_log("업로드 오류: CM_DATA_URL 상수 미정의");
             if (file_exists($upload_file_path)) {
                 unlink($upload_file_path);
             }
             return false;
        }

        return $upload_url . '/' . $stored_filename;

    } else {
        error_log("업로드 오류: 파일 이동 실패");
        return false;
    }
}

function process_editor_image_delete(string $tableName, string $tableCol, array $whereConditions, string $editorDir) { // : array 제거
    global $pdo;

    try {
        // WHERE 조건 생성
        $whereClause = [];
        $params = [];
        foreach ($whereConditions as $field => $value) {
            $whereClause[] = "`$field` = :$field";
            $params[":$field"] = $value;
        }
        $whereSql = implode(' AND ', $whereClause);

        // 게시물 콘텐츠 조회
        $sql = "SELECT `$tableCol` FROM `$tableName` WHERE $whereSql";
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $row = $stmt->fetch();

        if (!$row || empty($row[$tableCol])) {
            return ['success' => true, 'message' => '콘텐츠가 없거나 게시물이 존재하지 않습니다.'];
        }

        // content에서 <img> 태그의 src 속성 추출
        $content = $row[$tableCol];
        $pattern = '/<img[^>]+src=["\'](.*?)["\']/i';
        preg_match_all($pattern, $content, $matches);

        $deletedFiles = [];
        $errors = [];

        // 추출된 이미지 경로 처리
        if (!empty($matches[1])) {
            foreach ($matches[1] as $imgSrc) {
                // 절대 경로에서 파일 이름만 추출
                $fileName = basename($imgSrc);
                $filePath = rtrim($editorDir, '/') . '/' . $fileName;

                // 파일이 존재하는지 확인하고 삭제
                if (file_exists($filePath)) {
                    if (unlink($filePath)) {
                        $deletedFiles[] = $fileName;
                    } else {
                        $errors[] = "파일 삭제 실패: $fileName";
                    }
                }
            }
        }

        if (empty($errors)) {
            return ['success' => true, 'message' => '이미지 삭제 완료: ' . (empty($deletedFiles) ? '삭제된 파일 없음' : implode(', ', $deletedFiles))];
        } else {
            return ['success' => false, 'message' => '일부 이미지 삭제 실패: ' . implode(', ', $errors)];
        }
    } catch (Exception $e) {
        return ['success' => false, 'message' => '이미지 삭제 중 오류 발생: ' . $e->getMessage()];
    }
}


/**
 * SQL 쿼리를 실행하고 단일 행을 반환합니다.
 *
 * @param string $sql    실행할 SQL 쿼리
 * @param array  $params (선택 사항) 쿼리 매개변수
 * @return array|false  결과 행 (연관 배열), 결과가 없거나 오류 발생 시 false 반환
 */
function sql_fetch(string $sql, array $params = []) { // : array|false 제거
    global $pdo;

    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("sql_fetch 오류: " . $e->getMessage());
        return false;
    }
}

/**
 * 게시판외 일반페이지 목록을 조회합니다. 페이징처리 O
 */
function sql_list(array $options = []) { // : array 제거

	global $pdo; // 데이터베이스 연결 객체인 $pdo에 접근

    if (!$pdo) {
        error_log("sql_fetch 오류: 데이터베이스 연결( \$pdo )이 설정되지 않았습니다.");
        return [];
    }

    $table = $options['table'] ?? '';
    $page = $options['page'] ?? 1;
    $per_page = $options['per_page'] ?? 10;
    $order_by = $options['order_by'] ?? 'id DESC';
    $conditions = $options['conditions'] ?? [];

    if (!$table) {
        throw new InvalidArgumentException('테이블명을 지정해주세요.');
    }

    $start = ($page - 1) * $per_page;
    $where_clauses = [];
    $params = [];

    foreach ($conditions as $idx => $cond) {
        $field = $cond['field'] ?? '';
        $operator = strtoupper($cond['operator'] ?? '=');
        $value = $cond['value'] ?? '';

        if (empty($field) || empty($operator)) {
            continue;
        }

        $param_key = ":cond$idx";

        if ($operator === 'IN' && is_array($value)) {
            $placeholders = [];
            foreach ($value as $i => $val) {
                $key = ":cond{$idx}_{$i}";
                $placeholders[] = $key;
                $params[$key] = $val;
            }
            $where_clauses[] = "$field IN (" . implode(', ', $placeholders) . ")";

        } elseif ($operator === 'BETWEEN' && is_array($value) && count($value) === 2) {
            $params[":cond{$idx}_start"] = $value[0];
            $params[":cond{$idx}_end"] = $value[1];
            $where_clauses[] = "$field BETWEEN :cond{$idx}_start AND :cond{$idx}_end";

        } elseif ($operator === 'LIKE') {
            // IP 주소 검색인 경우 (ip_address 필드)
            if ($field === 'ip_address') {
                $where_clauses[] = "$field $operator $param_key";
                $params[$param_key] = $value;
            } else {
                // 일반 LIKE 검색의 경우 기존처럼 양쪽에 % 추가
                $value = '%' . $value . '%';
                $where_clauses[] = "$field $operator $param_key";
                $params[$param_key] = $value;
            }
        } else {
            $where_clauses[] = "$field $operator $param_key";
            $params[$param_key] = $value;
        }
    }

    $where_sql = !empty($where_clauses) ? 'WHERE ' . implode(' AND ', $where_clauses) : '';

    try {
        $count_sql = "SELECT COUNT(*) FROM $table $where_sql";
        $count_stmt = $pdo->prepare($count_sql);
        $count_stmt->execute($params);
        $total_rows = $count_stmt->fetchColumn();
        $total_pages = ceil($total_rows / $per_page);

        $list_sql = "
            SELECT *
            FROM $table
            $where_sql
            ORDER BY $order_by
            LIMIT :start, :per_page
        ";

        $stmt = $pdo->prepare($list_sql);
        foreach ($params as $key => $value) {
            $stmt->bindValue($key, $value);
        }
        $stmt->bindValue(':start', (int)$start, PDO::PARAM_INT);
        $stmt->bindValue(':per_page', (int)$per_page, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll();

        return [
            'list' => $rows,
			'current_page' => $page,
			'per_page' => $per_page,
            'total_rows' => $total_rows,
            'total_pages' => $total_pages
        ];
    } catch (PDOException $e) {
        error_log("sql_list 오류: " . $e->getMessage() . " SQL: " . $list_sql . " PARAMS: " . json_encode($params));
        throw new RuntimeException('DB 오류: ' . $e->getMessage());
    }
}

/**
 * 게시판 목록을 조회합니다. 페이징처리 O
*/
function sql_board_list(string $table, array $options = []) { // : array 제거

	global $pdo; // 데이터베이스 연결 객체인 $pdo에 접근

    if (!$pdo) {
        error_log("sql_fetch 오류: 데이터베이스 연결( \$pdo )이 설정되지 않았습니다.");
        return [];
    }

    $page = intval($options['page'] ?? 1);
    $per_page = intval($options['per_page'] ?? 10);
    $start = ($page - 1) * $per_page;

    $searches = $options['search'] ?? [];  // 필드별 조건 배열
    $order_by = $options['order_by'] ?? 'thread_id';
    $order_dir = strtoupper($options['order_dir'] ?? 'DESC');
    $debug = $options['debug'] ?? false;

    // 기본 정렬 조건 설정
    $default_order = "thread_id DESC, reply_depth ASC, reply_order ASC, board_num ASC";
    $order_sql = $order_by === 'thread_id' ? $default_order : "$order_by $order_dir";

    $where_clauses = [];
    $params = [];

    // 검색 조건 구성
    foreach ($searches as $i => $s) {
        $field = $s['field'] ?? '';
        $operator = strtoupper($s['operator'] ?? '=');
        $value = $s['value'] ?? null;

        $param_name = ":param_$i";

        if ($operator === 'LIKE') {
            $where_clauses[] = "$field LIKE $param_name";
            $params[$param_name] = "%$value%";
        } elseif ($operator === 'IN' && is_array($value)) {
            $in_params = [];
            foreach ($value as $j => $v) {
                $pname = ":param_{$i}_$j";
                $in_params[] = $pname;
                $params[$pname] = $v;
            }
            $where_clauses[] = "$field IN (" . implode(", ", $in_params) . ")";
        } elseif ($operator === 'BETWEEN' && is_array($value) && count($value) === 2) {
            $params[":param_{$i}_1"] = $value[0];
            $params[":param_{$i}_2"] = $value[1];
            $where_clauses[] = "($field BETWEEN :param_{$i}_1 AND :param_{$i}_2)";
        } else {
            // 일반 연산자 (=, >=, <=, <, > 등)
            $where_clauses[] = "$field $operator $param_name";
            $params[$param_name] = $value;
        }
    }

    $where_sql = count($where_clauses) ? "WHERE " . implode(" AND ", $where_clauses) : "";

    // 전체 개수 쿼리
    $count_sql = "SELECT COUNT(*) FROM {$table} $where_sql";
    $count_stmt = $pdo->prepare($count_sql);
    $count_stmt->execute($params);
    $total_rows = $count_stmt->fetchColumn();
    $total_pages = ceil($total_rows / $per_page);

    // 데이터 조회 쿼리
    $sql = "
        SELECT b.*,
            (SELECT COUNT(*) FROM cm_board_file WHERE board_num = b.board_num) as file_count,
            (SELECT COUNT(*) FROM cm_board_comment WHERE board_id = b.board_id AND board_num = b.board_num) as comment_count
        FROM {$table} b
        $where_sql
        ORDER BY
            b.thread_id DESC,
            b.reply_order ASC,
            b.reply_depth ASC,
            b.board_num ASC
        LIMIT :start, :per_page
    ";

    if ($debug) {
        echo "<pre>SQL: $sql\nParams: " . print_r($params, true) . "</pre>";
    }

    try {
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(':start', $start, PDO::PARAM_INT);
        $stmt->bindValue(':per_page', $per_page, PDO::PARAM_INT);

        foreach ($params as $key => $value) {
            $stmt->bindValue($key, $value);
        }

        $stmt->execute();
        $rows = $stmt->fetchAll();

        return [
            'list' => $rows,
            'current_page' => $page,
            'per_page' => $per_page,
            'total_rows' => $total_rows,
            'total_pages' => $total_pages
        ];
    } catch (PDOException $e) {
        error_log("sql_board_list 오류: " . $e->getMessage() . " SQL: " . $sql . " PARAMS: " . json_encode($params));
        throw $e;
    }
}

/**
 * SQL 쿼리를 실행하고 전체 목록을 반환합니다. 간단한 리스트 조회 페이징처리 X
 *
 * @param string $sql    실행할 SQL 쿼리
 * @param array  $params (선택 사항) 쿼리 매개변수
 */
function sql_all_list(string $sql, array $params = [])
{
    global $pdo;

    if (!$pdo) {
        error_log("sql_list 오류: 데이터베이스 연결( \$pdo )이 설정되지 않았습니다.");
        return false;
    }

    try {
        // 쿼리 준비
        $stmt = $pdo->prepare($sql);

        // 파라미터 바인딩
        foreach ($params as $key => $value) {
            if ($key === ':limit' || $key === ':offset') {
                $stmt->bindValue($key, (int)$value, PDO::PARAM_INT);
            } else {
                $stmt->bindValue($key, $value);
            }
        }

        // 쿼리 실행
        $executeResult = $stmt->execute();

        if ($executeResult === false) {
            $error = $stmt->errorInfo();
            error_log("sql_list 오류: 쿼리 실행 실패. [쿼리: " . $sql . "] [파라미터: " . print_r($params, true) . "] [에러: " . print_r($error, true) . "]");
            return false;
        }

        // 결과의 모든 행을 연관 배열의 배열로 가져오기
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Statement 객체 닫기
        $stmt->closeCursor();

        return $results;

    } catch (PDOException $e) {
        error_log("sql_list PDO 오류: " . $e->getMessage() . " [쿼리: " . $sql . "] [파라미터: " . print_r($params, true) . "]");
        return false;
    } catch (Exception $e) {
        error_log("sql_list 알 수 없는 오류: " . $e->getMessage() . " [쿼리: " . $sql . "] [파라미터: " . print_r($params, true) . "]");
        return false;
    }
}

/**
 * SQL 쿼리를 실행하고 결과 레코드의 수를 반환합니다.
 *
 * @param string $sql    실행할 SQL 쿼리
 * @param array  $params (선택 사항) 쿼리 매개변수
 * @return int          결과 레코드 수
 */
function sql_count(string $sql, array $params = []) { // : int 제거
    global $pdo;

    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchColumn();
    } catch (PDOException $e) {
        error_log("sql_count 오류: " . $e->getMessage());
        return 0;
    }
}

/**
 * 최신글 출력 
 *
 * @param string $board_id    게시판아이디
 * @param int $post_cnt       출력할 게시물 수 (기본값: 5)
 * @param string $skin        사용할 스킨 폴더명 (기본값: basic_new_post)
 * @return string            HTML 출력
 */
function get_new_post(string $board_id, int $post_cnt = 5, string $skin = 'basic_new_post'): string {
    global $pdo;
    
    // 게시물 조회 쿼리
    $sql = "SELECT * FROM cm_board 
            WHERE board_id = :board_id 
            AND reply_depth = '0' 
            AND secret_chk = '0' 
            AND notice_chk = '0' 
            ORDER BY board_num DESC 
            LIMIT " . (int)$post_cnt;
    
    $params = [
        ':board_id' => $board_id
    ];
    
    $latest_posts = sql_all_list($sql, $params);
    
    // 쿼리 결과가 배열이 아니면 빈 배열로 초기화
    if (!is_array($latest_posts)) {
        $latest_posts = [];
    }
    
    $output = '';

    if (empty($latest_posts)) {
        return '<div class="col-12 text-center py-5">등록된 게시물이 없습니다.</div>';
    }

    // 스킨 파일 경로 설정
    $skin_file = CM_TEMPLATE_PATH . '/skin/new_post/' . $skin . '/new_post.skin.php';
    
    // 기본 스킨이 없으면 기본 메시지 출력
    if (!file_exists($skin_file)) {
        $skin_file = CM_TEMPLATE_PATH . '/skin/new_post/basic_new_post/new_post.skin.php';
        if (!file_exists($skin_file)) {
            return '<div class="col-12">스킨 파일을 찾을 수 없습니다: ' . $skin . '</div>';
        }
    }

    // 각 게시물에 대해 스킨 적용
    foreach ($latest_posts as $list) {
        // 이미지 가져오기
        $images = [];
        if (function_exists('get_image_post')) {
            $image_result = get_image_post('cm_board', 'board_num', $list['board_num'], $list['content'], $list['board_id']);
            if ($image_result && is_string($image_result)) {
                $images = [['file' => $image_result]];
            }
        }
        
        // 스킨 파일에 변수 전달
        ob_start();
        include $skin_file;
        $output .= ob_get_clean();
    }

    return $output;
}

/**
 * 이미지 출력
 *
 * @param string $table        데이터베이스 테이블 (현재 함수에서는 사용되지 않음)
 * @param string $cols         데이터베이스 테이블 컬럼 (현재 함수에서는 사용되지 않음)
 * @param int    $idx          데이터베이스 테이블 컬럼 값 (게시물 번호)
 * @param string $content      내용
 * @param string $board_id     게시판 아이디
 * @return string|false        출력할 이미지 URL 또는 false
 */
function get_image_post(string $table, string $cols, int $idx, string $content, string $board_id = '')
{
    global $pdo;

    // 1. content 내용에서 이미지 태그 찾기
    if (!empty($content)) {
        preg_match('/<img[^>]+src=["\']([^">]+)["\']/', $content, $matches);
        if (isset($matches[1])) {
            return htmlspecialchars($matches[1]);
        }
    }

    // 2. 첨부 파일에서 이미지 찾기
    if (!empty($board_id)) {
        $sql = "SELECT stored_filename FROM cm_board_file 
                WHERE board_id = :board_id 
                AND board_num = :board_num 
                AND file_type LIKE 'image/%' 
                ORDER BY file_id ASC 
                LIMIT 1";
        
        try {
            $stmt = $pdo->prepare($sql);
            $stmt->bindParam(':board_id', $board_id, PDO::PARAM_STR);
            $stmt->bindParam(':board_num', $idx, PDO::PARAM_INT);
            $stmt->execute();
            $file = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($file && !empty($file['stored_filename'])) {
                return CM_DATA_URL . '/board/' . $board_id . '/' . htmlspecialchars($file['stored_filename']);
            }
        } catch (PDOException $e) {
            error_log("get_image_post DB 오류: " . $e->getMessage());
        }
    }

    return false;
}

/**
 * 게시물에 등록된 모든 이미지 출력
 *
 * @param string $board_id   게시판 아이디
 * @param int    $board_num  게시물 번호
 * @return string|bool       모든 이미지 태그를 포함하는 HTML 문자열 (이미지가 없을 경우 false 반환) 
 */
function get_board_file_image_view($board_id, $board_num)
{
    global $pdo;  // PDO 객체가 전역 변수로 선언되어 있다고 가정

    $images_html = '';  // 반환할 모든 이미지 태그를 담을 변수

    // 해당 게시물에 연결된 모든 이미지 파일을 가져오는 SQL 쿼리
    $sql = "SELECT stored_filename FROM cm_board_file WHERE board_id = :board_id AND board_num = :board_num AND file_type LIKE 'image/%' ORDER BY file_id ASC";
    $stmt = $pdo->prepare($sql);
    $stmt->bindParam(':board_id', $board_id, PDO::PARAM_STR);
    $stmt->bindParam(':board_num', $board_num, PDO::PARAM_INT);
    $stmt->execute();

    // fetchAll을 사용하여 모든 결과를 배열로 가져옵니다.
    $files = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if (!empty($files)) {
        // foreach 문을 사용하여 가져온 모든 파일에 대해 이미지 태그를 생성합니다.
        foreach ($files as $file) {
            // CM_DATA_URL 상수가 정의되어 있다고 가정합니다.
            // 실제 이미지 경로에 맞게 CM_DATA_URL과 경로를 조합해야 합니다.
            $images_html .= '<div><img src="' . CM_DATA_URL . '/board/' . $board_id . '/' . htmlspecialchars($file['stored_filename']) . '" class="img-fluid"></div>';
        }
        return $images_html;
    }

    // 이미지가 없을 경우 false 반환
    return false;
}

/**
 * 페이지네이션 HTML 코드를 생성합니다.
 *
 * @param int   $current_page 현재 페이지 번호
 * @param int   $total_pages  전체 페이지 수
 * @param array $query_params  페이지 링크에 추가할 쿼리 매개변수
 * @param int   $range        현재 페이지 기준으로 표시할 페이지 범위
 * @return string 생성된 페이지네이션 HTML 코드
 */

function render_pagination(int $current_page, int $total_pages, array $query_params = [], int $range = 4) { // : string 제거
    if ($total_pages <= 1) return '';

    $start_page = max(1, $current_page - $range);
    $end_page = min($total_pages, $current_page + $range);

    // query string 생성
    $base_query = $query_params;
    unset($base_query['page']); // 기존 page 제거

    $query_string = function($page) use ($base_query) {
        return '?' . http_build_query(array_merge($base_query, ['page' => $page]));
    };

    ob_start();
    ?>
    <nav class="cm-pagination-nav" aria-label="Page navigation">
        <ul class="cm-pagination">
            <?php if ($current_page > 1): ?>
                <li class="cm-pagination-item">
                    <a class="cm-pagination-link" href="<?= $query_string(1) ?>" aria-label="First">
                        <span aria-hidden="true">&laquo;&laquo;</span>
                    </a>
                </li>
                <li class="cm-pagination-item">
                    <a class="cm-pagination-link" href="<?= $query_string($current_page - 1) ?>" aria-label="Previous">
                        <span aria-hidden="true">&laquo;</span>
                    </a>
                </li>
            <?php endif; ?>

            <?php for ($i = $start_page; $i <= $end_page; $i++): ?>
                <li class="cm-pagination-item <?= $i == $current_page ? 'cm-pagination-active' : '' ?>">
                    <a class="cm-pagination-link" href="<?= $query_string($i) ?>"><?= $i ?></a>
                </li>
            <?php endfor; ?>

            <?php if ($current_page < $total_pages): ?>
                <li class="cm-pagination-item">
                    <a class="cm-pagination-link" href="<?= $query_string($current_page + 1) ?>" aria-label="Next">
                        <span aria-hidden="true">&raquo;</span>
                    </a>
                </li>
                <li class="cm-pagination-item">
                    <a class="cm-pagination-link" href="<?= $query_string($total_pages) ?>" aria-label="Last">
                        <span aria-hidden="true">&raquo;&raquo;</span>
                    </a>
                </li>
            <?php endif; ?>
        </ul>
    </nav>
    <?php
    return ob_get_clean();
}

/**
 * 정렬 아이콘을 생성합니다.
 *
 * @param string $current_field 현재 정렬 필드
 * @param string $current_order 현재 정렬 방향
 * @param string $field 비교할 필드
 * @return string 정렬 아이콘 HTML
 */
function get_sort_icon(string $current_field, string $current_order, string $field) { // : string 제거
    if ($current_field !== $field) {
        return '<i class="fas fa-sort"></i>';
    }
    return $current_order === 'ASC' ?
        '<i class="fas fa-sort-up"></i>' :
        '<i class="fas fa-sort-down"></i>';
}

/**
 * 정렬 가능한 필드 목록을 반환합니다.
 *
 * @param string $table 테이블 이름
 * @return array 정렬 가능한 필드 목록
 */
function get_sortable_fields(string $table) { // : array 제거
    $fields = [
        'cm_users' => ['user_no', 'user_id', 'user_name', 'user_email', 'user_hp', 'user_lv', 'user_point', 'created_at'],
        'cm_point' => ['id', 'user_id', 'point', 'description', 'created_at'],
        'cm_board' => ['board_num', 'board_id', 'name', 'title', 'reg_date']
    ];

    return $fields[$table] ?? [];
}

/**
 * 파일 확장자에 따른 Font Awesome 아이콘 클래스를 반환합니다.
 *
 * @param string $filename 파일명 또는 확장자
 * @return string Font Awesome 아이콘 클래스
 */
function get_file_icon_class(string $filename) { // : string 제거
    $file_ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

    // 파일 타입별 아이콘 클래스 설정
    switch($file_ext) {
        case 'pdf':
            return 'fa-file-pdf';
        case 'doc':
        case 'docx':
            return 'fa-file-word';
        case 'xls':
        case 'xlsx':
            return 'fa-file-excel';
        case 'ppt':
        case 'pptx':
            return 'fa-file-powerpoint';
        case 'zip':
        case 'rar':
            return 'fa-file-archive';
        case 'txt':
            return 'fa-file-alt';
        default:
            return 'fa-file';
    }
}

/**
 * 파일이 이미지인지 확인합니다.
 *
 * @param string $filename 파일명 또는 확장자
 * @return bool 이미지 파일 여부
 */
function is_image_file(string $filename) { // : bool 제거
    $file_ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    return in_array($file_ext, ['jpg', 'jpeg', 'png', 'gif', 'webp']);
}

/**
 * 다국어 문자열을 가져옵니다. 한국어를 기본값으로 사용합니다.
 *
 * @param string $key 다국어 키
 * @param string $default 기본값 (한국어)
 * @return string 번역된 문자열
 */
function get_lang(string $key, string $default = '') { // : string 제거
    global $lang;
    return htmlspecialchars($lang->get($key, $default));
}

/**
 * HTML 태그가 포함된 다국어 문자열을 가져옵니다.
 *
 * @param string $key 다국어 키
 * @param string $default 기본값 (한국어)
 * @return string 번역된 문자열 (HTML 태그 포함)
 */
function get_lang_html(string $key, string $default = '') { // : string 제거
    global $lang;
    return $lang->get($key, $default);
}

// 구조 출력 함수 (불필요한 폴더 제외)
//echo showTree(CM_PATH);
//showTree(CM_PATH, '', ['vendor/composer', '.git', 'cache']);

function showTree($dir, $prefix = '', $excludeFolders = []) {
    // 기본 제외 폴더들
    $defaultExclude = ['.', '..', '.git', 'node_modules', '.vscode', '.idea', 'cache', 'logs', '.well-known' ];
    $excludeFolders = array_merge($defaultExclude, $excludeFolders);

    $files = scandir($dir);
    $files = array_diff($files, $excludeFolders);

    // 파일과 폴더 분리 및 정렬
    $folders = [];
    $regularFiles = [];

    foreach ($files as $file) {
        $path = $dir . '/' . $file;
        if (is_dir($path)) {
            $folders[] = $file;
        } else {
            $regularFiles[] = $file;
        }
    }

    sort($folders);
    sort($regularFiles);

    // 폴더 먼저 출력
    foreach ($folders as $folder) {
        $path = $dir . '/' . $folder;
        echo $prefix . '├── ' . $folder . "<br>";
        showTree($path, $prefix . '│   ', $excludeFolders);
    }

    // 파일 출력
    foreach ($regularFiles as $file) {
        echo $prefix . '├── ' . $file . "<br>";
    }
}

/**
 * 이미지 리사이징 및 압축 함수
 * 
 * @param string $source_path 원본 이미지 경로
 * @param int $max_width 최대 가로 크기 (기본값: 1000px)
 * @param int $quality 이미지 품질 (기본값: 80)
 * @return bool 성공 시 true, 실패 시 false
 */
function resize_and_compress_image($source_path, $max_width = 1000, $quality = 80) {
    // GD 라이브러리 확인
    if (!extension_loaded('gd')) {
        error_log("GD 라이브러리가 설치되지 않았습니다.");
        return false;
    }

    // 파일 존재 확인
    if (!file_exists($source_path)) {
        error_log("원본 이미지 파일이 존재하지 않습니다: {$source_path}");
        return false;
    }

    // 이미지 정보 가져오기
    $image_info = getimagesize($source_path);
    if ($image_info === false) {
        error_log("이미지 정보를 가져올 수 없습니다: {$source_path}");
        return false;
    }

    $original_width = $image_info[0];
    $original_height = $image_info[1];
    $image_type = $image_info[2];

    // 지원하는 이미지 타입 확인
    if (!in_array($image_type, [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_GIF])) {
        error_log("지원하지 않는 이미지 타입입니다: {$image_type}");
        return false;
    }

    // 이미 최대 크기보다 작으면 리사이징 불필요
    if ($original_width <= $max_width) {
        // 품질만 조정하여 압축
        return compress_image_only($source_path, $quality);
    }

    // 새로운 크기 계산 (비율 유지)
    $ratio = $max_width / $original_width;
    $new_width = $max_width;
    $new_height = round($original_height * $ratio);

    // 원본 이미지 생성
    $source_image = null;
    switch ($image_type) {
        case IMAGETYPE_JPEG:
            $source_image = imagecreatefromjpeg($source_path);
            break;
        case IMAGETYPE_PNG:
            $source_image = imagecreatefrompng($source_path);
            break;
        case IMAGETYPE_GIF:
            $source_image = imagecreatefromgif($source_path);
            break;
    }

    if (!$source_image) {
        error_log("원본 이미지를 생성할 수 없습니다: {$source_path}");
        return false;
    }

    // 새 이미지 생성
    $new_image = imagecreatetruecolor($new_width, $new_height);

    // PNG 투명도 유지
    if ($image_type == IMAGETYPE_PNG) {
        imagealphablending($new_image, false);
        imagesavealpha($new_image, true);
        $transparent = imagecolorallocatealpha($new_image, 255, 255, 255, 127);
        imagefilledrectangle($new_image, 0, 0, $new_width, $new_height, $transparent);
    }

    // 이미지 리사이징
    if (!imagecopyresampled($new_image, $source_image, 0, 0, 0, 0, $new_width, $new_height, $original_width, $original_height)) {
        error_log("이미지 리사이징에 실패했습니다: {$source_path}");
        imagedestroy($source_image);
        imagedestroy($new_image);
        return false;
    }

    // 임시 파일로 저장
    $temp_path = $source_path . '.tmp';
    $success = false;

    switch ($image_type) {
        case IMAGETYPE_JPEG:
            $success = imagejpeg($new_image, $temp_path, $quality);
            break;
        case IMAGETYPE_PNG:
            // PNG 품질은 0-9 (낮을수록 압축률 높음)
            $png_quality = round((100 - $quality) / 11.11);
            $success = imagepng($new_image, $temp_path, $png_quality);
            break;
        case IMAGETYPE_GIF:
            $success = imagegif($new_image, $temp_path);
            break;
    }

    // 메모리 해제
    imagedestroy($source_image);
    imagedestroy($new_image);

    if (!$success) {
        error_log("이미지 저장에 실패했습니다: {$temp_path}");
        if (file_exists($temp_path)) {
            unlink($temp_path);
        }
        return false;
    }

    // 원본 파일을 임시 파일로 교체
    if (!rename($temp_path, $source_path)) {
        error_log("파일 교체에 실패했습니다: {$source_path}");
        if (file_exists($temp_path)) {
            unlink($temp_path);
        }
        return false;
    }

    return true;
}

/**
 * 이미지 품질만 조정하여 압축하는 함수 (크기는 변경하지 않음)
 * 
 * @param string $source_path 원본 이미지 경로
 * @param int $quality 이미지 품질 (기본값: 80)
 * @return bool 성공 시 true, 실패 시 false
 */
function compress_image_only($source_path, $quality = 80) {
    // GD 라이브러리 확인
    if (!extension_loaded('gd')) {
        error_log("GD 라이브러리가 설치되지 않았습니다.");
        return false;
    }

    // 파일 존재 확인
    if (!file_exists($source_path)) {
        error_log("원본 이미지 파일이 존재하지 않습니다: {$source_path}");
        return false;
    }

    // 이미지 정보 가져오기
    $image_info = getimagesize($source_path);
    if ($image_info === false) {
        error_log("이미지 정보를 가져올 수 없습니다: {$source_path}");
        return false;
    }

    $image_type = $image_info[2];

    // 지원하는 이미지 타입 확인
    if (!in_array($image_type, [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_GIF])) {
        error_log("지원하지 않는 이미지 타입입니다: {$image_type}");
        return false;
    }

    // 원본 이미지 생성
    $source_image = null;
    switch ($image_type) {
        case IMAGETYPE_JPEG:
            $source_image = imagecreatefromjpeg($source_path);
            break;
        case IMAGETYPE_PNG:
            $source_image = imagecreatefrompng($source_path);
            break;
        case IMAGETYPE_GIF:
            $source_image = imagecreatefromgif($source_path);
            break;
    }

    if (!$source_image) {
        error_log("원본 이미지를 생성할 수 없습니다: {$source_path}");
        return false;
    }

    // 임시 파일로 저장
    $temp_path = $source_path . '.tmp';
    $success = false;

    switch ($image_type) {
        case IMAGETYPE_JPEG:
            $success = imagejpeg($source_image, $temp_path, $quality);
            break;
        case IMAGETYPE_PNG:
            // PNG 품질은 0-9 (낮을수록 압축률 높음)
            $png_quality = round((100 - $quality) / 11.11);
            $success = imagepng($source_image, $temp_path, $png_quality);
            break;
        case IMAGETYPE_GIF:
            $success = imagegif($source_image, $temp_path);
            break;
    }

    // 메모리 해제
    imagedestroy($source_image);

    if (!$success) {
        error_log("이미지 압축에 실패했습니다: {$temp_path}");
        if (file_exists($temp_path)) {
            unlink($temp_path);
        }
        return false;
    }

    // 원본 파일을 임시 파일로 교체
    if (!rename($temp_path, $source_path)) {
        error_log("파일 교체에 실패했습니다: {$source_path}");
        if (file_exists($temp_path)) {
            unlink($temp_path);
        }
        return false;
    }

    return true;
}
