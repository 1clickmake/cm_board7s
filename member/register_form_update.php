<?php
include_once('./_common.php');
/**
 * 회원가입 처리 스크립트
 * Ajax 요청을 통해 회원 정보를 검증하고 데이터베이스에 저장
 */

// 헤더 설정: JSON 응답으로 지정
header('Content-Type: application/json');

// 응답용 배열 초기화
$response = [
    'status' => 'error',
    'message' => '',
    'field' => ''
];

// POST 요청인지 확인
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $response['message'] = '올바른 접근 방식이 아닙니다';
    echo json_encode($response, JSON_UNESCAPED_UNICODE);
    exit;
}

// reCAPTCHA 검증
if ($recaptcha_site && $recaptcha_secret){
	$recaptcha_response = isset($_POST['g-recaptcha-response']) ? $_POST['g-recaptcha-response'] : '';

	if (empty($recaptcha_response)) {
		$response['message'] = '캡챠 인증이 필요합니다';
		echo json_encode($response, JSON_UNESCAPED_UNICODE);
		exit;
	}

	$verify = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret={$recaptcha_secret}&response={$recaptcha_response}");
	$captcha_success = json_decode($verify);

	if ($captcha_success->success == false) {
		$response['message'] = '캡챠 인증에 실패했습니다';
		echo json_encode($response, JSON_UNESCAPED_UNICODE);
		exit;
	}
}
// reCAPTCHA 검증 끝

$w = isset($_POST['w']) ? $_POST['w'] : '';

if ($w == 'update') {
    // 회원정보 수정 처리
    if (!$is_member) {
        $response['message'] = '회원만 이용하실 수 있습니다';
        echo json_encode($response, JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 필수 필드 확인
    $required_fields = ['user_id', 'user_name', 'user_email'];
    foreach ($required_fields as $field) {
        if (empty($_POST[$field])) {
            $response['message'] = '필수 항목을 입력해주세요';
            $response['field'] = $field;
            echo json_encode($response, JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    // 입력 데이터 가져오기 및 필터링
    $user_id = filter_input(INPUT_POST, 'user_id', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $user_name = filter_input(INPUT_POST, 'user_name', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $user_password = $_POST['user_password']; // 비밀번호는 해시 전에 필터링하지 않음
    $password_confirm = $_POST['password_confirm']; // 필드 이름 수정
    $user_email = filter_input(INPUT_POST, 'user_email', FILTER_SANITIZE_EMAIL);
    $user_hp = filter_input(INPUT_POST, 'user_hp', FILTER_SANITIZE_FULL_SPECIAL_CHARS);

    // 비밀번호 변경이 있는 경우 검증
    if (!empty($user_password)) {
        if ($user_password !== $password_confirm) {
            $response['message'] = '비밀번호가 일치하지 않습니다';
            $response['field'] = 'password_confirm'; // 클라이언트와 일치하도록 수정
            echo json_encode($response, JSON_UNESCAPED_UNICODE);
            exit;
        }

        if (strlen($user_password) < 8) {
            $response['message'] = '비밀번호는 최소 8자 이상이어야 합니다';
            $response['field'] = 'user_password';
            echo json_encode($response, JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    // 이메일 유효성 검사
    if (!filter_var($user_email, FILTER_VALIDATE_EMAIL)) {
        $response['message'] = '유효한 이메일 주소를 입력해주세요';
        $response['field'] = 'user_email';
        echo json_encode($response, JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 이메일 중복 검사 (자기 자신 제외)
    try {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM cm_users WHERE user_email = :user_email AND user_id != :user_id");
        $stmt->bindParam(':user_email', $user_email);
        $stmt->bindParam(':user_id', $user_id);
        $stmt->execute();
        
        if ($stmt->fetchColumn() > 0) {
            $response['message'] = '이미 사용 중인 이메일입니다';
            $response['field'] = 'user_email';
            echo json_encode($response, JSON_UNESCAPED_UNICODE);
            exit;
        }
    } catch (PDOException $e) {
        $response['message'] = '데이터베이스 오류가 발생했습니다';
		$errorMessage = mb_convert_encoding($e->getMessage(), 'UTF-8', 'auto');
        error_log("이메일 중복 검사 오류: " . $errorMessage);
        echo json_encode($response, JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 휴대폰 번호 중복 검사 (입력된 경우에만)
    if (!empty($user_hp)) {
        $user_hp = get_only_number($user_hp);
        try {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM cm_users WHERE user_hp = :user_hp AND user_id != :user_id");
            $stmt->bindParam(':user_hp', $user_hp);
            $stmt->bindParam(':user_id', $user_id);
            $stmt->execute();
            
            if ($stmt->fetchColumn() > 0) {
                $response['message'] = '이미 사용 중인 연락처입니다';
                $response['field'] = 'user_hp';
                echo json_encode($response, JSON_UNESCAPED_UNICODE);
                exit;
            }
        } catch (PDOException $e) {
            $response['message'] = '데이터베이스 오류가 발생했습니다';
			$errorMessage = mb_convert_encoding($e->getMessage(), 'UTF-8', 'auto');
            error_log("연락처 중복 검사 오류: " . $errorMessage);
            echo json_encode($response, JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    // 업데이트할 데이터 준비
    $update_data = [
        'user_name' => $user_name,
        'user_email' => $user_email,
        'user_hp' => $user_hp
    ];

    // 비밀번호가 입력된 경우에만 업데이트
    if (!empty($user_password)) {
        $update_data['user_password'] = password_hash($user_password, PASSWORD_DEFAULT);
    }

    // 데이터 업데이트
    try {
        $sql = "UPDATE cm_users SET ";
        $params = [];
        foreach ($update_data as $key => $value) {
            $sql .= "{$key} = :{$key}, ";
            $params[":{$key}"] = $value;
        }
        $sql = rtrim($sql, ", ");
        $sql .= " WHERE user_id = :user_id";
        $params[':user_id'] = $user_id;

        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);

        $response['status'] = 'success';
        $response['message'] = '회원정보가 수정되었습니다';
    } catch (PDOException $e) {
        $response['message'] = '회원정보 수정 중 오류가 발생했습니다';
		$errorMessage = mb_convert_encoding($e->getMessage(), 'UTF-8', 'auto');
        error_log("회원정보 수정 오류: " . $errorMessage);
    }
} else {
    // 필수 필드 확인
    $required_fields = ['user_id', 'user_name', 'user_password', 'password_confirm', 'user_email'];
    foreach ($required_fields as $field) {
        if (empty($_POST[$field])) {
            $response['message'] = '모든 필수 항목을 입력해주세요';
            $response['field'] = $field;
            echo json_encode($response, JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    // 입력 데이터 가져오기 및 필터링
    $user_id = filter_input(INPUT_POST, 'user_id', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $user_name = filter_input(INPUT_POST, 'user_name', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $user_password = $_POST['user_password'];
    $password_confirm = $_POST['password_confirm'];
    $user_email = filter_input(INPUT_POST, 'user_email', FILTER_SANITIZE_EMAIL);
    $user_hp = filter_input(INPUT_POST, 'user_hp', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
	$user_recommend = filter_input(INPUT_POST, 'user_recommend', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
	
    // 비밀번호 확인
    if ($user_password !== $password_confirm) {
        $response['message'] = '비밀번호가 일치하지 않습니다';
        $response['field'] = 'password_confirm';
        echo json_encode($response, JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 비밀번호 길이 검증 
    if (strlen($user_password) < 8) {
        $response['message'] = '비밀번호는 최소 8자 이상이어야 합니다';
        $response['field'] = 'user_password';
        echo json_encode($response, JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 이메일 유효성 검사
    if (!filter_var($user_email, FILTER_VALIDATE_EMAIL)) {
        $response['message'] = '유효한 이메일 주소를 입력해주세요';
        $response['field'] = 'user_email';
        echo json_encode($response, JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 아이디 중복 검사
    try {
        $stmt = $pdo->prepare("SELECT * FROM cm_users WHERE user_id = :user_id");
        $stmt->bindParam(':user_id', $user_id);
        $stmt->execute();
        
        $user = $stmt->fetch(PDO::FETCH_ASSOC); // Fetch the user data if it exists
    
		if ($user) { // Check if a user with the given ID exists
			if (isset($user['user_leave']) && $user['user_leave'] == 1) {
				$response['message'] = '탈퇴한 회원 아이디입니다.';
				$response['field'] = 'user_id';
				echo json_encode($response, JSON_UNESCAPED_UNICODE);
				exit;
			} elseif (isset($user['user_block']) && $user['user_block'] == 1) {
				$response['message'] = '접근이 차단된 아이디입니다.';
				$response['field'] = 'user_id';
				echo json_encode($response, JSON_UNESCAPED_UNICODE);
				exit;
			} else {
				// User exists, but is neither withdrawn nor blocked (means it's an active, in-use ID)
				$response['message'] = '이미 사용 중인 아이디입니다.';
				$response['field'] = 'user_id';
				echo json_encode($response, JSON_UNESCAPED_UNICODE);
				exit;
			}
		}
		
    } catch (PDOException $e) {
        $response['message'] = '데이터베이스 오류가 발생했습니다';
		$errorMessage = mb_convert_encoding($e->getMessage(), 'UTF-8', 'auto');
        error_log("아이디 중복 검사 오류: " . $errorMessage);
        echo json_encode($response, JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 이메일 중복 검사
    if (!empty($user_email)) {
        try {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM cm_users WHERE user_email = :user_email");
            $stmt->bindParam(':user_email', $user_email);
            $stmt->execute();
            
            if ($stmt->fetchColumn() > 0) {
                $response['message'] = '이미 사용 중인 이메일입니다';
                $response['field'] = 'user_email';
                echo json_encode($response, JSON_UNESCAPED_UNICODE);
                exit;
            }
        } catch (PDOException $e) {
            $response['message'] = '데이터베이스 오류가 발생했습니다';
			$errorMessage = mb_convert_encoding($e->getMessage(), 'UTF-8', 'auto');
            error_log("이메일 중복 검사 오류: " . $errorMessage);
            echo json_encode($response, JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    // 휴대폰 번호 중복 검사 (입력된 경우에만)
    if (!empty($user_hp)) {
        $user_hp = get_only_number($user_hp);
        try {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM cm_users WHERE user_hp = :user_hp");
            $stmt->bindParam(':user_hp', $user_hp);
            $stmt->execute();
            
            if ($stmt->fetchColumn() > 0) {
                $response['message'] = '이미 사용 중인 연락처입니다';
                $response['field'] = 'user_hp';
                echo json_encode($response, JSON_UNESCAPED_UNICODE);
                exit;
            }
        } catch (PDOException $e) {
            $response['message'] = '데이터베이스 오류가 발생했습니다';
			$errorMessage = mb_convert_encoding($e->getMessage(), 'UTF-8', 'auto');
            error_log("연락처 중복 검사 오류: " . $errorMessage);
            echo json_encode($response, JSON_UNESCAPED_UNICODE);
            exit;
        }
    }
	
	// 추천인 중복 검사
	if (!empty($user_recommend)) {
		try {
			$stmt = $pdo->prepare("SELECT COUNT(*) FROM cm_users WHERE user_id = :user_id");
			$stmt->bindParam(':user_id', $user_recommend);
			$stmt->execute();
			
			if ($stmt->fetchColumn() <= 0) {
				$response['message'] = '가입되지 않은 회원입니다.';
				$response['field'] = 'user_id';
				echo json_encode($response, JSON_UNESCAPED_UNICODE);
				exit;
			}
			
		} catch (PDOException $e) {
			$response['message'] = '데이터베이스 오류가 발생했습니다';
			error_log("추천인 검사 오류: " . mb_convert_encoding($e->getMessage(), 'UTF-8', 'auto'));
			echo json_encode($response, JSON_UNESCAPED_UNICODE);
			exit;
		}
	}


    // 비밀번호 해시 생성
    $hashed_password = password_hash($user_password, PASSWORD_DEFAULT);

    // 삽입할 데이터 준비
    $userData = [
        'user_id' => $user_id,
        'user_name' => $user_name,
        'user_password' => $hashed_password,
        'user_email' => $user_email,
		'user_hp' => $user_hp,
        'user_lv' => 2,
		'user_point' => 0,
        'user_block' => 0,
        'user_leave' => 0,
		'user_recommend' => $user_recommend ?? '',
        'today_login' => date('Y-m-d H:i:s')
    ];

    // 데이터 삽입 함수 호출
    $insert_result = process_data_insert('cm_users', $userData);

    // 삽입 결과 확인
    if ($insert_result !== false) {
        $response['status'] = 'success';
        $response['message'] = '회원가입이 완료되었습니다';
        $response['user_no'] = $insert_result; // 생성된 user_no 반환
        
        // 회원가입 성공 시 세션에 사용자 아이디 저장
        $_SESSION['user_id'] = $user_id;
    } else {
        $response['message'] = '회원가입 처리 중 오류가 발생했습니다1';
    }
}

// JSON 응답 출력
echo json_encode($response, JSON_UNESCAPED_UNICODE);
exit;