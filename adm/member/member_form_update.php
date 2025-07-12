<?php
include_once './_common.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
	alert('잘못된 요청 방식입니다.' );
}

// 폼 데이터 수집
$action = isset($_POST['action']) ? trim($_POST['action']) : '';
$user_id = isset($_POST['user_id']) ? trim($_POST['user_id']) : '';
$user_no = isset($_POST['user_no']) ? trim($_POST['user_no']) : 0;
$user_name = isset($_POST['user_name']) ? trim($_POST['user_name']) : '';
$user_password = isset($_POST['user_password']) ? trim($_POST['user_password']) : '';
$user_email = isset($_POST['user_email']) ? trim($_POST['user_email']) : '';
$user_hp = isset($_POST['user_hp']) ? trim($_POST['user_hp']) : '';
$user_lv = isset($_POST['user_lv']) ? (int)$_POST['user_lv'] : 1;

// 기본 유효성 검사
if (empty($user_id) || empty($user_name) || $user_lv < 1) {
	alert('필수 입력 항목이 누락되었습니다.');
}

// 삭제 처리
if ($action === 'delete') {

	if ($user_no <= 0) {
		alert('잘못된 회원 번호입니다.');
	}

	try {
		global $pdo;
		$pdo->beginTransaction();

		// 회원 관련 데이터 삭제
		$deletePoint = process_data_delete('cm_point', ['user_id' => $user_id]);
		$deleteUser = process_data_delete('cm_users', ['user_no' => $user_no]);

		$pdo->commit();
		alert('회원이 성공적으로 삭제되었습니다.', 'member_list.php');
	} catch (Exception $e) {
		if (isset($pdo)) {
			$pdo->rollBack();
		}
		alert('삭제 중 오류가 발생했습니다: ' . $e->getMessage());
	}
}



// 이메일 중복 체크
if (!empty($user_email)) {
	try {
		$sql = "SELECT COUNT(*) FROM cm_users WHERE user_email = :user_email";
		$params = ['user_email' => $user_email];
		
		if ($action === 'update') {
			$sql .= " AND user_no != :user_no";
			$params['user_no'] = $_POST['user_no'];
		}
		
		$stmt = $pdo->prepare($sql);
		$stmt->execute($params);
		if ($stmt->fetchColumn() > 0) {
			alert('이미 사용 중인 이메일입니다.');
		}
	} catch (PDOException $e) {
		alert('오류: ' . $e->getMessage());
	}
}

// 신규 등록 처리
if ($action === 'insert') {
	if (empty($user_password)) {
		alert('비밀번호를 입력해주세요.');
	}
	
	
	// 아이디 중복 체크 (신규 등록 시)
	if ($action === 'insert') {
		try {
			$stmt = $pdo->prepare("SELECT COUNT(*) FROM cm_users WHERE user_id = :user_id");
			$stmt->execute(['user_id' => $user_id]);
			if ($stmt->fetchColumn() > 0) {
				alert('이미 사용 중인 아이디입니다.');
			}
		} catch (PDOException $e) {
			alert('오류: ' . $e->getMessage());
		}
	}


	$userData = [
		'user_id' => $user_id,
		'user_password' => password_hash($user_password, PASSWORD_DEFAULT),
		'user_name' => $user_name,
		'user_email' => $user_email ?: null,
		'user_hp' => $user_hp ?: null,
		'user_lv' => $user_lv,
		'user_point' => 0,
		'user_block' => 0,
		'user_leave' => 0
	];

	try {
		$insertResult = process_data_insert('cm_users', $userData);
		if ($insertResult !== false) {
			alert('회원이 성공적으로 등록되었습니다.', 'member_form.php?user_no='.$insertResult);
		} else {
			alert('회원 등록 중 오류가 발생했습니다.');
		}
	} catch (Exception $e) {
		alert('회원 등록 중 오류가 발생했습니다: ' . $e->getMessage());
	}
}

// 수정 처리
if ($action === 'update') {
	$user_no = isset($_POST['user_no']) ? (int)$_POST['user_no'] : 0;
	if ($user_no <= 0) {
		alert('잘못된 회원 번호입니다.');
	}

	$userData = [
		'user_name' => $user_name,
		'user_email' => $user_email ?: '',
		'user_hp' => $user_hp ?: '',
		'user_lv' => $user_lv,
		'user_block' => isset($_POST['user_block']) && $_POST['user_block'] == '1' ? 1 : 0,
		'user_leave' => isset($_POST['user_leave']) && $_POST['user_leave'] == '1' ? 1 : 0
	];

	// 비밀번호가 제공된 경우 업데이트
	if (!empty($user_password)) {
		$userData['user_password'] = password_hash($user_password, PASSWORD_DEFAULT);
	}

	try {
		$updateResult = process_data_update('cm_users', $userData, ['user_no' => $user_no]);
		if ($updateResult !== false) {
			alert('회원 정보가 성공적으로 수정되었습니다.', 'member_form.php?user_no=' . $user_no);
		} else {
			alert('회원 정보 수정 중 오류가 발생했습니다.');
		}
	} catch (Exception $e) {
		alert('회원 정보 수정 중 오류가 발생했습니다: ' . $e->getMessage());
	}
}

