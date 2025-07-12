<?php
include_once('./_common.php'); // 공통 스크립트 포함

$cm_title = '비밀번호 확인'; // 페이지 제목 설정
include_once(CM_PATH.'/head_sub.php'); // 서브 헤더 포함
$previousPage = $_SERVER['HTTP_REFERER']; // 이전 페이지 URL 저장
?>

<div id="pass-form">
	<div class="pass-container">
		<h2>임시비밀번호 생성</h2>
		<form id="forgotPasswordForm">
			<div class="input-wrapper">
				<input
				type="text"
				id="user_id"
				name="user_id"
				class="password-input"
				placeholder="아이디를 입력하세요"
				/>
			
				<input
				type="email"
				id="user_email"
				name="user_email"
				class="password-input"
				placeholder="이메일을 입력하세요"
				/>
				<div id="forgotPasswordError" class=""></div>
				<div id="tempPasswordDisplay" class=""></div>
			</div>

			<div class="button-group">
				<button type="button" id="cancelBtn" class="button button-cancel" onclick="window.location.href='<?php echo CM_URL;?>'">취소</button>
				<button type="button" id="forgotPasswordSubmit" class="button button-submit"><i class="fa-solid fa-key"></i> 확인</button>
			</div>
		</form>
	</div>
</div>

<?php
//js 경로
echo '<script src="'.CM_URL.'/js/lost_password.js?ver='.time().'"></script>';
include_once(CM_PATH.'/tail_sub.php'); // 서브 푸터 포함
?>