<?php
include_once('./_common.php'); // 공통 스크립트 포함

$cm_title = '비밀번호 확인'; // 페이지 제목 설정
include_once(CM_PATH.'/head_sub.php'); // 서브 헤더 포함
$previousPage = $_SERVER['HTTP_REFERER']; // 이전 페이지 URL 저장
?>

<div id="pass-form">
	<div class="pass-container">
		<h2>비밀번호 확인</h2>
		<form id="passwordCheckForm">
			<div class="input-wrapper">
				<input
				type="password"
				id="user_password"
				name="user_password"
				class="password-input"
				placeholder="비밀번호를 입력해주세요"
				/>
				<div id="passwordError" class=""></div>
			</div>

			<div class="button-group">
				<button id="cancelBtn" class="button button-cancel" onclick="window.location.href='<?php echo $previousPage;?>'">취소</button>
				<?php if (isset($_GET['act'])) {?>
					<?php if($_GET['act'] == "update"){?>
						<button type="submit" id="ConfirmUpdateBtn" class="button button-submit"><i class="fas fa-edit me-1"></i> 정보수정</button>
					<?php } else if ($_GET['act'] == "leave"){?>
						<button type="submit" id="ConfirmUpdateBtn" class="button button-submit"><i class="fas fa-user-times me-1"></i> 회원탈퇴</button>
					<?php } ?>
				<?php } ?>
			</div>
		</form>
	</div>
</div>

<?php
//js 경로
echo '<script>
const user_id = "'.htmlspecialchars($member['user_id']).'";
</script>';
echo '<script src="'.CM_URL.'/js/mypage.js?ver='.time().'"></script>';
include_once(CM_PATH.'/tail_sub.php'); // 서브 푸터 포함
?>