<?php
include_once('./_common.php'); // 공통 스크립트 포함

$cm_title = '비밀번호 확인'; // 페이지 제목 설정
include_once(CM_PATH.'/head_sub.php'); // 서브 헤더 포함
include_once CM_BOARD_PATH.'/board.lib.php';

$previousPage = $_SERVER['HTTP_REFERER']; // 이전 페이지 URL 저장
?>

<div id="pass-form">
	<div class="pass-container">
		<h2>비밀번호 확인</h2>

			<div class="input-wrapper">
				<input type="hidden" id="actionType" value="<?php echo htmlspecialchars($_GET['act'] ?? ''); ?>">
				<?php if ($is_member): ?>
                    <!-- 회원: 이메일 hidden 처리 -->
                    <input type="hidden" id="checkEmail" value="<?php echo htmlspecialchars($member['user_email'] ?? ''); ?>">
                <?php else: ?>
                    <!-- 비회원: 이메일 입력창 표시 -->
                    <input 
					type="email" 
					id="checkEmail" 
					class="password-input" 
					placeholder="이메일을 입력해주세요"
					required
					/>
                    <div id="emailError"></div>
                <?php endif; ?>

				<input
				type="password"
				id="checkPassword"
				class="password-input"
				placeholder="비밀번호를 입력해주세요"
				required
				/>
				<div id="passwordError" class=""></div>
			</div>

			<div class="button-group">
				<button id="cancelBtn" class="button button-cancel" onclick="window.location.href='<?php echo $previousPage;?>'">취소</button>
				<?php if (isset($_GET['act'])) {?>
					<?php if($_GET['act'] == "edit"){?>
						<button type="button" id="confirmPassword" class="button button-submit"><i class="fas fa-edit me-1"></i> 수정</button>
					<?php } else if ($_GET['act'] == "delete"){?>
						<button type="button" id="confirmPassword" class="button button-submit"><i class="fas fa-user-times me-1"></i> 삭제</button>
					<?php } ?>
				<?php } ?>
			</div>

	</div>
</div>

<?php
//js 경로
echo '<script>
const boardId 	= ' . json_encode($boardId) . ';
const boardNum	= ' . json_encode($boardNum) . ';
const is_member	= ' . json_encode($is_member) . ';
</script>';
echo '<script src="' . CM_URL . '/js/board.view.js?ver=' . time() . '"></script>';
include_once(CM_PATH.'/tail_sub.php'); // 서브 푸터 포함
?>