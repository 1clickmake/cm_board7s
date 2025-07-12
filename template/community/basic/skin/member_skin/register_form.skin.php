<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가 
?>
<div class="container my-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div id="updateForm">
                <h2 class="text-center mb-4"><?php echo $cm_title;?></h2>
                <form id="registerForm" method="post" action="./register_form_update.php">
					<input type="hidden" name="g-recaptcha-response" id="g-recaptcha-response">
                    <input type="hidden" name="w" value="<?php echo $w;?>">
                    
                    <div class="mb-3">
						<label for="user_id" class="form-label" style="color: #555;">아이디</label>
						<input type="text" class="form-control" id="user_id" name="user_id" value="<?php echo $member['user_id'] ?? '';?>" placeholder="아이디를 입력하세요" required autofocus <?php if($update){?>readonly<?php } ?>>
						<div id="user_idError" class="form-text text-danger"></div>
					</div>
                    <div class="mb-3">
                        <label for="user_name" class="form-label">이름</label>
                        <input type="text" class="form-control" id="user_name" name="user_name" value="<?php echo $member['user_name'] ?? ''; ?>" required>
                        <div id="user_nameError" class="form-text text-danger"></div>
                    </div>

                    <div class="mb-3">
                        <label for="user_password" class="form-label">새 비밀번호</label>
                        <input type="password" class="form-control" id="user_password" name="user_password">
                        <?php if($update){?><small class="text-muted">변경하지 않으려면 비워두세요</small><?php } ?>
                        <div id="user_passwordError" class="form-text text-danger"></div>
                    </div>

                    <div class="mb-3">
                        <label for="password_confirm" class="form-label">새 비밀번호 확인</label>
                        <input type="password" class="form-control" id="password_confirm" name="password_confirm">
                        <div id="password_confirmError" class="form-text text-danger"></div>
                    </div>

                    <div class="mb-3">
                        <label for="user_email" class="form-label">이메일</label>
                        <input type="email" class="form-control" id="user_email" name="user_email" value="<?php echo $member['user_email'] ?? ''; ?>" required>
                        <div id="user_emailError" class="form-text text-danger"></div>
                    </div>

                    <div class="mb-3">
                        <label for="user_hp" class="form-label">휴대폰번호</label>
                        <input type="tel" class="form-control" id="user_hp" name="user_hp" value="<?php echo $member['user_hp'] ?? ''; ?>">
                        <div id="user_hpError" class="form-text text-danger"></div>
                    </div>

                    <div class="text-center">
                        <button type="submit" class="btn btn-primary" id="submitButton"><?php if($update) echo '수정'; else echo '가입';?></button>
                        <button type="button" onclick="history.back()" class="btn btn-secondary">취소</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>