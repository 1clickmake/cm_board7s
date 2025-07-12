<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가
?>
<div id="login-form" class="container-fluid d-flex justify-content-center align-items-center">
  <div class="card shadow-lg p-4" style="max-width: 400px; width: 100%; border-radius: 15px;">
    <div class="card-body">
      <h3 class="text-center mb-4" style="color: #333; font-weight: 600;">로그인</h3>
      <form id="loginForm" method="post">
        <div class="mb-3">
          <label for="user_id" class="form-label" style="color: #555;">아이디</label>
          <input type="text" class="form-control" id="user_id" name="user_id" placeholder="아이디를 입력하세요" required autofocus>
        </div>
        <div class="mb-3">
          <label for="user_password" class="form-label" style="color: #555;">비밀번호</label>
          <input type="password" class="form-control" id="user_password" name="user_password" placeholder="비밀번호를 입력하세요" required>
        </div>
        <div id="loginError" class="alert alert-danger d-none mb-3"></div>
        <div class="d-flex justify-content-between align-items-center mb-3">
          <a href="<?php echo CM_MB_URL?>/lost_password.php" class="text-decoration-none"  style="color: #007bff; font-size: 0.9rem;">비밀번호를 잊으셨나요?</a>
        </div>
        <button type="submit" class="btn btn-primary w-100" style="border-radius: 10px; padding: 10px; font-weight: 500;">로그인</button>
      </form>
      <div class="text-center mt-3">
        <p class="mb-0" style="color: #777; font-size: 0.9rem;">계정이 없으신가요? <a href="<?php echo CM_MB_URL?>/register_form.php" class="text-decoration-none" style="color: #007bff;">회원가입</a></p>
      </div>
    </div>
  </div>
</div>
