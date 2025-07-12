<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가 
?>
<!-- Footer  -->
<footer class="footer">
	<section class="py-5 bg-dark mt-0 text-center">
      <div class="container">
        <div class="row f-flex justify-content-between" style="justify-content: space-between;">

          <div class="col-md-4 text-dark my-1">

            <p class="mt-2  text-primary">
                <a class="text-white" href="#">이용약관</a> 
                <span class="text-white mx-2">|</span> 
                <a class="text-white" href="#">개인정보보호정책</a> 
            </p>
          </div>
          <div class="col-md-2">
            <h2 class="fw-bold mb-3 mb-md-0"><a href="<?php echo CM_URL;?>" class="text-white"><?php echo $config['site_title'];?></a></h2>
          </div>

          <div class="col-md-4 my-1">
            <div class="btn-container mt-1 text-md-right text-sm-center">
              <div class="mb-1 mr-3 align-self-right pt-0 d-inline-block">
                <div class="sns-icons">
                  <?php if (!empty($config['sns_facebook'])): ?>
                  <a href="<?php echo htmlspecialchars($config['sns_facebook']); ?>" target="_blank" class="sns-icon" title="Facebook">
                    <i class="fab fa-facebook-f"></i>
                  </a>
                  <?php endif; ?>

                  <?php if (!empty($config['sns_x'])): ?>
                  <a href="<?php echo htmlspecialchars($config['sns_x']); ?>" target="_blank" class="sns-icon" title="X (트위터)">
                  <i class="bi bi-twitter-x"></i>
                  </a>
                  <?php endif; ?>

                  <?php if (!empty($config['sns_kakao'])): ?>
                  <a href="<?php echo htmlspecialchars($config['sns_kakao']); ?>" target="_blank" class="sns-icon" title="카카오톡">
                    <i class="fas fa-comment"></i>
                  </a>
                  <?php endif; ?>

                  <?php if (!empty($config['sns_naver'])): ?>
                  <a href="<?php echo htmlspecialchars($config['sns_naver']); ?>" target="_blank" class="sns-icon" title="네이버 블로그">
                    <i class="fas fa-blog"></i>
                  </a>
                  <?php endif; ?>

                  <?php if (!empty($config['sns_line'])): ?>
                  <a href="<?php echo htmlspecialchars($config['sns_line']); ?>" target="_blank" class="sns-icon" title="LINE">
                    <i class="fab fa-line"></i>
                  </a>
                  <?php endif; ?>

                  <?php if (!empty($config['sns_pinterest'])): ?>
                  <a href="<?php echo htmlspecialchars($config['sns_pinterest']); ?>" target="_blank" class="sns-icon" title="Pinterest">
                    <i class="fab fa-pinterest"></i>
                  </a>
                  <?php endif; ?>

                  <?php if (!empty($config['sns_linkedin'])): ?>
                  <a href="<?php echo htmlspecialchars($config['sns_linkedin']); ?>" target="_blank" class="sns-icon" title="LinkedIn">
                    <i class="fab fa-linkedin-in"></i>
                  </a>
                  <?php endif; ?>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="copyright mt-2 text-center text-white">
      Copyright © 2025 <?php echo $config['site_title'];?>. All Rights Reserved.
      </div>
    </section>
</footer>