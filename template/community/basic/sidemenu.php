<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가
?>
<div class="offcanvas offcanvas-end" tabindex="-1" id="site-menu" aria-labelledby="siteMenuLabel">
    <div class="offcanvas-header">
        <h5 class="offcanvas-title d-none" id="siteMenuLabel">메뉴</h5>
        <button type="button" class="btn-close" data-bs-dismiss="offcanvas" aria-label="Close"></button>
    </div>
    <div class="offcanvas-body p-0 d-flex flex-column">
        <!-- 회원 관련 링크 -->
        <div class="pb-3 px-3">
            <div class="member-actions">
                <?php if ($is_member) { ?>
                    <div class="d-flex gap-2">
                        <a href="<?php echo CM_MB_URL ?>/mypage.php" class="btn btn-outline-primary btn-sm flex-fill rounded-0">
                            <i class="bi bi-person-lines-fill me-1"></i>마이페이지
                        </a>
                        <a href="<?php echo CM_MB_URL ?>/logout.php" class="btn btn-outline-secondary btn-sm flex-fill rounded-0">
                            <i class="bi bi-box-arrow-right me-1"></i>로그아웃
                        </a>
                    </div>
                <?php } else { ?>
                    <div class="d-flex gap-2">
                        <a href="<?php echo CM_MB_URL ?>/login.php" class="btn btn-outline-primary btn-sm flex-fill rounded-0">
                            <i class="bi bi-box-arrow-in-right me-1"></i>로그인
                        </a>
                        <a href="<?php echo CM_MB_URL ?>/register.php" class="btn btn-outline-success btn-sm flex-fill rounded-0">
                            <i class="bi bi-person-plus me-1"></i>회원가입
                        </a>
                    </div>
                <?php } ?>
				<!-- 관리자 영역 (하단 고정) -->
				<?php if ($is_member && $is_admin) { ?>
					<div class="w-100 mt-2">
						<a href="<?php echo CM_ADMIN_URL ?>" class="btn btn-danger w-100 rounded-0">
							<i class="bi bi-shield-lock me-2"></i>관리자
						</a>
					</div>
				<?php } ?>
            </div>
        </div>

        <!-- 메뉴 영역 (확장 가능) -->
        <div class="flex-grow-1">
            <?php 
            // 메뉴 라이브러리가 있는지 확인
            if (function_exists('generateAccordionMenu')) {
                // 최상위 메뉴 (parent_id = 0)부터 시작, 레벨 1로 시작
                echo generateAccordionMenu(0, 1);
            } else {
                // 메뉴 라이브러리가 없을 경우 기본 메뉴 표시
                echo '<div class="alert alert-warning m-3">메뉴를 불러올 수 없습니다.</div>';
            }
            ?>
        </div>

        
    </div>

    <script>
        $(document).ready(function() {
            // 아코디언 버튼에 화살표 아이콘 추가
            $('#site-menu .accordion-button').each(function() {
                if (!$(this).hasClass('no-arrow')) {
                    $(this).append('<i class="bi bi-chevron-down accordion-arrow"></i>');
                }
            });

            // 아코디언 버튼 클릭 시 화살표 방향 변경
            $('#site-menu .accordion-button').on('click', function() {
                $('#site-menu .accordion-button').each(function() {
                    if ($(this).hasClass('no-arrow')) {
                        return; // 화살표 없는 버튼은 제외
                    }
                    var $arrow = $(this).find('.accordion-arrow');
                    if ($(this).attr('aria-expanded') === 'true') {
                        // 열려 있는 경우 위쪽 화살표
                        $arrow.removeClass('bi-chevron-down').addClass('bi-chevron-up');
                    } else {
                        // 닫혀 있는 경우 아래쪽 화살표
                        $arrow.removeClass('bi-chevron-up').addClass('bi-chevron-down');
                    }
                });
            });

            // 초기 상태 설정
            $('#site-menu .accordion-button').each(function() {
                if ($(this).hasClass('no-arrow')) {
                    return; // 화살표 없는 버튼은 제외
                }
                var $arrow = $(this).find('.accordion-arrow');
                if ($(this).attr('aria-expanded') === 'true') {
                    $arrow.removeClass('bi-chevron-down').addClass('bi-chevron-up');
                } else {
                    $arrow.removeClass('bi-chevron-up').addClass('bi-chevron-down');
                }
            });
        });
    </script>
</div>