<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가
?>

<!-- Sidebar { -->
<div class="sidebar" id="sidebar">
    <div class="sidebar-header d-flex justify-content-between align-items-center p-3 bg-dark text-white">
        <h5 class="mb-0">Menu</h5>
        <button type="button" class="btn-close btn-close-white" id="closeSidebar" aria-label="Close"></button>
    </div>
    <div class="p-3">
        <ul class="nav flex-column">

            <!-- Home -->
            <li class="nav-item">
                <a class="nav-link active" href="<?php echo CM_ADMIN_URL ?>"><i class="bi bi-speedometer"></i> Home</a>
            </li>
			
			<li class="nav-item">
                <a class="nav-link" href="<?php echo CM_ADMIN_URL ?>/config/contact_list.php"><i class="bi bi-chat-dots"></i> 문의관리</a>
            </li>

            <!-- 홈페이지 설정 -->
            <li class="nav-item">
                <a class="nav-link d-flex justify-content-between align-items-center"
                   data-bs-toggle="collapse"
                   href="#submenu-config"
                   role="button"
                   aria-expanded="true"
                   aria-controls="submenu-config">
                    홈페이지 설정
                    <i class="bi bi-chevron-down ms-2 toggle-icon" data-target="submenu-config"></i>
                </a>
                <div class="collapse ps-1" id="submenu-config">
                    <ul class="nav flex-column my-2">
                        <li class="nav-item">
                            <a class="nav-link" href="<?php echo CM_ADMIN_URL ?>/config/config_form.php"><i class="bi bi-dot"></i> 환경설정</a>
                        </li>
						<li class="nav-item">
                            <a class="nav-link" href="<?php echo CM_ADMIN_URL ?>/config/menu_form.php"><i class="bi bi-dot"></i> 메뉴관리</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="<?php echo CM_ADMIN_URL ?>/config/design_form.php"><i class="bi bi-dot"></i> 디자인관리</a>
                        </li>
						<li class="nav-item">
                            <a class="nav-link" href="<?php echo CM_ADMIN_URL ?>/config/popup_list.php"><i class="bi bi-dot"></i> 팝업관리</a>
                        </li>
						<li class="nav-item">
                            <a class="nav-link" href="<?php echo CM_ADMIN_URL ?>/config/folder_list.php"><i class="bi bi-dot"></i> 폴더구조</a>
                        </li>
						<li class="nav-item">
                            <a class="nav-link" href="<?php echo CM_ADMIN_URL ?>/config/db_list.php"><i class="bi bi-dot"></i> DB 테이블 확인</a>
                        </li>
						<!--
                        <li class="nav-item">
                            <a class="nav-link" href="<?php echo CM_ADMIN_URL ?>/config/sms_form.php"><i class="bi bi-dot"></i> 문자(SMS)설정</a>
                        </li>
						-->
                    </ul>
                </div>
            </li>

            <!-- 회원관리 -->
            <li class="nav-item">
                <a class="nav-link d-flex justify-content-between align-items-center"
                   data-bs-toggle="collapse"
                   href="#submenu-member"
                   role="button"
                   aria-expanded="false"
                   aria-controls="submenu-member">
                    회원관리
                    <i class="bi bi-chevron-down ms-2 toggle-icon" data-target="submenu-member"></i>
                </a>
                <div class="collapse ps-1" id="submenu-member">
                    <ul class="nav flex-column my-2">
                        <li class="nav-item">
                            <a class="nav-link" href="<?php echo CM_ADMIN_URL ?>/member/member_list.php"><i class="bi bi-dot"></i> 회원관리</a>
                        </li>
						<li class="nav-item">
                            <a class="nav-link" href="<?php echo CM_ADMIN_URL ?>/member/point_list.php"><i class="bi bi-dot"></i> 포인트관리</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="<?php echo CM_ADMIN_URL ?>/member/visit_list.php"><i class="bi bi-dot"></i> 방문자관리</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="<?php echo CM_ADMIN_URL ?>/member/email_form.php"><i class="bi bi-dot"></i> 이메일발송</a>
                        </li>
						<!--
						<li class="nav-item">
                            <a class="nav-link" href="<?php echo CM_ADMIN_URL ?>/member/sms_form.php"><i class="bi bi-dot"></i> 문자발송</a>
                        </li>
						-->
                    </ul>
                </div>
            </li>
			
			<!-- 게시판관리 -->
            <li class="nav-item">
                <a class="nav-link d-flex justify-content-between align-items-center"
                   data-bs-toggle="collapse"
                   href="#submenu-board"
                   role="button"
                   aria-expanded="false"
                   aria-controls="submenu-board">
                    게시판관리
                    <i class="bi bi-chevron-down ms-2 toggle-icon" data-target="submenu-board"></i>
                </a>
                <div class="collapse ps-1" id="submenu-board">
                    <ul class="nav flex-column my-2">
                        <li class="nav-item">
                            <a class="nav-link" href="<?php echo CM_ADMIN_URL ?>/board/board_group_list.php"><i class="bi bi-dot"></i> 게시판그룹관리</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="<?php echo CM_ADMIN_URL ?>/board/board_list.php"><i class="bi bi-dot"></i> 게시판관리</a>
                        </li>
						<li class="nav-item">
                            <a class="nav-link" href="<?php echo CM_ADMIN_URL ?>/board/content_list.php"><i class="bi bi-dot"></i> 내용관리</a>
                        </li>
                    </ul>
                </div>
            </li>
			
            

        </ul>
    </div>
</div>
<!-- } Sidebar -->