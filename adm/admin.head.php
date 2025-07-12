<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가
include_once './_common.php';
include_once CM_PATH.'/head_sub.php';
include_once CM_ADMIN_PATH.'/admin.lib.php';
?>

<!-- Top Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
			<button class="btn btn-outline-0 me-2 " id="toggleSidebar">
                <span class="navbar-toggler-icon"></span>
            </button>
            <a class="navbar-brand" href="<?php echo CM_ADMIN_URL?>">ADMIN</a>
            <div class="collapse navbar-collapse">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="<?php echo CM_URL?>"><i class="bi bi-house"></i> HOME</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="<?php echo CM_MB_URL?>/logout.php"><i class="bi bi-box-arrow-right"></i> LOGOUT</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

   <?php include_once CM_ADMIN_PATH.'/include/sidebar_menu.php'; //사이드바?>


