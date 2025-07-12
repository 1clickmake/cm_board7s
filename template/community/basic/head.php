<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가 
include_once CM_TEMPLATE_PATH.'/lib/menu.lib.php';
include_once(CM_TEMPLATE_PATH.'/sidemenu.php'); 
?>
<header>
    <div id="navbar" class="container-fluid bg-dark fixed-top">
		<div class="container">
			<div class="d-flex justify-content-between align-items-center">
				<h1 class="m-0">
					<a href="<?php echo CM_URL?>" class="text-white text-decoration-none">
						<?php echo $config['site_title'];?>
					</a>
				</h1>
				<nav class="custom-navbar">
					<?php generateMegaMenu(); ?>
				</nav>
			</div>
		</div>
	</div>
</header>	
	