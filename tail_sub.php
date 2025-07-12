<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가
?>
		<?php
		if (defined('CM_IS_ADMIN')) {
			include_once CM_ADMIN_PATH.'/add/add.script.tail.php';
		}else{
			include_once CM_TEMPLATE_PATH.'/add/add.script.tail.php';
		}
		?>

		<!-- 앱 스크립트 로드 -->
		<script src="<?php echo CM_URL?>/js/app.js?ver=<?php echo time();?>"></script>
	</body>
</html>