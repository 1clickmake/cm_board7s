<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가

$cm_site_title = $config['site_title'];
if(isset($cm_title) && $cm_title !== ""){
	$cm_site_title .= "/".$cm_title;
}
?>
<!doctype html>
<html lang="<?php echo htmlspecialchars($html_page_lang); ?>">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
		<!-- PWA 관련 메타태그 -->
		<meta name="theme-color" content="#ffffff">
		<meta name="apple-mobile-web-app-capable" content="yes">
		<meta name="mobile-web-app-capable" content="yes">
		<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
		<meta name="apple-mobile-web-app-title" content="<?php echo htmlspecialchars($config['site_title'] ?? '홈페이지'); ?>">
		<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
		<meta http-equiv="Pragma" content="no-cache">
		<meta http-equiv="Expires" content="0">
		<?php echo !empty($config['add_meta']) ? nl2br(htmlspecialchars($config['add_meta'])) : ''; ?>


		<title><?php echo $cm_site_title;?></title>
		<script src="<?php echo CM_URL?>/js/cm.config.js?ver=<?php echo time();?>"></script><!--// 자바스크립트에서 사용하는 전역변수-->
		<link rel="stylesheet" href="<?php echo CM_URL?>/css/style.css?ver=<?php echo time();?>">
		<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
		<script src="https://cdn.jsdelivr.net/npm/quill@2.0.3/dist/quill.js"></script>
		<link href="https://cdn.jsdelivr.net/npm/quill@2.0.3/dist/quill.snow.css" rel="stylesheet">
		
		<?php
		if (defined('CM_IS_ADMIN')) {
			include_once CM_ADMIN_PATH.'/add/add.stylesheet.php';
			// 관리자/CSS 폴더 내 모든 CSS 파일 로드
			$css_path = CM_ADMIN_PATH.'/css';
			if (is_dir($css_path)) {
				$css_files = glob($css_path.'/*.css');
				if ($css_files) {
					foreach ($css_files as $css_file) {
						$css_url = str_replace(CM_ADMIN_PATH, CM_ADMIN_URL, $css_file);
						echo '<link rel="stylesheet" href="'.$css_url.'?ver='.time().'">'."\n";
					}
				}
			}
		}else{
			include_once CM_TEMPLATE_PATH.'/add/add.stylesheet.php';
			// 템플릿/CSS 폴더 내 모든 CSS 파일 로드
			$css_path = CM_TEMPLATE_PATH.'/css';
			if (is_dir($css_path)) {
				$css_files = glob($css_path.'/*.css');
				if ($css_files) {
					foreach ($css_files as $css_file) {
						$css_url = str_replace(CM_TEMPLATE_PATH, CM_TEMPLATE_URL, $css_file);
						echo '<link rel="stylesheet" href="'.$css_url.'?ver='.time().'">'."\n";
					}
				}
			}
		}

		if (defined('CM_IS_ADMIN')) {
			include_once CM_ADMIN_PATH.'/add/add.script.head.php';
			// 관리자/js 폴더 내 모든 JavaScript 파일 로드
			$js_path = CM_ADMIN_PATH.'/js';
			if (is_dir($js_path)) {
				$js_files = glob($js_path.'/*.js');
				if ($js_files) {
					foreach ($js_files as $js_file) {
						$js_url = str_replace(CM_ADMIN_PATH, CM_ADMIN_URL, $js_file);
						echo '<script src="'.$js_url.'?ver='.time().'"></script>'."\n";
					}
				}
			}
		}else{
			include_once CM_TEMPLATE_PATH.'/add/add.script.head.php';
			// 템플릿/js 폴더 내 모든 JavaScript 파일 로드
			$js_path = CM_TEMPLATE_PATH.'/js';
			if (is_dir($js_path)) {
				$js_files = glob($js_path.'/*.js');
				if ($js_files) {
					foreach ($js_files as $js_file) {
						$js_url = str_replace(CM_TEMPLATE_PATH, CM_TEMPLATE_URL, $js_file);
						echo '<script src="'.$js_url.'?ver='.time().'"></script>'."\n";
					}
				}
			}
		}
		
		$fName = get_First_FolderName($current_url);
		?>
		<script src="<?php echo CM_URL?>/js/common.js"></script>
		<?php if($deepl_api_use_from_config == 1 && $deepl_api_key_from_config){ //deepl 사이트 번역?>
		<script src="<?php echo CM_URL?>/js/deepl_translator.js"></script>
		<script>
			// DeepL 번역 대상 언어를 JavaScript에 전달 (세션 값 사용)
			var CM_TARGET_LANG_FROM_SESSION = '<?php echo htmlspecialchars($_SESSION['deepl_lang'] ?? '', ENT_QUOTES, 'UTF-8'); ?>';
		</script>
		<?php } ?>
		
		<?php if($recaptcha_site && $recaptcha_secret && is_AllowedFolder()){ //구를 리캡챠?>
		<script src="https://www.google.com/recaptcha/api.js?render=<?php echo $recaptcha_site;?>"></script>
		<?php } ?>
		
		<?php if (!empty($config['add_js'])): // ?>
		<script>
		//<![CDATA[
		<?php echo $config['add_js']; ?>
		//]]>
		</script>
		<?php endif; ?>

	</head>
	<body>
	<div id="loadingSpinner"></div>
    <div id="loadingOverlay"></div>
