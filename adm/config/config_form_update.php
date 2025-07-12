<?php
include_once './_common.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $site_title = filter_input(INPUT_POST, 'site_title', FILTER_SANITIZE_SPECIAL_CHARS);
    $admin_email = filter_input(INPUT_POST, 'admin_email', FILTER_SANITIZE_EMAIL);
    $contact_number = filter_input(INPUT_POST, 'contact_number', FILTER_SANITIZE_SPECIAL_CHARS);
	$fax_number = filter_input(INPUT_POST, 'contact_number', FILTER_SANITIZE_SPECIAL_CHARS);
    $privacy_manager = filter_input(INPUT_POST, 'privacy_manager', FILTER_SANITIZE_SPECIAL_CHARS); // 개인정보보호 책임자 추가
	$ip_access = filter_input(INPUT_POST, 'ip_access', FILTER_SANITIZE_SPECIAL_CHARS);
    $ip_block = filter_input(INPUT_POST, 'ip_block', FILTER_SANITIZE_SPECIAL_CHARS);
    
    // 사업자 정보 필드
    $business_reg_no = filter_input(INPUT_POST, 'business_reg_no', FILTER_SANITIZE_SPECIAL_CHARS);
    $online_sales_no = filter_input(INPUT_POST, 'online_sales_no', FILTER_SANITIZE_SPECIAL_CHARS);
    $representative_name = filter_input(INPUT_POST, 'representative_name', FILTER_SANITIZE_SPECIAL_CHARS);
    $business_type = filter_input(INPUT_POST, 'business_type', FILTER_SANITIZE_SPECIAL_CHARS);
    $business_category = filter_input(INPUT_POST, 'business_category', FILTER_SANITIZE_SPECIAL_CHARS);
	$business_address = isset($_POST['business_address']) ? trim($_POST['business_address']) : '';
	$operating_hours = isset($_POST['operating_hours']) ? trim($_POST['operating_hours']) : '';
	
	$google_email = filter_input(INPUT_POST, 'google_email', FILTER_SANITIZE_SPECIAL_CHARS);
	$google_appkey = filter_input(INPUT_POST, 'google_appkey', FILTER_SANITIZE_SPECIAL_CHARS);
	$recaptcha_site_key = filter_input(INPUT_POST, 'recaptcha_site_key', FILTER_SANITIZE_SPECIAL_CHARS);
	$recaptcha_secret_key = filter_input(INPUT_POST, 'recaptcha_secret_key', FILTER_SANITIZE_SPECIAL_CHARS);
	$google_map_iframe_src = isset($_POST['google_map_iframe_src']) ? trim($_POST['google_map_iframe_src']) : '';
	
	$cf_original_lang = $_POST['cf_original_lang'] ?? 'KO';
	$deepl_api_use = filter_input(INPUT_POST, 'deepl_api_use', FILTER_SANITIZE_SPECIAL_CHARS);
	$deepl_api_key = filter_input(INPUT_POST, 'deepl_api_key', FILTER_SANITIZE_SPECIAL_CHARS);
	$deepl_api_plan = filter_input(INPUT_POST, 'deepl_api_plan', FILTER_SANITIZE_SPECIAL_CHARS);
	
	$pwa_use = filter_input(INPUT_POST, 'pwa_use', FILTER_SANITIZE_SPECIAL_CHARS);
	$pwa_vapid_public_key = filter_input(INPUT_POST, 'pwa_vapid_public_key', FILTER_SANITIZE_SPECIAL_CHARS);
	$pwa_vapid_private_key = filter_input(INPUT_POST, 'pwa_vapid_private_key', FILTER_SANITIZE_SPECIAL_CHARS);
    
    // 추가 메타 및 JS 필드
    $add_meta = isset($_POST['add_meta']) ? trim($_POST['add_meta']) : '';
    $add_js = isset($_POST['add_js']) ? trim($_POST['add_js']) : '';
    
    // SNS 링크 필드
    $sns_facebook = filter_input(INPUT_POST, 'sns_facebook', FILTER_SANITIZE_URL);
    $sns_x = filter_input(INPUT_POST, 'sns_x', FILTER_SANITIZE_URL);
    $sns_kakao = filter_input(INPUT_POST, 'sns_kakao', FILTER_SANITIZE_URL);
    $sns_naver = filter_input(INPUT_POST, 'sns_naver', FILTER_SANITIZE_URL);
    $sns_line = filter_input(INPUT_POST, 'sns_line', FILTER_SANITIZE_URL);
    $sns_pinterest = filter_input(INPUT_POST, 'sns_pinterest', FILTER_SANITIZE_URL);
    $sns_linkedin = filter_input(INPUT_POST, 'sns_linkedin', FILTER_SANITIZE_URL);
   
	$DataToUpdate = [
		'site_title' => $site_title,
		'admin_email' => $admin_email,
		'contact_number' => $contact_number,
		'fax_number' => $fax_number,
        'privacy_manager' => $privacy_manager, // 개인정보보호 책임자 추가
		'ip_access' => $ip_access,
		'ip_block' => $ip_block,
        'business_reg_no' => $business_reg_no,
        'online_sales_no' => $online_sales_no,
        'representative_name' => $representative_name,
        'business_address' => $business_address,
        'business_type' => $business_type,
        'business_category' => $business_category,
        'operating_hours' => $operating_hours, // 운영시간 추가
		'google_email' => $google_email,
		'google_appkey' => $google_appkey,
		'recaptcha_site_key' => $recaptcha_site_key,
		'recaptcha_secret_key' => $recaptcha_secret_key,
		'google_map_iframe_src' => $google_map_iframe_src, // 구글 지도 iframe src 추가
        'sns_facebook' => $sns_facebook,
        'sns_x' => $sns_x,
        'sns_kakao' => $sns_kakao,
        'sns_naver' => $sns_naver,
        'sns_line' => $sns_line,
        'sns_pinterest' => $sns_pinterest,
        'sns_linkedin' => $sns_linkedin,
		'cf_original_lang' => $cf_original_lang, // DeepL API Key 추가
		'deepl_api_use' => $deepl_api_use, // DeepL API Key 추가
		'deepl_api_key' => $deepl_api_key, // DeepL API Key 추가
		'deepl_api_plan' => $deepl_api_plan, // DeepL API Plan 추가
		'pwa_use' => $pwa_use, // PWA 사용
		'pwa_vapid_public_key' => $pwa_vapid_public_key, // PWA VAPID 공개 키
		'pwa_vapid_private_key' => $pwa_vapid_private_key, // PWA VAPID 비공개 키
		'add_meta' => $add_meta,
		'add_js' => $add_js,
	];
	
	for ($col=1 ; $col <= 5; $col++){
		$DataToUpdate['cf_add_sub_'.$col] = isset($_POST['cf_add_sub_'.$col]) ? $_POST['cf_add_sub_'.$col] : '';
		$DataToUpdate['cf_add_con_'.$col] = isset($_POST['cf_add_con_'.$col]) ? $_POST['cf_add_con_'.$col] : '';
	}
	
	// 업데이트 조건 where
	$where = [
		'id' => 1 
	];
	$data_update = process_data_update('cm_config', $DataToUpdate, $where); // $pdo 인자 없이 호출
	
	// 삽입 결과 확인
    if ($data_update !== false) {
        // 업데이트 성공
		alert('업데이트 되었습니다.', './config_form.php');
    } else {
        // 업데이트 실패 
        echo "<script>alert('오류가 발생했습니다.'); history.back();</script>";
    }
}