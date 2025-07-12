<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가

// 구글 reCAPTCHA 검증
$recaptcha_site = $config['recaptcha_site_key'] ?? ''; //사이트키
$recaptcha_secret = $config['recaptcha_secret_key'] ?? ''; //시크릿키
$recaptcha_response = $_POST['g-recaptcha-response'] ?? '';


//DeepL 번역관련{
// 언어 변경 링크 생성 함수
function create_lang_url($lang_code, $current_path, $params) {
	$params['translate_to'] = $lang_code;
	return htmlspecialchars($current_path . '?' . http_build_query($params));
}

// DeepL 번역 대상 언어 세션 관리
$html_page_lang = $config['cf_original_lang'] ?? 'KO';//사이트 원본 언어
$deepl_api_use_from_config = $config['deepl_api_use'] ?? 0; //번역사용여부
$deepl_api_key_from_config = $config['deepl_api_key'] ?? ''; //DeepL API Key
$deepl_api_plan_from_config = $config['deepl_api_plan'] ?? 'free'; // DeepL API 플랜 기본값 'free'

define('DEEPL_API_USE', $deepl_api_use_from_config);
define('DEEPL_API_KEY', $deepl_api_key_from_config);

if (isset($_GET['translate_to'])) {
    $allowed_deepl_langs = ['KO', 'EN-US', 'EN', 'JA', 'ZH', 'DE', 'FR', 'ES', 'PT-BR', 'PT-PT', 'PT', 'IT', 'NL', 'PL', 'RU']; // EN-GB 등 필요시 추가
    $requested_lang = strtoupper($_GET['translate_to']);

    // 요청된 언어가 허용 목록에 있는지 확인 (대소문자 구분 없이 비교하기 위해 strtoupper 사용)
    if (in_array($requested_lang, array_map('strtoupper', $allowed_deepl_langs))) {
        $_SESSION['deepl_lang'] = $requested_lang;
    }
}

// 세션에 DeepL 언어가 없으면 기본값 설정 (예: 한국어)
if (!isset($_SESSION['deepl_lang'])) {
    $_SESSION['deepl_lang'] = 'KO'; // 기본 언어를 한국어로 설정
}
// }DeepL 언어 변경 끝

//PWA 관련 key{
$pwa_use = $config['pwa_use'] ?? 0; //	PWA 사용1
$pwa_vapid_public_key = $config['pwa_vapid_public_key'] ?? ''; //PWA VAPID 공개 키
$pwa_vapid_private_key = $config['pwa_vapid_private_key'] ?? '';//PWA VAPID 비공개 키
$pwaSet = false;
if($pwa_use == 1 && $pwa_vapid_public_key && $pwa_vapid_private_key){
	$pwaSet = true;
}
// } PWA 관련 끝