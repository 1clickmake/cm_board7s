<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 직접 접근 방지

// 중요: 아래 YOUR_DEEPL_API_KEY_HERE 를 실제 DeepL API 키로 교체해야 합니다.
// Pro 플랜 API 키 예시: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
// Free 플랜 API 키 예시: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx:fx' (끝에 :fx가 붙습니다)

if ($deepl_api_plan_from_config === 'pro') {
    define('DEEPL_API_URL', "https://api.deepl.com/v2/translate"); // Pro 플랜
} else {
    define('DEEPL_API_URL', "https://api-free.deepl.com/v2/translate"); // Free 플랜 (기본값)
}


/**
 * DeepL API를 사용하여 텍스트를 번역합니다.
 *
 * @param string|array $text_input 번역할 텍스트 또는 텍스트 배열.
 * @param string $target_lang 대상 언어 코드 (예: 'KO', 'EN-US', 'JA').
 * @param string|null $source_lang 원본 언어 코드 (선택 사항, null이면 자동 감지).
 * @return string|array|null 번역된 텍스트, 번역된 텍스트 배열 또는 실패 시 null.
 */

function deepl_translate($text_input, string $target_lang, string $source_lang = null) {
	
	if(DEEPL_API_USE === '' || DEEPL_API_USE === 0){
        return null; // 사용안함일때
	}
    if (DEEPL_API_KEY === '') {
        error_log("DeepL API 키가 설정되지 않았습니다.");
        return null; // API 키가 없으면 번역 실패
    }

    // 캐시 디렉토리 설정 및 생성
    $cache_base_dir = CM_DATA_PATH . '/langs';
    if (!is_dir($cache_base_dir)) {
        if (!mkdir($cache_base_dir, 0777, true)) {
            error_log("DeepL 캐시 디렉토리 생성 실패: " . $cache_base_dir);
            // 캐시 없이 진행하거나, 여기서 null을 반환할 수 있습니다. 여기서는 캐시 없이 진행합니다.
        }
    }

    $target_lang_upper = strtoupper($target_lang);
    $cache_lang_dir = $cache_base_dir . '/' . $target_lang_upper;
    if (!is_dir($cache_lang_dir)) {
        if (!mkdir($cache_lang_dir, 0777, true)) {
            error_log("DeepL 대상 언어 캐시 디렉토리 생성 실패: " . $cache_lang_dir);
        }
    }

    // 캐시 키 생성
    // 배열인 경우 serialize하여 해시, 문자열은 그대로 사용하거나 동일하게 serialize
    $cache_key_input = is_array($text_input) ? serialize($text_input) : (string)$text_input;
    $cache_key = md5($cache_key_input . '_' . $target_lang_upper . '_' . ($source_lang ? strtoupper($source_lang) : ''));
    $cache_file = $cache_lang_dir . '/' . $cache_key . '.txt';

    // 캐시된 내용 확인
    if (file_exists($cache_file) && is_readable($cache_file)) {
        $cached_content = file_get_contents($cache_file);
        $unserialized_content = @unserialize($cached_content); // unserialize 시도
        return ($unserialized_content !== false || $cached_content === 'b:0;') ? $unserialized_content : $cached_content; // false도 유효한 직렬화 값이므로 'b:0;'도 체크
    }

    $is_input_array = is_array($text_input);

    // 기본 요청 파라미터 (text 제외)
    $base_params = [
        'auth_key' => DEEPL_API_KEY,
        'target_lang' => $target_lang_upper,
    ];

    if ($source_lang !== null) {
        $base_params['source_lang'] = strtoupper($source_lang);
    }

    // POST 필드를 위한 배열 초기화
    $post_fields_list = [];
    foreach ($base_params as $key => $value) {
        $post_fields_list[] = urlencode($key) . '=' . urlencode($value);
    }

    // text 파라미터 추가
    if ($is_input_array) {
        foreach ($text_input as $single_text_item) {
            $post_fields_list[] = 'text=' . urlencode((string)$single_text_item);
        }
    } else {
        $post_fields_list[] = 'text=' . urlencode((string)$text_input);
    }
    $final_post_data = implode('&', $post_fields_list);

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, DEEPL_API_URL);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $final_post_data);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
    // 로컬 개발 환경에서 SSL 인증서 문제를 겪는 경우 아래 두 줄의 주석을 해제할 수 있습니다.
    // 경고: 프로덕션 환경에서는 절대 사용하지 마세요.
    // curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    // curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);
    curl_close($ch);

    $log_text_preview = "";
    if ($is_input_array) {
        $preview_parts = [];
        $count = 0;
        foreach($text_input as $t) {
            if ($count < 3) { // 처음 몇 개 항목만 미리보기
                 $preview_parts[] = mb_substr((string)$t, 0, 20) . (mb_strlen((string)$t) > 20 ? "..." : "");
            }
            $count++;
        }
        $log_text_preview = "Array(" . count($text_input) . " items): [" . implode(", ", $preview_parts) . ($count > 3 ? ", ..." : "") . "]";
    } else {
        $log_text_preview = mb_substr((string)$text_input, 0, 50) . (mb_strlen((string)$text_input) > 50 ? "..." : "");
    }

    if ($curl_error) {
        error_log("DeepL API cURL Error for text \"{$log_text_preview}\": " . $curl_error);
        return null;
    }

    $result = json_decode($response, true);

    if ($http_code == 200 && isset($result['translations']) && is_array($result['translations'])) {
        if (!$is_input_array) { // 입력이 단일 문자열이었던 경우
            if (isset($result['translations'][0]['text'])) {
                $translated_text = $result['translations'][0]['text'];
                // 캐시에 저장 (문자열로 저장)
                if (is_writable($cache_lang_dir)) {
                    file_put_contents($cache_file, $translated_text);
                }
                return $translated_text;
            }
        } else { // 입력이 문자열 배열이었던 경우
            $translated_texts = [];
            foreach ($result['translations'] as $translation_item) {
                $translated_texts[] = $translation_item['text'] ?? null; // 번역 실패 시 null 추가 가능
            }
            // 입력과 출력의 개수가 동일한지 확인 (DeepL은 동일하게 반환)
            if (count($translated_texts) === count($text_input)) {
                // 캐시에 저장 (직렬화된 배열로 저장)
                if (is_writable($cache_lang_dir)) {
                    file_put_contents($cache_file, serialize($translated_texts));
                }
                return $translated_texts;
            }
            error_log("DeepL API 번역 결과 개수 불일치. Input: " . count($text_input) . ", Output: " . count($translated_texts));
        }
        // 이 지점에 도달하면 단일 문자열 입력 시 'text' 키가 없거나, 배열 입력 시 개수가 불일치하는 경우
        // 또는 $result['translations']가 비어있는 경우
        error_log("DeepL API 응답 형식 오류 또는 번역 내용 누락. HTTP {$http_code}. Response: " . $response);
        return null;

    } else {
        $api_message = $result['message'] ?? 'No specific message from API.';
        error_log("DeepL API Error (HTTP {$http_code}) for text \"{$log_text_preview}\": {$api_message}. Response: " . $response);
        // 특정 HTTP 코드에 따른 사용자 메시지 반환 가능 (예: 403 - 인증 실패, 429/456 - 할당량 초과)
        return null;
    }
    // 함수가 정상적으로 값을 반환하지 못하는 모든 경로에 대해 null 반환 보장
    return null;
} 
