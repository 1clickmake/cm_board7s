<?php
include_once './_common.php'; // 기본 설정 및 라이브러리 로드

// JSON 응답 헤더 설정
header('Content-Type: application/json');

// POST 요청인지 확인
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); // Method Not Allowed
    echo json_encode(['error' => 'POST 요청만 허용됩니다.']);
    exit;
}

// 필요한 데이터 (텍스트, 대상 언어) 추출 및 검증
$request_data = json_decode(file_get_contents('php://input'), true);

$text_to_translate = $request_data['text'] ?? '';
$target_lang = $request_data['target_lang'] ?? '';
$source_lang = $request_data['source_lang'] ?? null; // 선택 사항

if (empty($text_to_translate) || empty($target_lang)) {
    http_response_code(400); // Bad Request
    echo json_encode(['error' => '번역할 텍스트와 대상 언어를 지정해야 합니다.']);
    exit;
}

// DeepL 번역 헬퍼 함수 로드
include_once CM_LIB_PATH . '/deepl_translator.php';

// DeepL API를 사용하여 번역 실행
$translated_text = deepl_translate($text_to_translate, $target_lang, $source_lang);

if ($translated_text !== null) {
    echo json_encode(['success' => true, 'translated_text' => $translated_text]);
} else {
    http_response_code(500); // Internal Server Error
    echo json_encode(['success' => false, 'error' => '번역 중 오류가 발생했습니다. 서버 로그를 확인하세요.']);
}