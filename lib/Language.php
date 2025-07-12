<?php
// 언어 클래스
class Language {
    private string $currentLang;
    private array $translations = [];
    private string $langDir;
    private array $availableLanguages = ['en', 'ko']; // 지원하는 언어 목록
    private string $fallbackLang; // 기본으로 사용할 언어 (예: 한국어)

    public function __construct(string $initialAttemptLang = 'ko', string $langDir = 'languages/') {
        $this->langDir = rtrim($langDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

        // 강력한 폴백 언어 결정 (ko -> en -> 사용 가능한 첫 번째 언어 순)
        if (in_array('ko', $this->availableLanguages) && file_exists($this->langDir . 'ko.php')) {
            $this->fallbackLang = 'ko';
        } elseif (in_array('en', $this->availableLanguages) && file_exists($this->langDir . 'en.php')) {
            $this->fallbackLang = 'en';
        } elseif (!empty($this->availableLanguages) && file_exists($this->langDir . $this->availableLanguages[0] . '.php')) {
            $this->fallbackLang = $this->availableLanguages[0];
        } else {
            // 심각한 설정 오류: 사용 가능한 언어 파일이 없음
            $this->fallbackLang = !empty($this->availableLanguages) ? $this->availableLanguages[0] : 'xx'; // 문제 발생 표시
            error_log("CRITICAL SETUP ERROR: No valid fallback language. Check 'availableLanguages' and files in '{$this->langDir}'. Attempting '{$this->fallbackLang}'.");
        }

        $langToSet = $this->fallbackLang;

        // 우선순위: 1. 세션에 저장된 언어, 2. 생성자 초기 시도 언어, 3. 폴백 언어
        if (isset($_SESSION['lang']) && $this->isValidLanguageCode($_SESSION['lang'])) {
            $langToSet = $_SESSION['lang'];
        } elseif ($this->isValidLanguageCode($initialAttemptLang)) {
            $langToSet = $initialAttemptLang;
        }
        
        $this->loadLanguage($langToSet); // 실제 언어 로딩
    }

    private function isValidLanguageCode(string $langCode): bool {
        return in_array($langCode, $this->availableLanguages) && file_exists($this->langDir . $langCode . '.php');
    }

    // 내부적으로 언어를 로드하고 현재 언어 상태를 설정합니다.
    private function loadLanguage(string $langCode): bool {
        if ($this->isValidLanguageCode($langCode)) {
            $this->translations = require $this->langDir . $langCode . '.php';
            $this->currentLang = $langCode;
            return true;
        } elseif ($langCode !== $this->fallbackLang && $this->isValidLanguageCode($this->fallbackLang)) {
            // 요청된 언어 로드 실패 시, 폴백 언어로 시도 (이미 폴백 언어가 아니라면)
            $this->translations = require $this->langDir . $this->fallbackLang . '.php';
            $this->currentLang = $this->fallbackLang;
            error_log("Language '{$langCode}' not found or invalid, fell back to '{$this->currentLang}'.");
            return true;
        }
        
        // 최후의 수단도 실패: 번역 없음
        $this->translations = [];
        $this->currentLang = $this->fallbackLang; // currentLang을 폴백으로 설정 (비록 로드 실패했더라도)
        error_log("CRITICAL: Could not load language '{$langCode}' or fallback '{$this->fallbackLang}'. No translations available.");
        return false;
    }

    // 공개 메소드: 언어를 변경하고 세션을 업데이트합니다.
    public function setLanguage(string $langCode): bool {
        if ($this->loadLanguage($langCode)) {
            if (session_status() === PHP_SESSION_ACTIVE) {
                $_SESSION['lang'] = $this->currentLang;
            }
            return true;
        }
        return false;
    }

    // 번역된 문자열을 가져옵니다. 키가 없으면 기본 텍스트를 반환합니다.
    public function get(string $key, string $defaultText = ''): string {
        return $this->translations[$key] ?? $defaultText;
    }

    // 현재 설정된 언어 코드를 반환합니다.
    public function getCurrentLanguage(): string {
        return $this->currentLang ?? $this->fallbackLang;
    }

    // 사용 가능한 언어 목록을 반환합니다.
    public function getAvailableLanguages(): array {
        return $this->availableLanguages;
    }
}