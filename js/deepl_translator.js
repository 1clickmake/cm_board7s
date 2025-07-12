document.addEventListener('DOMContentLoaded', function() {
    // URL에서 번역 대상 언어 코드 가져오기 (예: ?translate_to=EN-US)
    const urlParams = new URLSearchParams(window.location.search);
    let targetLangFromUrl = urlParams.get('translate_to');
    let targetLang = '';

    if (targetLangFromUrl) {
        targetLang = targetLangFromUrl.toUpperCase();
        console.log(`DeepL: 번역 대상 언어가 URL 파라미터로 지정되었습니다: ${targetLang}`);
        // URL 파라미터 사용 시, PHP 세션 값도 업데이트하려면 별도 처리가 필요할 수 있습니다.
        // 현재 로직에서는 URL 파라미터가 세션 값보다 우선 적용됩니다.
    } else if (typeof CM_TARGET_LANG_FROM_SESSION !== 'undefined' && CM_TARGET_LANG_FROM_SESSION) {
        targetLang = CM_TARGET_LANG_FROM_SESSION.toUpperCase();
        console.log(`DeepL: 번역 대상 언어가 세션으로부터 지정되었습니다: ${targetLang}`);
    }

    // 번역 대상 언어가 URL 파라미터나 세션에도 없는 경우 번역 실행 안 함
    if (!targetLang) {
        console.log('DeepL: 번역 대상 언어가 지정되지 않았습니다 (URL 파라미터 및 세션 확인). 번역을 실행하지 않습니다.');
        return;
    }

    const pageHtmlLang = document.documentElement.lang; // HTML의 lang 속성 (예: "ko", "en-US")

    // HTML lang 속성이 존재하고, 그 기본 언어 코드와 targetLang의 기본 언어 코드가 동일한 경우 번역 실행 안 함
    if (pageHtmlLang) {
        const pageBaseLang = pageHtmlLang.split('-')[0].toUpperCase(); // 예: "ko-KR" -> "KO", "en" -> "EN"
        const targetBaseLang = targetLang.split('-')[0].toUpperCase(); // 예: "KO" -> "KO", "EN-US" -> "EN"
 
        if (pageBaseLang === targetBaseLang) {
            console.log(`DeepL: 페이지 원본 언어(${pageBaseLang})와 번역 대상 언어(${targetBaseLang})가 동일하여 번역을 실행하지 않습니다.`);
            return;
        }
    }
    // pageHtmlLang이 설정되지 않았거나, 설정되었지만 targetLang과 다른 경우 번역을 진행합니다.
    // pageHtmlLang이 없으면 DeepL API에서 원본 언어를 자동 감지합니다.

    // 번역 대상 언어를 대문자로 통일하여 캐시 키 일관성 확보
    targetLang = targetLang.toUpperCase();

    console.log(`DeepL 번역 시작: 원본 추정(${pageHtmlLang || '자동 감지'}) -> 대상(${targetLang})`);

    // 번역할 텍스트 노드를 수집하는 함수 (기존 함수 유지)
    function collectTranslatableTextNodes(element) {
        const textNodes = [];
        const walker = document.createTreeWalker(
            element,
            NodeFilter.SHOW_TEXT,
            {
                acceptNode: function(node) {
                    if (node.textContent.trim() === '') {
                        return NodeFilter.FILTER_REJECT;
                    }
                    const parentElement = node.parentElement;
                    if (!parentElement) return NodeFilter.FILTER_REJECT;
                    const parentTagName = parentElement.tagName.toLowerCase();
                    if (['script', 'style', 'pre', 'code', 'textarea', 'input', 'button', 'select', 'option'].includes(parentTagName) ||
                        parentElement.closest('pre, code, noscript, [contenteditable="true"], .notranslate, #wpadminbar, .deepl-ignore')) {
                         return NodeFilter.FILTER_REJECT;
                    }
                    if (parentElement.closest('[data-translated="true"]')) {
                         return NodeFilter.FILTER_REJECT;
                    }
                    if (node.nodeType === Node.COMMENT_NODE) {
                        return NodeFilter.FILTER_REJECT;
                    }
                    return NodeFilter.FILTER_ACCEPT;
                }
            },
            false
        );
        let node;
        while (node = walker.nextNode()) {
            textNodes.push(node);
        }
        return textNodes;
    }

    // 페이지 전체에서 번역할 텍스트 노드 먼저 수집
    const nodesToTranslate = collectTranslatableTextNodes(document.body);

    if (nodesToTranslate.length === 0) {
        console.log('DeepL: 번역할 텍스트 노드를 찾지 못했습니다.');
        return;
    }

    // --- 캐시 로직 추가 ---
    const cacheKey = `deepl_translation_v2_${window.location.pathname}_${targetLang}`; // 캐시 버전 명시 및 targetLang 대문자 사용
    try {
        const cachedData = localStorage.getItem(cacheKey);
        if (cachedData) {
            const cachedTranslations = JSON.parse(cachedData);
            // 캐시된 데이터가 있고, 현재 페이지의 번역 대상 노드 수와 일치하는지 확인
            if (Array.isArray(cachedTranslations) && cachedTranslations.length === nodesToTranslate.length) {
                console.log(`DeepL: 캐시된 번역 데이터를 사용합니다. (Key: ${cacheKey})`);
                nodesToTranslate.forEach((node, index) => {
                    if (cachedTranslations[index] !== undefined && cachedTranslations[index] !== null) {
                        // 원본 텍스트와 번역된 텍스트가 실제로 다른 경우에만 업데이트
                        if (node.textContent !== cachedTranslations[index]) {
                            node.textContent = cachedTranslations[index];
                        }
                    }
                });
                console.log('DeepL: 캐시된 번역 적용 완료.');
                // 로딩 스피너가 있다면 숨김 처리
                const loadingSpinner = document.getElementById('loadingSpinner');
                const loadingOverlay = document.getElementById('loadingOverlay');
                if (loadingSpinner) loadingSpinner.style.display = 'none';
                if (loadingOverlay) loadingOverlay.style.display = 'none';
                return; // 캐시 사용했으므로 API 호출 불필요
            } else {
                console.log(`DeepL: 캐시 데이터가 유효하지 않습니다 (길이 불일치 또는 타입 오류). 캐시를 무시합니다. (Key: ${cacheKey})`);
                localStorage.removeItem(cacheKey); // 유효하지 않은 캐시 삭제
            }
        }
    } catch (e) {
        console.error('DeepL: 캐시 읽기 오류:', e);
        localStorage.removeItem(cacheKey); // 오류 발생 시 캐시 삭제
    }
    // --- 캐시 로직 종료 ---

    // 캐시 미스 시 API 호출 진행
    console.log(`DeepL: 번역할 텍스트 노드 ${nodesToTranslate.length}개 수집 완료 (API 호출 예정).`);

    // 번역할 텍스트 노드를 수집하는 함수
    // 번역 요청을 위한 텍스트 배열 생성
    const texts = nodesToTranslate.map(node => node.textContent); // 원본 공백 유지를 위해 trim() 제거

    // 로딩 스피너 표시
    const loadingSpinner = document.getElementById('loadingSpinner');
    const loadingOverlay = document.getElementById('loadingOverlay');
    if (loadingSpinner) loadingSpinner.style.display = 'block';
    if (loadingOverlay) loadingOverlay.style.display = 'block';


    // 서버 측 번역 엔드포인트 호출
    // CM.LIB_URL은 common.js 또는 cm.config.js에서 정의되어 있어야 합니다.
    const translateEndpoint = (typeof CM !== 'undefined' && CM.LIB_URL) ? CM.LIB_URL + '/deepl_ajax_translator.php' : '/lib/deepl_ajax_translator.php';
    
    // DeepL API는 한 번에 여러 텍스트 번역을 지원하지만, 여기서는 단순화를 위해 각 노드별로 요청하거나,
    // 또는 모든 텍스트를 하나의 큰 문자열로 합쳐서 보내는 방법을 고려할 수 있습니다.
    // 모든 텍스트를 합쳐서 보내는 것은 API 호출 횟수를 줄이지만, 번역 결과와 원본 노드를 매핑하기 어렵습니다.
    // 여기서는 각 노드별로 요청하는 대신, 모든 텍스트를 배열로 보내고 응답도 배열로 받는 방식을 가정합니다.
    // DeepL API는 'text' 파라미터에 문자열 배열을 받을 수 있습니다.

    fetch(translateEndpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            text: texts, // 텍스트 배열로 전송
            target_lang: targetLang,
            source_lang: pageHtmlLang ? pageHtmlLang.split('-')[0].toUpperCase() : null // 원본 언어 힌트 제공
        }),
    })
    .then(response => {
        if (!response.ok) {
            // 서버에서 JSON 에러 메시지를 보냈을 경우를 대비
            return response.json().then(errData => {
                throw new Error(`HTTP error! status: ${response.status}, message: ${errData.error || response.statusText}`);
            }).catch(() => { // JSON 에러 메시지가 없거나 파싱 실패 시
                throw new Error(`HTTP error! status: ${response.status}, statusText: ${response.statusText}`);
            });
        }
        return response.json();
    })
    .then(data => {
        if (data.success && data.translated_text && Array.isArray(data.translated_text)) {
            if (texts.length !== data.translated_text.length) {
                console.warn(`DeepL: 원본 텍스트 수(${texts.length})와 번역된 텍스트 수(${data.translated_text.length})가 일치하지 않습니다.`);
            }
            // 번역된 텍스트를 해당 노드에 적용
            nodesToTranslate.forEach((node, index) => {
                if (data.translated_text[index] !== undefined && data.translated_text[index] !== null) {
                    // 원본 텍스트와 번역된 텍스트가 실제로 다른 경우에만 업데이트 (불필요한 DOM 변경 방지)
                    if (node.textContent !== data.translated_text[index]) {
                        node.textContent = data.translated_text[index];
                    }
                }
            });
            console.log('DeepL: 번역 적용 완료.');

            // --- 캐시 저장 로직 ---
            try {
                localStorage.setItem(cacheKey, JSON.stringify(data.translated_text));
                console.log(`DeepL: 번역 결과를 캐시에 저장했습니다. (Key: ${cacheKey})`);
            } catch (e) {
                console.error('DeepL: 캐시 저장 오류:', e);
                // 캐시 저장 실패는 번역 기능 자체에 영향을 주지 않도록 처리
            }
            // --- 캐시 저장 로직 종료 ---

            // 선택 사항: 번역 완료 후 html lang 속성을 targetLang으로 변경
            // document.documentElement.lang = targetLang.toLowerCase(); // 예: 'en-us'
        } else {
            console.error('DeepL: 번역 응답 오류:', data.error || '알 수 없는 응답 형식');
        }
    })
    .catch(error => {
        console.error('DeepL: 번역 요청 실패:', error);
        // 사용자에게 오류 메시지 표시 가능
    })
    .finally(() => {
        // 로딩 스피너 숨김
        if (loadingSpinner) loadingSpinner.style.display = 'none';
        if (loadingOverlay) loadingOverlay.style.display = 'none';
    });
}); 