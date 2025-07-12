<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가

/**
 * 세션 데이터를 단일 또는 다중으로 설정하는 함수
 * @param string|array $key 세션 키(문자열) 또는 키-값 배열
 * @param mixed $value 단일 키에 대한 값 (배열 입력 시 무시)
 * @return bool 성공 여부
 */
function setSessionData($key, $value = null) {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    if (is_string($key) && !empty($key)) {
        $_SESSION[$key] = $value;
        return true;
    } elseif (is_array($key)) {
        foreach ($key as $k => $v) {
            if (is_string($k) && !empty($k)) {
                $_SESSION[$k] = $v;
            }
        }
        return true;
    }

    return false;
}

/**
 * 현재 세션 데이터를 출력하는 함수
 * @param string $format 출력 형식 ('json' 또는 'html')
 * @return string 출력 문자열
 */
function printSessionData($format = 'html') {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    if (empty($_SESSION)) {
        return $format === 'json'
            ? json_encode(['message' => 'No session data available'])
            : '<p>No session data available</p>';
    }

    if ($format === 'json') {
        return json_encode($_SESSION, JSON_PRETTY_PRINT);
    }

    $output = '<ul style="list-style-type: none;">';
    foreach ($_SESSION as $key => $value) {
        $value = is_scalar($value) ? htmlspecialchars($value) : print_r($value, true);
        $output .= "<li><strong>$key</strong>: $value</li>";
    }
    $output .= '</ul>';
    return $output;
}

/**
 * 특정 세션 키 또는 여러 키를 삭제하는 함수
 * @param string|array $keys 단일 키(문자열) 또는 여러 키(배열)
 * @return bool 성공 여부
 */
function deleteSessionData($keys) {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    if (is_string($keys) && !empty($keys) && isset($_SESSION[$keys])) {
        unset($_SESSION[$keys]);
        return true;
    } elseif (is_array($keys)) {
        $success = false;
        foreach ($keys as $key) {
            if (is_string($key) && !empty($key) && isset($_SESSION[$key])) {
                unset($_SESSION[$key]);
                $success = true;
            }
        }
        return $success;
    }

    return false;
}

/**
 * 모든 세션 데이터를 삭제하고 세션을 종료하는 함수
 * @return bool 성공 여부
 */
function clearAllSessionData() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    $_SESSION = [];
    session_destroy();
    return true;
}

/**
 * 특정 세션 키의 값을 반환하는 함수
 * @param string $key 세션 키
 * @param mixed $default 키가 없을 때 반환할 기본값
 * @return mixed 값 또는 기본값
 */
function getSessionValue($key, $default = null) {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    return isset($_SESSION[$key]) ? $_SESSION[$key] : $default;
}

/**
 * 특정 세션 변수의 값을 반환하는 함수
 * @param string|array $variableName 세션 변수 키(문자열) 또는 키 배열
 * @param mixed $default 키가 없을 때 반환할 기본값
 * @return mixed 값, 배열, 또는 기본값
 */
function getSessionVariable($variableName, $default = null) {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    if (is_string($variableName) && !empty($variableName)) {
        return isset($_SESSION[$variableName]) ? $_SESSION[$variableName] : $default;
    } elseif (is_array($variableName)) {
        $result = [];
        foreach ($variableName as $key) {
            if (is_string($key) && !empty($key)) {
                $result[$key] = isset($_SESSION[$key]) ? $_SESSION[$key] : $default;
            }
        }
        return $result;
    }

    return $default;
}
