<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가

// IP 접속 국가/지역 조회
function cm_city_Curl($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        error_log("유효하지 않은 IP: IP=$ip");
        return false;
    }

    $url = "http://ip-api.com/php/" . urlencode($ip);
    $ch = curl_init();
    
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    
    $response = curl_exec($ch);
    
    if (curl_errno($ch)) {
        error_log("cURL 오류: IP=$ip, 오류=" . curl_error($ch));
        curl_close($ch);
        return false;
    }
    
    curl_close($ch);
    $data = @unserialize($response);
    
    if ($data === false) {
        error_log("IP-API 응답 파싱 실패: IP=$ip, 응답=" . print_r($response, true));
        return false;
    }
    
    if (isset($data['status']) && $data['status'] === 'success') {
        return [
            'country' => $data['country'] ?? '',
            'countryCode' => $data['countryCode'] ?? '',
            'city' => $data['city'] ?? '',
            'isp' => $data['isp'] ?? ''
        ];
    }
    
    $error_message = isset($data['message']) ? $data['message'] : '알 수 없는 오류';
    error_log("IP-API 응답 실패: IP=$ip, 상태=" . ($data['status'] ?? '없음') . ", 메시지=$error_message, 응답=" . print_r($response, true));
    return false;
}

function get_visit() {
    global $pdo;
    
    if (!$pdo) {
        error_log("PDO 객체가 초기화되지 않음");
        return;
    }
    
    try {
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $visit_time = date('Y-m-d H:i:s');
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        
        if (empty($referer)) {
            $scheme = $_SERVER['REQUEST_SCHEME'] ?? 'http';
            $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
            $uri = $_SERVER['REQUEST_URI'] ?? '/';
            $referer = $scheme . '://' . $host . $uri;
        }
        
        $ct_data = cm_city_Curl($ip_address);
        
        $country = $ct_data ? $ct_data['country'] : '';
        $country_code = $ct_data ? $ct_data['countryCode'] : '';
        $city = $ct_data ? $ct_data['city'] : '';
        $isp = $ct_data ? $ct_data['isp'] : '';

        if ($referer) {
            $url_parts = parse_url($referer);
            if ($url_parts === false) {
                error_log("참조 URL 파싱 실패: referer=$referer");
                $referer = '';
            } else {
                $path = $url_parts['path'] ?? '';
                $query = $url_parts['query'] ?? '';
                
                parse_str($query, $query_params);
                if (isset($query_params['board'])) {
                    $referer = ($url_parts['scheme'] ?? 'http') . '://' . ($url_parts['host'] ?? 'unknown') . $path . '?board=' . $query_params['board'];
                } else {
                    $referer = ($url_parts['scheme'] ?? 'http') . '://' . ($url_parts['host'] ?? 'unknown') . $path;
                }
            }
        }

        // 오늘 날짜 확인
        $today = date('Y-m-d');
        $stmt = $pdo->prepare("SELECT id, visit_count FROM cm_visit WHERE ip_address = ? AND DATE(visit_time) = ?");
        $stmt->execute([$ip_address, $today]);
        $existing = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($existing) {
            // 이미 오늘 방문 기록이 있는 경우, 카운트만 증가
            $stmt = $pdo->prepare("UPDATE cm_visit SET visit_count = visit_count + 1, visit_time = ? WHERE id = ?");
            $stmt->execute([$visit_time, $existing['id']]);
        } else {
            // 오늘 방문 기록이 없는 경우, 새로운 기록 삽입
            $stmt = $pdo->prepare("INSERT INTO cm_visit (ip_address, ip_country, ip_countryCode, ip_city, ip_isp, visit_time, user_agent, referer, visit_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$ip_address, $country, $country_code, $city, $isp, $visit_time, $user_agent, $referer, 1]);
        }
    } catch (PDOException $e) {
        error_log("방문자 기록 실패: IP=$ip_address, 오류=" . $e->getMessage());
        throw new Exception("데이터베이스 오류: " . $e->getMessage()); // 디버깅용, 프로덕션에서는 제거
    }
}
?>