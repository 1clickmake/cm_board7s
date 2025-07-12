<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가

/**
 * 이메일 발송 함수
 * 
 * @param array $recipients 수신자 배열 [['email' => '이메일', 'name' => '이름']]
 * @param string $subject 이메일 제목
 * @param string $body 이메일 본문 (HTML)
 * @param array $attachments 첨부파일 배열 [['path' => '파일경로', 'name' => '표시파일명']]
 * @param array $cc_list CC 수신자 배열
 * @param array $bcc_list BCC 수신자 배열
 * @return array ['success' => true/false, 'message' => '결과메시지']
 */
function send_bulk_email($recipients, $subject, $body, $attachments = [], $cc_list = [], $bcc_list = []) {
    require_once CM_LIB_PATH.'/send_gmail_function.php';
    
    $success_count = 0;
    $fail_count = 0;
    $error_messages = [];
    
    // 첨부파일 정보 로그
    error_log("send_bulk_email 호출 - 수신자: " . count($recipients) . "명, 첨부파일: " . count($attachments) . "개");
    if (!empty($attachments)) {
        foreach ($attachments as $attachment) {
            error_log("첨부파일 정보: " . json_encode($attachment));
        }
    }
    
    foreach ($recipients as $recipient) {
        $result = send_gmail(
            $recipient['name'] ?? '',
            $recipient['email'],
            $subject,
            $body,
            strip_tags($body), // alt_body
            $attachments,
            $cc_list,
            $bcc_list
        );
        
        if ($result['success']) {
            $success_count++;
        } else {
            $fail_count++;
            $error_messages[] = $recipient['email'] . ': ' . $result['message'];
        }
    }
    
    return [
        'success' => $fail_count === 0,
        'success_count' => $success_count,
        'fail_count' => $fail_count,
        'total_count' => count($recipients),
        'error_messages' => $error_messages,
        'message' => "발송 완료: 성공 {$success_count}건, 실패 {$fail_count}건"
    ];
}

/**
 * 전체 회원 목록 조회
 * 
 * @param int $user_lv 최소 회원 레벨 (기본값: 1)
 * @return array 회원 목록
 */
function get_all_members($user_lv = 1) {
    $sql = "SELECT user_id, user_name, user_email, user_lv 
            FROM cm_users 
            WHERE user_lv >= :user_lv 
            ORDER BY user_lv DESC, user_name ASC";
    
    $params = [':user_lv' => $user_lv];
    return sql_all_list($sql, $params);
}

/**
 * 특정 레벨 회원 목록 조회
 * 
 * @param int $user_lv 회원 레벨
 * @return array 회원 목록
 */
function get_members_by_level($user_lv) {
    $sql = "SELECT user_id, user_name, user_email, user_lv 
            FROM cm_users 
            WHERE user_lv = :user_lv 
            ORDER BY user_name ASC";
    
    $params = [':user_lv' => $user_lv];
    return sql_all_list($sql, $params);
}

/**
 * 레벨 구간 회원 목록 조회
 * 
 * @param int $level_start 시작 레벨
 * @param int $level_end 끝 레벨
 * @return array 회원 목록
 */
function get_members_by_level_range($level_start, $level_end) {
    $sql = "SELECT user_id, user_name, user_email, user_lv 
            FROM cm_users 
            WHERE user_lv >= :level_start AND user_lv <= :level_end 
            ORDER BY user_lv DESC, user_name ASC";
    
    $params = [
        ':level_start' => $level_start,
        ':level_end' => $level_end
    ];
    return sql_all_list($sql, $params);
}

/**
 * 이메일 주소 문자열을 배열로 변환
 * 
 * @param string $email_string 쉼표로 구분된 이메일 주소들
 * @return array 이메일 주소 배열
 */
function parse_email_string($email_string) {
    $emails = explode(',', $email_string);
    $clean_emails = [];
    
    foreach ($emails as $email) {
        $email = trim($email);
        if (!empty($email) && filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $clean_emails[] = $email;
        }
    }
    
    return $clean_emails;
}

/**
 * 회원 레벨별 이름 조회
 * 
 * @return array 레벨별 이름 배열
 */
function get_user_level_names() {
    return [
        1 => '일반회원',
        2 => '우수회원', 
        3 => 'VIP회원',
        4 => '관리자',
        5 => '최고관리자'
    ];
}

/**
 * 첨부파일 업로드 처리
 * 
 * @param array $files $_FILES 배열
 * @param string $upload_dir 업로드 디렉토리
 * @return array 업로드된 파일 정보
 */
function process_email_attachments($files, $upload_dir = 'data/email_attachments/') {
    $uploaded_files = [];
    
    // 첨부파일 용량 제한 (10MB)
    $max_file_size = 10 * 1024 * 1024; // 10MB
    $max_total_size = 10 * 1024 * 1024; // 10MB (전체 첨부파일)
    $total_size = 0;
    
    // 업로드 디렉토리 생성
    $full_upload_dir = CM_PATH . '/' . $upload_dir;
    if (!is_dir($full_upload_dir)) {
        mkdir($full_upload_dir, 0755, true);
    }
    
    // 파일 업로드 처리
    if (isset($files['attachments']) && is_array($files['attachments']['name'])) {
        $file_count = count($files['attachments']['name']);
        
        for ($i = 0; $i < $file_count; $i++) {
            // 파일 업로드 오류 확인
            if ($files['attachments']['error'][$i] !== UPLOAD_ERR_OK) {
                continue; // 업로드 오류가 있는 파일은 건너뛰기
            }
            
            $original_name = $files['attachments']['name'][$i];
            $file_size = $files['attachments']['size'][$i];
            $tmp_name = $files['attachments']['tmp_name'][$i];
            
            // 파일이 실제로 존재하는지 확인
            if (!file_exists($tmp_name)) {
                continue;
            }
            
            // 개별 파일 크기 확인
            if ($file_size > $max_file_size) {
                continue; // 10MB 초과 파일은 건너뛰기
            }
            
            // 전체 첨부파일 크기 확인
            if (($total_size + $file_size) > $max_total_size) {
                continue; // 전체 크기 초과 시 건너뛰기
            }
            
            // 파일 확장자 확인
            $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'zip'];
            $file_extension = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));
            
            if (!in_array($file_extension, $allowed_extensions)) {
                continue; // 허용되지 않은 파일 형식은 건너뛰기
            }
            
            // 파일명 중복 방지 (타임스탬프 추가)
            $unique_filename = time() . '_' . uniqid() . '_' . $original_name;
            $upload_path = $full_upload_dir . $unique_filename;
            
            // 파일 업로드
            if (move_uploaded_file($tmp_name, $upload_path)) {
                $uploaded_files[] = [
                    'path' => $upload_path,
                    'name' => $original_name,
                    'size' => $file_size
                ];
                $total_size += $file_size;
            }
        }
    }
    
    return $uploaded_files;
}

/**
 * 이메일 발송 로그 저장
 * 
 * @param array $email_data 이메일 발송 데이터
 * @param array $result 발송 결과
 * @return bool 저장 성공 여부
 */
function save_email_log($email_data, $result) {
    $sql = "INSERT INTO cm_email_log 
            (sender_id, recipient_type, recipients, subject, content, attachments, 
             success_count, fail_count, error_messages, created_at) 
            VALUES 
            (:sender_id, :recipient_type, :recipients, :subject, :content, :attachments,
             :success_count, :fail_count, :error_messages, NOW())";
    
    $params = [
        ':sender_id' => $_SESSION['user_id'] ?? 'admin',
        ':recipient_type' => $email_data['recipient_type'],
        ':recipients' => json_encode($email_data['recipients']),
        ':subject' => $email_data['subject'],
        ':content' => $email_data['content'],
        ':attachments' => json_encode($email_data['attachments'] ?? []),
        ':success_count' => $result['success_count'],
        ':fail_count' => $result['fail_count'],
        ':error_messages' => json_encode($result['error_messages'])
    ];
    
    return sql_fetch($sql, $params) !== false;
}
?> 