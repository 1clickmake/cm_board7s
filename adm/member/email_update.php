<?php
include_once './_common.php';
include_once CM_LIB_PATH.'/mailer.lib.php';

// POST 요청 처리 
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $recipient_type = $_POST['recipient_type'] ?? '';
    $subject = trim($_POST['subject'] ?? '');
    $content = $_POST['content'] ?? '';
    
    // 수신자 목록 생성
    $recipients = [];
    
    switch ($recipient_type) {
        case 'all':
            // 전체 회원
            $min_level = (int)($_POST['min_level'] ?? 1);
            $members = get_all_members($min_level);
            foreach ($members as $member) {
                $recipients[] = [
                    'email' => $member['user_email'],
                    'name' => $member['user_name']
                ];
            }
            break;
            
        case 'level':
            // 레벨 구간 회원
            $level_start = (int)($_POST['level_start'] ?? 1);
            $level_end = (int)($_POST['level_end'] ?? 10);
            
            // 유효성 검사
            if ($level_start > $level_end) {
                alert('시작 레벨이 끝 레벨보다 클 수 없습니다.', './email_form.php');
                exit;
            }
            
            $members = get_members_by_level_range($level_start, $level_end);
            foreach ($members as $member) {
                $recipients[] = [
                    'email' => $member['user_email'],
                    'name' => $member['user_name']
                ];
            }
            break;
            
        case 'individual':
            // 개별 회원
            $email_string = $_POST['individual_emails'] ?? '';
            $emails = parse_email_string($email_string);
            foreach ($emails as $email) {
                $recipients[] = [
                    'email' => $email,
                    'name' => ''
                ];
            }
            break;
    }
    
    // 첨부파일 처리
    $attachments = [];
    if (!empty($_FILES['attachment']['name'])) {
        // 단일 파일 업로드 처리
        $file = $_FILES['attachment'];
        
        // 디버깅 로그
        error_log("첨부파일 업로드 시도: " . $file['name'] . ", 크기: " . $file['size'] . ", 오류: " . $file['error']);
        
        // 파일 업로드 오류 확인
        if ($file['error'] === UPLOAD_ERR_OK) {
            // 파일 크기 확인 (10MB 제한)
            $max_file_size = 10 * 1024 * 1024; // 10MB
            
            if ($file['size'] <= $max_file_size) {
                // 파일 확장자 확인
                $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'hwp', 'xls', 'xlsx', 'txt'];
                $file_extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
                
                if (in_array($file_extension, $allowed_extensions)) {
                    // 업로드 디렉토리 생성
                    $upload_dir = 'data/email_attachments/';
                    $full_upload_dir = CM_PATH . '/' . $upload_dir;
                    if (!is_dir($full_upload_dir)) {
                        mkdir($full_upload_dir, 0755, true);
                    }
                    
                    // 파일명 중복 방지 (타임스탬프 추가)
                    $unique_filename = time() . '_' . uniqid() . '_' . $file['name'];
                    $upload_path = $full_upload_dir . $unique_filename;
                    
                    // 파일 업로드
                    if (move_uploaded_file($file['tmp_name'], $upload_path)) {
                        $attachments[] = [
                            'path' => $upload_path,
                            'name' => $file['name']
                        ];
                        error_log("첨부파일 업로드 성공: " . $upload_path);
                    } else {
                        error_log("첨부파일 업로드 실패: " . $file['tmp_name'] . " -> " . $upload_path);
                    }
                } else {
                    error_log("허용되지 않은 파일 형식: " . $file_extension);
                }
            } else {
                error_log("파일 크기 초과: " . $file['size'] . " > " . $max_file_size);
            }
        } else {
            error_log("파일 업로드 오류: " . $file['error']);
        }
    }
    
    // 첨부파일 정보 로그
    error_log("첨부파일 배열: " . json_encode($attachments));
    
    // 이메일 발송
    if (!empty($recipients) && !empty($subject) && !empty($content)) {
        $result = send_bulk_email($recipients, $subject, $content, $attachments);
        
        // 로그 저장
        $email_data = [
            'recipient_type' => $recipient_type,
            'recipients' => $recipients,
            'subject' => $subject,
            'content' => $content,
            'attachments' => $attachments
        ];
        save_email_log($email_data, $result);
        
        // 결과 메시지
        if ($result['success']) {
            alert('이메일이 성공적으로 발송되었습니다.', './email_form.php');
        } else {
            // Gmail 보안 정책 관련 오류인지 확인
            $error_message = $result['message'];
            if (strpos($error_message, 'security issue') !== false || strpos($error_message, 'blocked') !== false) {
                $error_message = 'Gmail 보안 정책으로 인해 이메일이 차단되었습니다. ZIP 파일이나 실행 파일은 첨부할 수 없습니다.';
            }
            alert('이메일 발송 중 오류가 발생했습니다: ' . $error_message, './email_form.php');
        }
    } else {
        alert('필수 정보가 누락되었습니다.', './email_form.php');
    }
    exit;
}

// GET 요청 시 폼 페이지로 리다이렉트
header('Location: ./email_form.php');
exit;
?> 