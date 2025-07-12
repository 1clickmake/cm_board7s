<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가
/**
 * Gmail SMTP 서버를 이용하여 이메일을 발송하는 함수
 * 
 * @param string $to_email 수신자 이메일 주소
 * @param string $subject 이메일 제목
 * @param string $body 이메일 본문 (HTML 형식 가능)
 * @param string $to_name 수신자 이름 (선택사항)
 * @param string $alt_body 대체 본문 (HTML을 지원하지 않는 이메일 클라이언트용)
 * @param array $attachments 첨부 파일 배열 [['path' => '파일경로', 'name' => '표시될파일명']]
 * @param array $cc_list CC 수신자 배열 [['email' => '이메일주소', 'name' => '이름']]
 * @param array $bcc_list BCC 수신자 배열 [['email' => '이메일주소', 'name' => '이름']]
 * @param array $reply_to 답장 주소 [['email' => '이메일주소', 'name' => '이름']]
 * @return array ['success' => true/false, 'message' => '결과 메시지']
 */
function send_gmail($to_name, $to_email, $subject, $body,  $alt_body = '', $attachments = [], $cc_list = [], $bcc_list = [], $reply_to = []) {
	global $config;
    // PHPMailer 클래스 파일 포함 - 상대 경로 사용
    require_once CM_PLUGIN_PATH.'/PHPMailer/src/Exception.php';
    require_once CM_PLUGIN_PATH.'/PHPMailer/src/PHPMailer.php';
    require_once CM_PLUGIN_PATH.'/PHPMailer/src/SMTP.php';
    
    // Gmail 계정 정보 (실제 사용 시 이 정보는 설정 파일에서 로드하는 것이 좋습니다)
    $gmail_account = $config['google_email']; // Gmail 계정
    $gmail_password = $config['google_appkey']; // Gmail 앱 비밀번호 (보안을 위해 앱 비밀번호 사용)
    $sender_name = $config['site_title']; // 발신자 이름
    
    // 설정 정보 로그 제거됨
    
    // PHPMailer 객체 생성
    $mail = new PHPMailer\PHPMailer\PHPMailer(true);
    
    try {
        // 서버 설정
        $mail->SMTPDebug = 0; // 디버그 출력 레벨 (0=비활성화, 1=메시지, 2=메시지+연결 상태)
        $mail->isSMTP(); // SMTP 사용
        $mail->Host = 'smtp.gmail.com'; // Gmail SMTP 서버
        $mail->SMTPAuth = true; // SMTP 인증 사용
        $mail->Username = $gmail_account; // SMTP 사용자명
        $mail->Password = $gmail_password; // SMTP 비밀번호
        $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS; // TLS 암호화 사용
        $mail->Port = 587; // SMTP 포트
        $mail->CharSet = 'UTF-8'; // 문자셋 설정
        
        // SMTP 설정 로그 제거됨
        
        // 메모리 제한 증가 (대용량 파일 처리용)
        ini_set('memory_limit', '256M');
        
        // 발신자
        $mail->setFrom($gmail_account, $sender_name);
        
        // 수신자
        $mail->addAddress($to_email, $to_name);
        
        // CC 수신자 추가
        if (!empty($cc_list)) {
            foreach ($cc_list as $cc) {
                $mail->addCC($cc['email'], $cc['name'] ?? '');
            }
        }
        
        // BCC 수신자 추가
        if (!empty($bcc_list)) {
            foreach ($bcc_list as $bcc) {
                $mail->addBCC($bcc['email'], $bcc['name'] ?? '');
            }
        }
        
        // 답장 주소 설정
        if (!empty($reply_to)) {
            foreach ($reply_to as $reply) {
                $mail->addReplyTo($reply['email'], $reply['name'] ?? '');
            }
        }
        
        // 첨부 파일 추가
        if (!empty($attachments)) {
            foreach ($attachments as $attachment) {
                // 파일이 실제로 존재하는지 확인
                if (file_exists($attachment['path'])) {
                    // 파일 크기 확인 (10MB 제한)
                    $file_size = filesize($attachment['path']);
                    
                    if ($file_size <= 10 * 1024 * 1024) { // 10MB 이하만 첨부
                        try {
                            $mail->addAttachment($attachment['path'], $attachment['name'] ?? '');
                        } catch (Exception $e) {
                            // 첨부파일 추가 실패 시 조용히 처리
                        }
                    }
                }
            }
        }
        
        // 메일 내용 설정
        $mail->isHTML(true); // HTML 형식 이메일 사용
        $mail->Subject = $subject;
        $mail->Body = $body;
        $mail->AltBody = $alt_body ?: strip_tags($body); // HTML 지원하지 않는 클라이언트용 본문
        
        // 메일 발송
        $mail->send();
        
        // 이메일 발송 성공 로그 제거됨
        
        return [
            'success' => true,
            'message' => '이메일이 성공적으로 발송되었습니다.'
        ];
        
    } catch (Exception $e) {
        // 이메일 발송 실패 로그 제거됨
        
        return [
            'success' => false,
            'message' => '이메일 발송 실패: ' . $mail->ErrorInfo
        ];
    }
}

/**
 * 사용 예제
 */
/*
// 기본 사용법
$result = send_gmail(
	'Recipient Name'                    // 수신자 이름
    'recipient@example.com',            // 수신자 이메일
    '이메일 제목입니다',                  // 제목
    '<h1>HTML 형식 본문입니다.</h1><p>안녕하세요!</p>', // 본문
    
);

// 고급 사용법 (모든 옵션 사용)
$result = send_gmail(
	'Recipient Name',                   // 수신자 이름
    'recipient@example.com',            // 수신자 이메일
    '모든 옵션을 사용한 이메일입니다',       // 제목
    '<h1>HTML 형식 본문입니다.</h1><p>안녕하세요!</p>', // 본문
    
    '텍스트 형식 본문입니다. 안녕하세요!',   // 대체 본문
    [   // 첨부 파일 배열
        ['path' => '/path/to/file.pdf', 'name' => '문서.pdf'],
        ['path' => '/path/to/image.jpg', 'name' => '이미지.jpg']
    ],
    [   // CC 수신자 배열
        ['email' => 'cc1@example.com', 'name' => 'CC Recipient 1'],
        ['email' => 'cc2@example.com', 'name' => 'CC Recipient 2']
    ],
    [   // BCC 수신자 배열
        ['email' => 'bcc@example.com', 'name' => 'BCC Recipient']
    ],
    [   // 답장 주소 배열
        ['email' => 'reply@example.com', 'name' => 'Reply Handler']
    ]
);

// 결과 확인
if ($result['success']) {
    echo $result['message'];
} else {
    echo "오류 발생: " . $result['message'];
}
*/
?>