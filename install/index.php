<?php
session_start();

function getCurrentDomain(): string {
    // 현재 스킴(http 또는 https) 확인
    $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' || $_SERVER['SERVER_PORT'] == 443) ? 'https' : 'http';

    // 호스트명(도메인) 확인
    // HTTP_HOST는 클라이언트가 보낸 헤더이므로 필터링하는 것이 좋습니다.
    // SERVER_NAME은 서버 설정에 따라 달라질 수 있습니다.
    $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? '';

    // HTTP_HOST가 존재하는 경우 포트 제거 (클라이언트가 포트를 명시했을 수 있음)
    if (strpos($host, ':') !== false) {
        $host = explode(':', $host)[0];
    }

    // 도메인 유효성 검사 (선택 사항이지만 보안상 권장)
    // 실제 환경에서는 더 엄격한 유효성 검사가 필요할 수 있습니다.
    if (empty($host) || !filter_var($host, FILTER_VALIDATE_DOMAIN)) {
        // 유효한 도메인을 찾지 못했을 경우 기본값 또는 에러 처리
        // 여기서는 빈 문자열을 반환하지만, 실제 애플리케이션에서는 예외 처리 등을 고려할 수 있습니다.
        return '';
    }

    return $scheme . '://' . $host;
}

$domain = getCurrentDomain();
// 필요한 디렉토리 목록
$required_dirs = [
    '../data'
];

// 디렉토리 생성 및 권한 확인
$dir_error = '';
foreach ($required_dirs as $dir) {
    if (!file_exists($dir)) {
        if (!@mkdir($dir, 0755, true)) {
            $dir_error .= "디렉토리 생성 실패: $dir<br>";
        }
    } elseif (!is_writable($dir)) {
        $dir_error .= "디렉토리 쓰기 권한 없음: $dir<br>";
    }
}

// 이미 설치가 완료된 경우 메인 페이지로 리다이렉트
if (file_exists('../data/config.php')) {
    header('Location: ../index.php');
    exit;
}

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!empty($dir_error)) {
        $error = "디렉토리 권한 문제가 있습니다:<br>" . $dir_error;
    } else {
        $db_host = $_POST['db_host'] ?? '';
        $db_name = $_POST['db_name'] ?? '';
        $db_user = $_POST['db_user'] ?? '';
        $db_pass = $_POST['db_pass'] ?? '';
        $admin_id = $_POST['admin_id'] ?? '';
        $admin_pass = $_POST['admin_pass'] ?? '';
        $admin_name = $_POST['admin_name'] ?? '';
        $admin_email = $_POST['admin_email'] ?? '';

        if (empty($db_host) || empty($db_name) || empty($db_user) || empty($admin_id) || empty($admin_pass) || empty($admin_name) || empty($admin_email)) {
            $error = '모든 필드를 입력해주세요.';
        } else {
            try {
                // 데이터베이스 연결 테스트
                $pdo = new PDO("mysql:host=$db_host", $db_user, $db_pass);
                $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

                // 데이터베이스 생성
                $pdo->exec("CREATE DATABASE IF NOT EXISTS `$db_name` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
                $pdo->exec("USE `$db_name`");

                // config.php 파일 생성
                $config_content = <<<EOT
<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가

// 데이터베이스 연결 정보
\$host = '$db_host';
\$dbname = '$db_name';
\$username = '$db_user';
\$password = '$db_pass';

// PDO를 사용한 데이터베이스 연결
try {
    \$pdo = new PDO("mysql:host=\$host;dbname=\$dbname;charset=utf8mb4", \$username, \$password);
    \$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    \$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch (PDOException \$e) {
	// 디버깅을 위해 오류 메시지 기록 (운영 환경에서는 주석 처리)
	\$errorMessage = \$e->getMessage();
	\$encodedMessage = mb_convert_encoding(\$errorMessage, 'UTF-8', 'auto');
    error_log('Database connection failed: ' . \$encodedMessage);
    header('Location: ../install/index.php');
    exit();
}
EOT;

                if (!@file_put_contents('../data/config.php', $config_content)) {
                    throw new Exception('설정 파일을 생성할 수 없습니다. 디렉토리 권한을 확인해주세요.');
                }

                // 테이블 생성
                $sql = file_get_contents('sql/install.sql');
                $pdo->exec($sql);

                // 관리자 계정 업데이트
                $stmt = $pdo->prepare("UPDATE cm_config SET admin_id = ?, admin_email = ? WHERE id = '1'");
                $stmt->execute([$admin_id, $admin_email]);
                
                // 관리자 회원정보 업데이트
                $admin_pass_hash = password_hash($admin_pass, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("UPDATE cm_users SET user_id = ?, user_name = ?, user_password = ?, user_email = ?  WHERE user_no = '1'");
                $stmt->execute([$admin_id, $admin_name, $admin_pass_hash, $admin_email]);
				
                $success = '설치가 완료되었습니다. 잠시 후 메인 페이지로 이동합니다.';
                header('Refresh: 3; url=../index.php');
            } catch (Exception $e) {
                $error = '설치 중 오류가 발생했습니다: ' . $e->getMessage();
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CM Board 설치</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .install-container {
            padding: 40px 0;
        }
        
        .install-card {
            border: none;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
            background: rgba(255, 255, 255, 0.95);
            overflow: hidden;
        }
        
        .install-header {
            background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
            color: white;
            padding: 30px;
            text-align: center;
            margin: -1.25rem -1.25rem 2rem -1.25rem;
        }
        
        .install-header h3 {
            margin: 0;
            font-weight: 600;
            font-size: 1.8rem;
        }
        
        .install-header .subtitle {
            margin-top: 8px;
            opacity: 0.9;
            font-size: 0.95rem;
        }
        
        .section-divider {
            background: linear-gradient(to right, #4f46e5, #7c3aed);
            height: 3px;
            border-radius: 2px;
            margin: 2rem 0 1.5rem 0;
            position: relative;
        }
        
        .section-divider::before {
            content: '';
            position: absolute;
            top: -6px;
            left: 50%;
            transform: translateX(-50%);
            width: 12px;
            height: 12px;
            background: linear-gradient(135deg, #4f46e5, #7c3aed);
            border-radius: 50%;
        }
        
        .section-title {
            color: #4f46e5;
            font-weight: 600;
            font-size: 1.1rem;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .form-label {
            color: #374151;
            font-weight: 500;
            margin-bottom: 8px;
        }
        
        .form-control {
            border: 2px solid #e5e7eb;
            border-radius: 12px;
            padding: 12px 16px;
            font-size: 0.95rem;
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            border-color: #4f46e5;
            box-shadow: 0 0 0 0.2rem rgba(79, 70, 229, 0.1);
            transform: translateY(-1px);
        }
        
        .input-group {
            position: relative;
        }
        
        .input-icon {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #9ca3af;
            z-index: 3;
        }
        
        .btn-install {
            background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
            border: none;
            border-radius: 12px;
            padding: 15px 30px;
            font-weight: 600;
            font-size: 1.1rem;
            color: white;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(79, 70, 229, 0.3);
        }
        
        .btn-install:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(79, 70, 229, 0.4);
            background: linear-gradient(135deg, #4338ca 0%, #6d28d9 100%);
        }
        
        .alert {
            border: none;
            border-radius: 12px;
            padding: 16px 20px;
            margin-bottom: 2rem;
        }
        
        .alert-danger {
            background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%);
            color: #dc2626;
            border-left: 4px solid #dc2626;
        }
        
        .alert-success {
            background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
            color: #16a34a;
            border-left: 4px solid #16a34a;
        }
        
        .form-floating {
            margin-bottom: 1.5rem;
        }
        
        .form-floating > .form-control {
            padding: 16px 16px 8px 16px;
        }
        
        .form-floating > label {
            padding: 16px 16px 8px 16px;
            color: #6b7280;
        }
        
        @media (max-width: 768px) {
            .install-container {
                padding: 20px 0;
            }
            
            .install-header {
                padding: 20px;
            }
            
            .install-header h3 {
                font-size: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="container install-container">
        <div class="row justify-content-center">
            <div class="col-md-8 col-lg-6">
                <div class="card install-card">
                    <div class="card-body p-3">
                        <div class="install-header rounded m-1">
                            <h3><i class="fas fa-cogs me-2"></i>CM Board 설치</h3>
                            <div class="subtitle">시스템 설정 및 관리자 계정 생성</div>
                        </div>
                        
                        <?php if ($error): ?>
                        <div class="alert alert-danger">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            <?php echo $error; ?>
                        </div>
                        <?php endif; ?>
                        
                        <?php if ($success): ?>
                        <div class="alert alert-success">
                            <i class="fas fa-check-circle me-2"></i>
                            <?php echo htmlspecialchars($success); ?>
                        </div>
                        <?php else: ?>
                        
                        <form method="post">
                            <div class="section-title">
                                <i class="fas fa-database"></i>
                                데이터베이스 정보
                            </div>
                            
                            <div class="form-floating mb-3">
                                <input type="text" class="form-control" id="db_host" name="db_host" value="localhost" placeholder="호스트" required>
                                <label for="db_host">호스트</label>
                                <i class="fas fa-server input-icon"></i>
                            </div>
                            
                            <div class="form-floating mb-3">
                                <input type="text" class="form-control" id="db_name" name="db_name" placeholder="데이터베이스명" required>
                                <label for="db_name">데이터베이스명</label>
                                <i class="fas fa-database input-icon"></i>
                            </div>
                            
                            <div class="form-floating mb-3">
                                <input type="text" class="form-control" id="db_user" name="db_user" placeholder="사용자명" required>
                                <label for="db_user">사용자명</label>
                                <i class="fas fa-user input-icon"></i>
                            </div>
                            
                            <div class="form-floating mb-4">
                                <input type="password" class="form-control" id="db_pass" name="db_pass" placeholder="비밀번호">
                                <label for="db_pass">비밀번호</label>
                                <i class="fas fa-lock input-icon"></i>
                            </div>

                            <div class="section-divider"></div>
                            
                            <div class="section-title">
                                <i class="fas fa-user-shield"></i>
                                관리자 정보
                            </div>
                            
                            <div class="form-floating mb-3">
                                <input type="text" class="form-control" id="admin_id" name="admin_id" value="admin" placeholder="아이디" required>
                                <label for="admin_id">아이디</label>
                                <i class="fas fa-user-cog input-icon"></i>
                            </div>
                            
                            <div class="form-floating mb-3">
                                <input type="password" class="form-control" id="admin_pass" name="admin_pass" placeholder="비밀번호" required>
                                <label for="admin_pass">비밀번호</label>
                                <i class="fas fa-key input-icon"></i>
                            </div>
                            
                            <div class="form-floating mb-3">
                                <input type="text" class="form-control" id="admin_name" name="admin_name" value="관리자" placeholder="이름" required>
                                <label for="admin_name">이름</label>
                                <i class="fas fa-id-card input-icon"></i>
                            </div>
                            
                            <div class="form-floating mb-4">
                                <input type="email" class="form-control" id="admin_email" name="admin_email" value="adm@site.com" placeholder="이메일" required>
                                <label for="admin_email">이메일</label>
                                <i class="fas fa-envelope input-icon"></i>
                            </div>

                            <div class="d-grid mt-4">
                                <button type="submit" class="btn btn-install">
                                    <i class="fas fa-rocket me-2"></i>설치하기
                                </button>
                            </div>
                        </form>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>