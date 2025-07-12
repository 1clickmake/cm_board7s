<?php
include_once './_common.php';
include_once CM_ADMIN_PATH.'/admin.head.php';

$user = [];
$is_new = true;

// user_no가 제공된 경우 수정 모드
if (isset($_GET['user_no']) && is_numeric($_GET['user_no'])) {
    $user_no = (int)$_GET['user_no'];
    $is_new = false;

    // 회원 데이터 조회
    try {
        $stmt = $pdo->prepare("SELECT * FROM cm_users WHERE user_no = :user_no");
        $stmt->execute(['user_no' => $user_no]);
        $user = $stmt->fetch();
        
        if (!$user) {
            alert('회원을 찾을 수 없습니다.', 'member_list.php');
            exit;
        }
    } catch (PDOException $e) {
        alert('오류: ' . $e->getMessage(), 'member_list.php');
        exit;
    }
}

$cm_title = $is_new ? '회원 신규 등록' : '회원 정보 수정';
?>

<!-- Main Content -->
<div class="main-content shifted" id="mainContent">
    <div class="container-fluid">
        <!-- 헤더 카드 -->
            <div class="card shadow-sm mb-4 border-0 card-move">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h2 class="card-title mb-1 text-primary">
                                <i class="bi bi-person-check-fill me-2"></i><?php echo $cm_title;?>
                            </h2>
                            <p class="card-text text-muted mb-0">회원 상세정보</p>
                        </div>
                    </div>
                </div>
            </div>
        
        <div class="row justify-content-center">
            <div class="col">
                <div class="card chart-card shadow-lg">
                    <div class="card-header">
                        <h5 class="card-title mb-0">
                            <i class="fas fa-user me-2"></i>
                            <?php echo $is_new ? '신규 회원 정보' : '회원 정보 수정'; ?>
                            <?php if (!$is_new): ?>
                            <span class="badge bg-secondary ms-2">ID: <?php echo htmlspecialchars($user['user_id']); ?></span>
                            <?php endif; ?>
                        </h5>
                    </div>
                    <div class="card-body p-4">
                        <form action="member_form_update.php" method="POST" id="memberForm">
                            <?php if (!$is_new): ?>
                            <input type="hidden" name="user_no" value="<?php echo htmlspecialchars($user['user_no']); ?>">
                            <?php endif; ?>
                            
                            <!-- 기본 정보 섹션 -->
                            <div class="mb-5">
                                <h6 class="text-muted fw-bold mb-3">
                                    <i class="fas fa-id-card me-2"></i>
                                    기본 정보
                                </h6>
                                
                                <div class="mb-4">
                                    <label for="user_id" class="form-label fw-semibold">
                                        <i class="fas fa-user me-2 text-primary"></i>
                                        회원 아이디
                                    </label>
                                    <div class="input-group">
                                        <span class="input-group-text bg-light">
                                            <i class="fas fa-id-card"></i>
                                        </span>
                                        <input type="text" class="form-control" id="user_id" name="user_id" 
                                               value="<?php echo $is_new ? '' : htmlspecialchars($user['user_id']); ?>" 
                                               <?php echo $is_new ? 'required' : 'readonly'; ?>
                                               placeholder="회원 아이디를 입력하세요">
                                    </div>
                                </div>
                                
                                <div class="mb-4">
                                    <label for="user_name" class="form-label fw-semibold">
                                        <i class="fas fa-signature me-2 text-success"></i>
                                        이름
                                    </label>
                                    <div class="input-group">
                                        <span class="input-group-text bg-light">
                                            <i class="fas fa-user"></i>
                                        </span>
                                        <input type="text" class="form-control" id="user_name" name="user_name" 
                                               value="<?php echo $is_new ? '' : htmlspecialchars($user['user_name']); ?>" 
                                               required placeholder="이름을 입력하세요">
                                    </div>
                                </div>
                                
                                <div class="mb-4">
                                    <label for="user_password" class="form-label fw-semibold">
                                        <i class="fas fa-key me-2 text-warning"></i>
                                        비밀번호
                                    </label>
                                    <div class="alert alert-info py-2 mb-2" role="alert">
                                        <i class="fas fa-info-circle me-2"></i>
                                        <small><?php echo $is_new ? '새 회원의 비밀번호를 입력하세요.' : '변경하지 않으려면 공란으로 두세요.'; ?></small>
                                    </div>
                                    <div class="input-group">
                                        <span class="input-group-text bg-light">
                                            <i class="fas fa-lock"></i>
                                        </span>
                                        <input type="password" class="form-control" id="user_password" name="user_password" 
                                               <?php echo $is_new ? 'required' : ''; ?>
                                               placeholder="<?php echo $is_new ? '비밀번호를 입력하세요' : '변경하지 않으려면 공란으로 두세요'; ?>">
                                        <button class="btn btn-outline-secondary" type="button" id="togglePassword">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                    </div>
                                </div>
                            </div>

                            <!-- 연락처 정보 섹션 -->
                            <div class="mb-5">
                                <h6 class="text-muted fw-bold mb-3">
                                    <i class="fas fa-address-book me-2"></i>
                                    연락처 정보
                                </h6>
                                
                                <div class="mb-4">
                                    <label for="user_email" class="form-label fw-semibold">
                                        <i class="fas fa-envelope me-2 text-info"></i>
                                        이메일
                                    </label>
                                    <div class="input-group">
                                        <span class="input-group-text bg-light">
                                            <i class="fas fa-at"></i>
                                        </span>
                                        <input type="email" class="form-control" id="user_email" name="user_email" 
                                               value="<?php echo $is_new ? '' : htmlspecialchars($user['user_email'] ?? ''); ?>"
                                               placeholder="이메일 주소를 입력하세요">
                                    </div>
                                </div>
                                
                                <div class="mb-4">
                                    <label for="user_hp" class="form-label fw-semibold">
                                        <i class="fas fa-mobile-alt me-2 text-success"></i>
                                        휴대폰 번호
                                    </label>
                                    <div class="input-group">
                                        <span class="input-group-text bg-light">
                                            <i class="fas fa-phone"></i>
                                        </span>
                                        <input type="text" class="form-control" id="user_hp" name="user_hp" 
                                               value="<?php echo $is_new ? '' : htmlspecialchars($user['user_hp'] ?? ''); ?>"
                                               placeholder="휴대폰 번호를 입력하세요 (예: 010-1234-5678)">
                                    </div>
                                </div>
                            </div>

                            <!-- 권한 설정 섹션 -->
                            <div class="mb-5">
                                <h6 class="text-muted fw-bold mb-3">
                                    <i class="fas fa-cog me-2"></i>
                                    권한 설정
                                </h6>
                                
                                <div class="mb-4">
                                    <label for="user_lv" class="form-label fw-semibold">
                                        <i class="fas fa-star me-2 text-warning"></i>
                                        회원 레벨
                                    </label>
                                    <div class="input-group">
                                        <span class="input-group-text bg-light">
                                            <i class="fas fa-level-up-alt"></i>
                                        </span>
                                        <input type="number" class="form-control" id="user_lv" name="user_lv" 
                                               value="<?php echo $is_new ? '1' : htmlspecialchars($user['user_lv']); ?>" 
                                               required min="1" placeholder="회원 레벨을 입력하세요">
                                    </div>
                                </div>
                                
                                <?php if (!$is_new): ?>
                                <div class="mb-4">
                                    <label class="form-label fw-semibold">
                                        <i class="fas fa-coins me-2 text-primary"></i>
                                        보유 포인트
                                    </label>
                                    <div class="input-group">
                                        <span class="input-group-text bg-light">
                                            <i class="fas fa-gem"></i>
                                        </span>
                                        <input type="text" class="form-control" value="<?php echo number_format($user['user_point']); ?> P" readonly>
                                    </div>
                                </div>
                                <?php endif; ?>
                            </div>

                            <?php if (!$is_new): ?>
                            <!-- 계정 상태 섹션 -->
                            <div class="mb-5">
                                <h6 class="text-muted fw-bold mb-3">
                                    <i class="fas fa-shield-alt me-2"></i>
                                    계정 상태
                                </h6>
                                
                                <div class="alert alert-warning py-2 mb-3" role="alert">
                                    <i class="fas fa-exclamation-triangle me-2"></i>
                                    <small>계정 상태 변경 시 주의하여 설정해주세요.</small>
                                </div>
                                
                                <div class="mb-3">
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="user_block" name="user_block" value="1" 
                                               <?php echo $user['user_block'] == 1 ? 'checked' : ''; ?>>
                                        <label class="form-check-label fw-semibold" for="user_block">
                                            <i class="fas fa-ban me-2 text-danger"></i>
                                            회원 차단
                                        </label>
                                    </div>
                                </div>
                                
                                <div class="mb-3">
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="user_leave" name="user_leave" value="1" 
                                               <?php echo $user['user_leave'] == 1 ? 'checked' : ''; ?>>
                                        <label class="form-check-label fw-semibold" for="user_leave">
                                            <i class="fas fa-user-times me-2 text-secondary"></i>
                                            회원 탈퇴
                                        </label>
                                    </div>
                                </div>
                            </div>
                            <?php endif; ?>

                            <!-- 저장 버튼 -->
                            <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                <button type="submit" name="action" value="<?php echo $is_new ? 'insert' : 'update'; ?>" class="btn btn-primary btn-lg px-5">
                                    <i class="fas fa-save me-2"></i>
                                    <?php echo $is_new ? '회원 등록' : '정보 수정'; ?>
                                </button>
                                <?php if (!$is_new): ?>
                                <button type="submit" name="action" value="delete" class="btn btn-danger btn-lg px-4" 
                                        onclick="return confirm('정말로 이 회원을 삭제하시겠습니까?');">
                                    <i class="fas fa-trash me-2"></i>
                                    회원 삭제
                                </button>
                                <?php endif; ?>
                                <a href="member_list.php" class="btn btn-secondary btn-lg px-4">
                                    <i class="fas fa-list me-2"></i>
                                    목록으로
                                </a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
// 비밀번호 보기/숨기기 토글
document.getElementById('togglePassword').addEventListener('click', function() {
    const passwordField = document.getElementById('user_password');
    const toggleIcon = this.querySelector('i');
    
    if (passwordField.type === 'password') {
        passwordField.type = 'text';
        toggleIcon.classList.remove('fa-eye');
        toggleIcon.classList.add('fa-eye-slash');
    } else {
        passwordField.type = 'password';
        toggleIcon.classList.remove('fa-eye-slash');
        toggleIcon.classList.add('fa-eye');
    }
});

// 폼 유효성 검사 시각적 피드백
document.getElementById('memberForm').addEventListener('submit', function(e) {
    const requiredFields = this.querySelectorAll('[required]');
    let isValid = true;
    
    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            field.classList.add('is-invalid');
            isValid = false;
        } else {
            field.classList.remove('is-invalid');
            field.classList.add('is-valid');
        }
    });
    
    if (!isValid) {
        e.preventDefault();
        alert('필수 입력 항목을 모두 입력해주세요.');
        return false;
    }
    
    // 추가 유효성 검사
    const userLevel = document.getElementById('user_lv').value;
    if (userLevel < 1) {
        alert('회원 레벨은 1 이상이어야 합니다.');
        e.preventDefault();
        return false;
    }
});

// 실시간 유효성 검사
document.querySelectorAll('input[required]').forEach(input => {
    input.addEventListener('blur', function() {
        if (this.value.trim()) {
            this.classList.remove('is-invalid');
            this.classList.add('is-valid');
        } else {
            this.classList.remove('is-valid');
            this.classList.add('is-invalid');
        }
    });
});

// 이메일 형식 검사
document.getElementById('user_email').addEventListener('blur', function() {
    if (this.value) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (emailRegex.test(this.value)) {
            this.classList.remove('is-invalid');
            this.classList.add('is-valid');
        } else {
            this.classList.remove('is-valid');
            this.classList.add('is-invalid');
        }
    }
});

// 휴대폰 번호 형식 자동 변환
document.getElementById('user_hp').addEventListener('input', function() {
    let value = this.value.replace(/[^0-9]/g, '');
    if (value.length >= 3 && value.length <= 7) {
        value = value.replace(/(\d{3})(\d{1,4})/, '$1-$2');
    } else if (value.length >= 8) {
        value = value.replace(/(\d{3})(\d{4})(\d{1,4})/, '$1-$2-$3');
    }
    this.value = value;
});
</script>

<?php
include_once CM_ADMIN_PATH.'/admin.tail.php';
?>