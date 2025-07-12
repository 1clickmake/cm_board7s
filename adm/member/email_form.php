<?php
include_once './_common.php'; 
include_once CM_LIB_PATH.'/mailer.lib.php';

$cm_title = "이메일 관리";

include_once CM_ADMIN_PATH.'/admin.head.php';
?>

<!-- Main Content -->
<div class="main-content shifted" id="mainContent">
    <div class="container-fluid">
		<?php if(empty($config['google_email']) || empty($config['google_appkey'])){?>
		<div class="alert alert-danger" role="alert">
			홈페이지 설정 > 환경설정 > 구글계정 이메일, Gmail App Key 을 등록하세요.
		</div>
		<?php } ?>
		<!-- 헤더 카드 -->
            <div class="card shadow-sm mb-4 border-0 card-move">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h2 class="card-title mb-1 text-primary">
                                <i class="bi bi-envelope me-2"></i><?php echo $cm_title;?>
                            </h2>
                            <p class="card-text text-muted mb-0">이메일을 발송/확인 가능합니다.</p>
                        </div>
                        <div>
                            <a href="email_log.php" class="btn btn-primary btn-lg shadow-sm">
                                <i class="fas fa-plus me-2"></i>로그확인
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h4 class="mt-2"><i class="bi bi-envelope-arrow-up"></i> 이메일 발송</h4>
                    </div>
                    <div class="card-body">
                        <form action="email_update.php" method="post" enctype="multipart/form-data" id="emailForm">
                            <!-- 수신자 선택 -->
                            <div class="mb-4">
                                <label class="form-label h6 mb-3">수신자 선택 <span class="text-danger">*</span></label>
                                <div class="d-flex flex-wrap gap-3">
                                    <div class="form-check">
                                        <input type="radio" class="form-check-input" name="recipient_type" id="recipient_all" value="all" checked>
                                        <label class="form-check-label" for="recipient_all">전체 회원</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="radio" class="form-check-input" name="recipient_type" id="recipient_level" value="level">
                                        <label class="form-check-label" for="recipient_level">회원 레벨 구간</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="radio" class="form-check-input" name="recipient_type" id="recipient_individual" value="individual">
                                        <label class="form-check-label" for="recipient_individual">개별 회원</label>
                                    </div>
                                </div>
                            </div>
                            
                            <!-- 전체 회원 옵션 -->
                            <div class="mb-3" id="allMembersOption">
                                <label for="min_level" class="form-label h6 mb-3">최소 회원 레벨</label>
                                <input type="number" class="form-control" name="min_level" id="min_level" 
                                       min="1" max="10" value="1" placeholder="1">
                                <div class="mt-2 text-primary">선택한 레벨 이상의 모든 회원에게 발송됩니다.</div>
                            </div>
                            
                            <!-- 레벨별 회원 옵션 -->
                            <div class="mb-3" id="levelMembersOption" style="display: none;">
                                <label class="form-label h6 mb-3">회원 레벨 구간</label>
                                <div class="row">
                                    <div class="col-md-6">
                                        <label for="level_start" class="form-label">시작 레벨</label>
                                        <input type="number" class="form-control" name="level_start" id="level_start" 
                                               min="1" max="10" value="1" placeholder="1">
                                    </div>
                                    <div class="col-md-6">
                                        <label for="level_end" class="form-label">끝 레벨</label>
                                        <input type="number" class="form-control" name="level_end" id="level_end" 
                                               min="1" max="10" value="10" placeholder="10">
                                    </div>
                                </div>
                                <div class="mt-2 text-primary">선택한 레벨 구간의 회원들에게만 발송됩니다. (예: 1레벨 ~ 5레벨)</div>
                            </div>
                            
                            <!-- 개별 회원 옵션 -->
                            <div class="mb-3" id="individualMembersOption" style="display: none;">
                                <label for="individual_emails" class="form-label h6 mb-3">이메일 주소</label>
                                <textarea class="form-control" name="individual_emails" id="individual_emails" 
                                          rows="4" placeholder="이메일 주소를 쉼표(,)로 구분하여 입력하세요.&#10;예: user1@example.com, user2@example.com"></textarea>
                                <p class="mt-2 text-primary">여러 이메일 주소는 쉼표(,)로 구분하여 입력하세요.</p>
                            </div>
                            
                            <!-- 제목 -->
                            <div class="mb-3">
                                <label for="subject" class="form-label h6 mb-3">제목 <span class="text-danger">*</span></label>
                                <input type="text" class="form-control" name="subject" id="subject" required>
                            </div>
                            
                            <!-- 내용 -->
                            <div class="mb-3">
                                <label for="content" class="form-label h6 mb-3">내용 <span class="text-danger">*</span></label>
                                <div id="editor" style="height: 300px;"></div>
                                <input type="hidden" name="content" id="content">
                            </div>
                            
                            <!-- 첨부파일 -->
                            <div class="mb-4">
                                <label class="form-label h6 mb-3">첨부파일</label>
                                <input type="file" id="fileInput" class="form-control" name="attachment" accept=".jpg,.jpeg,.png,.gif,.pdf,.doc,.docx,.hwp,.xls,.xlsx,.txt">
                                <div class="mt-3 text-muted">
                                    <strong>용량 제한:</strong> 파일 10MB<br>
                                    <strong>지원 형식:</strong> jpg, png, gif, pdf, doc, hwp, xls, txt<br>
                                    <strong class="text-danger">주의:</strong> ZIP 파일은 Gmail 보안 정책으로 인해 발송이 차단됩니다.<br>
                                    <strong class="text-info">대안:</strong> ZIP 파일은 Google Drive에 업로드 후 링크를 공유하세요.
                                </div>
                            </div>
                            
                            <!-- 발송 버튼 -->
                            <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                                <?php if(!empty($config['google_email']) && !empty($config['google_appkey'])){?><button type="submit" class="btn btn-primary px-4">📧 이메일 발송</button><?php } ?>
                                <a href="./member_list.php" class="btn btn-secondary px-4">취소</a>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>


<?php
include_once CM_ADMIN_PATH.'/admin.tail.php';
?>