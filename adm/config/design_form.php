<?php
include_once './_common.php';
$cm_title = "디자인 설정";
include_once CM_ADMIN_PATH.'/admin.head.php';
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
                                <i class="bi bi-palette me-2"></i><?php echo $cm_title;?>
                            </h2>
                            <p class="card-text text-muted mb-0">홈페이지 디자인을  관리합니다.</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- 설명 카드 -->
            <div class="row mb-4">
                <div class="col-12">
                    <div class="card chart-card">
                        <div class="card-body p-4">
                            <div class="d-flex align-items-center">
                                <div class="me-3">
                                    <i class="fas fa-info-circle text-primary" style="font-size: 2rem;"></i>
                                </div>
                                <div>
                                    <h5 class="mb-1 text-dark">템플릿 설정 안내</h5>
                                    <p class="mb-0 text-muted">커뮤니티와 쇼핑몰의 디자인 템플릿을 선택하여 사이트의 외관을 변경할 수 있습니다.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
			
			<!-- 추가 정보 카드들 -->
            <div class="row mt-5">
                <div class="col-md-4 mb-3">
                    <div class="stats-card card-visits h-100">
                        <div class="card-body text-white text-center">
                            <div class="card-icon">
                                <i class="fas fa-paint-brush"></i>
                            </div>
                            <h6 class="card-title">디자인 변경</h6>
                            <p class="card-subtitle">선택한 템플릿으로 즉시 적용됩니다</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4 mb-3">
                    <div class="stats-card card-today h-100">
                        <div class="card-body text-white text-center">
                            <div class="card-icon">
                                <i class="fas fa-mobile-alt"></i>
                            </div>
                            <h6 class="card-title">반응형 디자인</h6>
                            <p class="card-subtitle">모든 디바이스에서 최적화된 화면</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4 mb-3">
                    <div class="stats-card card-posts h-100">
                        <div class="card-body text-white text-center">
                            <div class="card-icon">
                                <i class="fas fa-rocket"></i>
                            </div>
                            <h6 class="card-title">빠른 로딩</h6>
                            <p class="card-subtitle">최적화된 템플릿으로 빠른 성능</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 메인 설정 카드 -->
            <div class="row justify-content-center">
                <div class="col">
                    <div class="card table-card">
                        <div class="card-header text-start">
                            <h5><i class="fas fa-cog me-2"></i>템플릿 설정</h5>
                        </div>
                        <div class="card-body p-4">
                            <form action="./design_form_update.php" method="post" id="designForm">
								<!-- CSRF 토큰 (예시) -->
								<!-- <input type="hidden" name="csrf_token" value="<?php // echo htmlspecialchars($_SESSION['csrf_token']); ?>"> -->
								<div class="row">
									<div class="col-md-6">
										<!-- 커뮤니티 템플릿 선택 -->
										<div class="mb-4">
											<label for="templateId" class="form-label fw-semibold">
												<i class="fas fa-users me-2 text-primary"></i>커뮤니티 템플릿
											</label>
											<div class="input-group">
												<span class="input-group-text bg-light border-end-0">
													<i class="fas fa-desktop text-muted"></i>
												</span>
												<select class="form-select border-start-0" id="templateId" name="template_id" required>
													<option value="">템플릿을 선택해주세요</option>
													<?php
													$folderDirectory = CM_PATH.'/template/community';
													$folders = getSubdirectories($folderDirectory);
													foreach ($folders as $folder) {
													    $safe_folder = htmlspecialchars($folder);
													?><option value="<?php echo $safe_folder;?>" <?php echo ($folder == $config['template_id']) ? 'selected' : ''; ?>><?php echo $safe_folder;?></option>
													<?php } ?>
												</select>
											</div>
											<div class="form-text">
												<i class="fas fa-lightbulb text-warning me-1"></i>
												커뮤니티 페이지의 디자인을 결정하는 템플릿입니다.
											</div>
										</div>
									</div>
                                
									<div class="col-md-6">
										<!-- 쇼핑몰 템플릿 선택 -->
										<div class="mb-4">
											<label for="shoptemplateId" class="form-label fw-semibold">
												<i class="fas fa-shopping-cart me-2 text-success"></i>쇼핑몰 템플릿
											</label>
											<div class="input-group">
												<span class="input-group-text bg-light border-end-0">
													<i class="fas fa-store text-muted"></i>
												</span>
												<select class="form-select border-start-0" id="shoptemplateId" name="shop_template_id" required>
													<option value="">템플릿을 선택해주세요</option>
													<?php
													$folderDirectory = CM_PATH.'/template/shop';
													$folders = getSubdirectories($folderDirectory);
													foreach ($folders as $folder) {
													    $safe_folder = htmlspecialchars($folder);
													?><option value="<?php echo $safe_folder;?>" <?php echo ($folder == $config['shop_template_id']) ? 'selected' : ''; ?>><?php echo $safe_folder;?></option>
													<?php } ?>
												</select>
											</div>
											<div class="form-text">
												<i class="fas fa-lightbulb text-warning me-1"></i>
												쇼핑몰 페이지의 디자인을 결정하는 템플릿입니다.
											</div>
										</div>
									</div>
								</div><!--//row-->

                                <!-- 버튼 그룹 -->
                                <div class="d-grid gap-2 d-md-flex justify-content-md-center mt-4">
                                    <button type="button" class="btn btn-outline-secondary me-md-2" onclick="resetForm()">
                                        <i class="fas fa-undo me-2"></i>초기화
                                    </button>
                                    <button type="submit" class="btn btn-primary">
                                        <i class="fas fa-save me-2"></i>설정 저장
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>

            
        </div>
    </div>

    <script>
    // 폼 초기화 함수
    function resetForm() {
        if (confirm('설정을 초기화하시겠습니까?')) {
            document.getElementById('designForm').reset();
        }
    }

    // 폼 제출 시 확인
    document.getElementById('designForm').addEventListener('submit', function(e) {
        const communityTemplate = document.getElementById('templateId').value;
        const shopTemplate = document.getElementById('shoptemplateId').value;
        
        if (!communityTemplate || !shopTemplate) {
            e.preventDefault();
            alert('모든 템플릿을 선택해주세요.');
            return false;
        }
        
        if (!confirm('선택한 템플릿으로 디자인을 변경하시겠습니까?')) {
            e.preventDefault();
            return false;
        }
    });

    // 선택 시 미리보기 효과 (옵션)
    document.getElementById('templateId').addEventListener('change', function() {
        this.style.borderColor = this.value ? '#28a745' : '#ced4da';
    });
    
    document.getElementById('shoptemplateId').addEventListener('change', function() {
        this.style.borderColor = this.value ? '#28a745' : '#ced4da';
    });
    </script>

<?php
include_once CM_ADMIN_PATH.'/admin.tail.php';
?>