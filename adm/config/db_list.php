<?php
include_once './_common.php';
$cm_title = "DB 테이블 내용확인";
include_once CM_ADMIN_PATH.'/admin.head.php';
?>
<style>

    </style>
    <!-- Main Content -->
    <div class="main-content shifted" id="mainContent">
        <div class="container-fluid">
            <!-- 헤더 카드 -->
            <div class="card shadow-sm mb-4 border-0 card-move">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h2 class="card-title mb-1 text-primary">
                                <i class="bi bi-folder-check me-2"></i><?php echo $cm_title;?>
                            </h2>
                            <p class="card-text text-muted mb-0">데이터베이스 테이블을 확인할 수 있습니다.</p>
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
                                    <h5 class="mb-1 text-dark">사용 방법</h5>
                                    <ul>
										<li>아래 입력란에 조회하고 싶은 테이블명을 입력하세요</li>
										<li>제한 행수를 입력하면 해당 수만큼만 표시됩니다 (비워두면 전체 표시)</li>
										<li>Submit 버튼을 클릭하면 명령프롬프트 스타일로 테이블이 표시됩니다</li>
										<li>테이블명은 영문자, 숫자, 언더스코어(_)만 사용 가능합니다</li>
										<li>제한 행수는 1~10000 사이의 숫자만 입력 가능합니다. (LIMIT 1, 10000)</li>
									</ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
			
			<!-- 검색 폼 -->
			<div class="card mb-4">
				<div class="card-body">
					<form method="GET" class="row g-3" id="searchForm">
						<div class="col-md-2">
							<label for="table" class="form-label">테이블명:</label>
							<input type="text" 
								   id="table" 
								   class="form-control"
								   name="table" 
								   placeholder="예: users, menus..." 
								   value="<?php echo isset($_GET['table']) ? htmlspecialchars($_GET['table']) : ''; ?>"
								   required>
						</div>
						
						<div class="col-md-2">
							<label for="limit_start" class="form-label">시작 번호:</label>
							<input type="number" 
								   id="limit_start" 
								   class="form-control"
								   name="limit_start" 
								   placeholder="예: 5" 
								   min="1" 
								   max="10000"
								   value="<?php echo isset($_GET['limit_start']) ? htmlspecialchars($_GET['limit_start']) : ''; ?>">
						</div>
						
						<div class="col-md-2">
							<label for="limit_end" class="form-label">끝 번호:</label>
							<input type="number" 
								   id="limit_end" 
								   class="form-control"
								   name="limit_end" 
								   placeholder="예: 10" 
								   min="1" 
								   max="10000"
								   value="<?php echo isset($_GET['limit_end']) ? htmlspecialchars($_GET['limit_end']) : ''; ?>">
						</div>
						
						<div class="col-md-2">
							<label for="order" class="form-label">정렬 방향:</label>
							<select id="order" name="order" class="form-select">
								<option value="asc" <?php echo (!isset($_GET['order']) || $_GET['order'] == 'asc') ? 'selected' : ''; ?>>
									오름차순 (ASC)
								</option>
								<option value="desc" <?php echo (isset($_GET['order']) && $_GET['order'] == 'desc') ? 'selected' : ''; ?>>
									내림차순 (DESC)
								</option>
							</select>
						</div>
						
						<div class="col-md-2 d-flex align-items-end">
							<button type="submit" class="btn btn-primary me-2">검색</button>
						</div>
					</form>
				</div>
			</div>

			<div class="row mb-4">
				<div class="col-12">
					<div class="result-container">
							<?php echo displayTableFromGet(); ?>
					</div>
					
				</div>
			</div>
		
	</div>

<?php
include_once CM_ADMIN_PATH.'/admin.tail.php';
?>