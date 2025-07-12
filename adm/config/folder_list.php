<?php
include_once './_common.php';
$cm_title = "폴더구조";
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
                                <i class="bi bi-folder-check me-2"></i><?php echo $cm_title;?>
                            </h2>
                            <p class="card-text text-muted mb-0">폴더구조를 확인할 수 있습니다.</p>
                        </div>
                    </div>
                </div>
            </div>
			
			<div class="row mb-4">
				<div class="col-12">
					<?php echo showTree(CM_PATH, '', ['PHPMailer', 'data']);?>
				</div>
			</div>
		
		</div>
    </div>

    
<?php
include_once CM_ADMIN_PATH.'/admin.tail.php';
?>