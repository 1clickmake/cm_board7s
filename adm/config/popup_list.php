<?php
include_once './_common.php';
$cm_title = "팝업레이어 관리";
include_once CM_ADMIN_PATH.'/admin.head.php';

// 목록 조회 옵션 설정
$options = [
    'table' => 'cm_popup',
    'page' => $_GET['page'] ?? 1,
    'per_page' => 20,
    'order_by' => 'po_id DESC',
    'conditions' => []
];

$result = sql_list($options);
$total_pages = $result['total_pages'];
$page = $result['current_page'];
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
                                <i class="fas fa-window-restore me-2"></i><?php echo $cm_title;?>
                            </h2>
                            <p class="card-text text-muted mb-0">팝업 레이어를 관리하고 설정할 수 있습니다.</p>
                        </div>
                        <div>
                            <a href="popup_form.php" class="btn btn-primary btn-lg shadow-sm">
                                <i class="fas fa-plus me-2"></i>팝업 생성
                            </a>
                        </div>
                    </div>
                </div>
            </div>
			
			<!-- 통계 카드 -->
            <div class="row mb-4">
				<?php
                $total_count = $result['total_rows'];
                $active_count = 0;
                $waiting_count = 0;
                $expired_count = 0;
                $inactive_count = 0;
                
                $today = date('Y-m-d');
                foreach ($result['list'] as $item) {
                    if ($item['po_use'] == 0) {
                        $inactive_count++;
                    } elseif ($today < $item['po_start_date']) {
                        $waiting_count++;
                    } elseif ($today > $item['po_end_date']) {
                        $expired_count++;
                    } else {
                        $active_count++;
                    }
                }
                ?>
                <div class="col-lg-3 col-md-6 mb-4">
                    <div class="card stats-card card-visits text-white">
                        <div class="card-body">
                            <i class="fas fa-users card-icon"></i>
                            <h5 class="card-title"><i class="fas fa-list-alt fa-2x"></i></h5>
                            <h2 class="card-number"><?php echo $total_count; ?></h2>
                            <p class="card-subtitle mb-0">전체 팝업</p>
                        </div>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6 mb-4">
                    <div class="card stats-card card-today text-white">
                        <div class="card-body">
                            <i class="fas fa-calendar-day card-icon"></i>
                            <h5 class="card-title"><i class="fas fa-play-circle fa-2x"></i></h5>
                            <h2 class="card-number"><?php echo $active_count; ?></h2>
                            <p class="card-subtitle mb-0">활성 팝업</p>
                        </div>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6 mb-4">
                    <div class="card stats-card card-yesterday text-white">
                        <div class="card-body">
                            <i class="fas fa-chart-line card-icon"></i>
                            <h5 class="card-title"> <i class="fas fa-clock fa-2x"></i></h5>
                            <h2 class="card-number"><?php echo $waiting_count; ?></h2>
                            <p class="card-subtitle mb-0">대기 팝업</p>
                        </div>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6 mb-4">
                    <div class="card stats-card card-posts text-white">
                        <div class="card-body">
                            <i class="fas fa-edit card-icon"></i>
                            <h5 class="card-title"><i class="fas fa-stop-circle fa-2x"></i></h5>
                            <h2 class="card-number"><?php echo $expired_count + $inactive_count; ?></h2>
                            <p class="card-subtitle mb-0">비활성 팝업</p>
                        </div>
                    </div>
                </div>
            </div>
			
           

            <!-- 메인 테이블 카드 -->
            <div class="card shadow-sm border-0">
                <div class="card-header bg-white border-bottom">
                    <div class="d-flex justify-content-between align-items-center">
                        <h5 class="card-title mb-0">
                            <i class="fas fa-table me-2 text-primary"></i>팝업 목록
                        </h5>
                        <small class="text-muted">총 <?php echo $total_count; ?>개의 팝업</small>
                    </div>
                </div>
                <div class="card-body p-0">
                    <div class="table-responsive">
                        <table class="table table-hover table-striped align-middle mb-0" style="min-width:1200px;">
                            <thead class="table-dark">
                                <tr class="text-center">
                                    <th scope="col" style="width: 80px;">No</th>
                                    <th scope="col">팝업 제목</th>
                                    <th scope="col">노출 기간</th>
                                    <th scope="col" style="width: 120px;">크기</th>
                                    <th scope="col" style="width: 100px;">상태</th>
                                    <th scope="col" style="width: 150px;">관리</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($result['list'])){ ?>
                                    <tr>
                                        <td colspan="6" class="text-center py-5">
                                            <div class="text-muted">
                                                <i class="fas fa-inbox fa-3x mb-3"></i>
                                                <p class="mb-0">등록된 팝업이 없습니다.</p>
                                                <small>새로운 팝업을 생성해보세요.</small>
                                            </div>
                                        </td>
                                    </tr>
                                <?php } else { ?>
                                    <?php 
                                    $start_number = $result['total_rows'] - ($page - 1) * $options['per_page'];
                                    foreach ($result['list'] as $index => $list) {
                                        $list_no = $start_number - $index;
                                    ?>
                                    <tr class="text-center">
                                        <td>
                                            <span class="badge bg-light text-dark"><?php echo $list_no;?></span>
                                        </td>
                                        <td class="text-start">
                                            <div class="d-flex align-items-center">
                                                <i class="fas fa-window-maximize text-primary me-2"></i>
                                                <div>
													<small class="text-muted">POPUP-ID: <?php echo $list['po_id']; ?></small>
                                                    <div class="fw-semibold"><?php echo htmlspecialchars($list['po_title']);?></div>
                                                    
                                                </div>
                                            </div>
                                        </td>
                                        <td>
                                            <div class="text-center">
                                                <div class="small">
                                                    <i class="fas fa-calendar-alt text-muted me-1"></i>
                                                    <?php echo $list['po_start_date']; ?>
													~
                                                    <i class="fas fa-calendar-alt text-muted me-1"></i>
                                                    <?php echo $list['po_end_date']; ?>
                                                </div>
                                            </div>
                                        </td>
                                        <td>
                                            <span class="badge bg-info text-dark">
                                                <?php echo $list['po_width'] . '×' . $list['po_height'];?>
                                            </span>
                                        </td>
                                        <td>
                                            <?php
                                            $today = date('Y-m-d');
                                            $start_date = $list['po_start_date'];
                                            $end_date = $list['po_end_date'];
                                            $status = '';
                                            
                                            if ($list['po_use'] == 0) {
                                                $status = '<span class="badge bg-secondary"><i class="fas fa-pause me-1"></i>미사용</span>';
                                            } elseif ($today < $start_date) {
                                                $status = '<span class="badge bg-warning text-dark"><i class="fas fa-clock me-1"></i>대기</span>';
                                            } elseif ($today > $end_date) {
                                                $status = '<span class="badge bg-danger"><i class="fas fa-stop me-1"></i>종료</span>';
                                            } else {
                                                $status = '<span class="badge bg-success"><i class="fas fa-play me-1"></i>활성</span>';
                                            }
                                            
                                            echo $status;
                                            ?>
                                        </td>
                                        <td>
                                            <div class="btn-group" role="group">
                                                <a href="popup_form.php?po_id=<?php echo $list['po_id'];?>" 
                                                   class="btn btn-sm btn-outline-primary" 
                                                   data-bs-toggle="tooltip" 
                                                   title="수정">
                                                    <i class="fas fa-edit"></i>
                                                </a>
                                                <button type="button" 
                                                        class="btn btn-sm btn-outline-danger delete-popup" 
                                                        data-po-id="<?php echo $list['po_id'];?>" 
                                                        data-po-title="<?php echo htmlspecialchars($list['po_title']);?>"
                                                        data-bs-toggle="tooltip" 
                                                        title="삭제">
                                                    <i class="fas fa-trash"></i>
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                    <?php } ?>
                                <?php } ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <!-- 페이지네이션 카드 푸터 -->
                <?php if ($total_pages > 1) { ?>
                <div class="card-footer bg-white border-top-0">
                    <div class="d-flex justify-content-center">
                        <?php echo render_pagination($page, $total_pages, $_GET); ?>
                    </div>
                </div>
                <?php } ?>
            </div>
        </div>

        <!-- 삭제 확인 모달 -->
        <div class="modal fade" id="deleteModal" tabindex="-1" aria-labelledby="deleteModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content border-0 shadow">
                    <div class="modal-header bg-danger text-white">
                        <h5 class="modal-title" id="deleteModalLabel">
                            <i class="fas fa-exclamation-triangle me-2"></i>팝업 삭제 확인
                        </h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body text-center py-4">
                        <div class="mb-3">
                            <i class="fas fa-question-circle fa-3x text-warning"></i>
                        </div>
                        <p id="deleteModalMessage" class="lead"></p>
                        <p class="text-muted small">이 작업은 되돌릴 수 없습니다.</p>
                    </div>
                    <div class="modal-footer justify-content-center">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                            <i class="fas fa-times me-2"></i>취소
                        </button>
                        <form id="deleteForm" method="post" action="popup_form_update.php" class="d-inline">
                            <input type="hidden" name="po_id" id="deletePoId" value="">
                            <input type="hidden" name="mode" value="delete">
                            <button type="submit" class="btn btn-danger">
                                <i class="fas fa-trash me-2"></i>삭제
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

<script>
    $(document).ready(function() {
        // 툴팁 초기화
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl)
        });

        // 팝업 삭제 버튼 클릭 이벤트
        $('.delete-popup').click(function() {
            const poId = $(this).data('po-id');
            const poTitle = $(this).data('po-title');
            
            $('#deletePoId').val(poId);
            $('#deleteModalMessage').text(`"${poTitle}" 팝업을 삭제하시겠습니까?`);
            
            $('#deleteModal').modal('show');
        });

        // 테이블 행 호버 효과 향상
        $('tbody tr').hover(
            function() {
                $(this).addClass('table-active');
            },
            function() {
                $(this).removeClass('table-active');
            }
        );
    });
</script>

<style>

</style>
   
<?php
include_once CM_ADMIN_PATH.'/admin.tail.php';
?>