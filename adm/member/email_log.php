<?php
include_once './_common.php';
include_once CM_ADMIN_PATH.'/admin.head.php';

// 페이지네이션 설정
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$limit = 20;
$offset = ($page - 1) * $limit;

// 로그 조회
$sql = "SELECT * FROM cm_email_log ORDER BY created_at DESC LIMIT :limit OFFSET :offset";
$params = [
    ':limit' => $limit,
    ':offset' => $offset
];
$logs = sql_all_list($sql, $params);

// 전체 로그 수 조회
$count_sql = "SELECT COUNT(*) as total FROM cm_email_log";
$total_count = sql_fetch($count_sql)['total'];
$total_pages = ceil($total_count / $limit);
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
                                <i class="bi bi-people-fill me-2"></i><?php echo $cm_title;?>
                            </h2>
                            <p class="card-text text-muted mb-0">발송된 이메일로그를 확인합니다.</p>
                        </div>
                        <div>
                            <a href="email_form.php" class="btn btn-primary btn-lg shadow-sm">
                                <i class="fas fa-plus me-2"></i>새 이메일 발송
                            </a>
                        </div>
                    </div>
                </div>
            </div>
			
        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h4 class="card-title">📧 이메일 발송 로그</h4>
                    </div>
                    <div class="card-body">
                        <?php if (empty($logs)): ?>
                            <div class="text-center py-5">
                                <h5 class="text-muted">발송된 이메일이 없습니다.</h5>
                                <a href="email_form.php" class="btn btn-primary mt-3">첫 이메일 발송하기</a>
                            </div>
                        <?php else: ?>
                            <div class="table-responsive">
                                <table class="table table-striped text-center">
                                    <thead>
                                        <tr>
                                            <th>번호</th>
                                            <th>발송자</th>
                                            <th>수신자 타입</th>
                                            <th>제목</th>
                                            <th>수신자 수</th>
                                            <th>성공/실패</th>
                                            <th>발송 시간</th>
                                            <th>상세보기</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($logs as $log): ?>
                                            <tr>
                                                <td><?php echo $log['log_id']; ?></td>
                                                <td><?php echo htmlspecialchars($log['sender_id']); ?></td>
                                                <td>
                                                    <?php
                                                    $type_names = [
                                                        'all' => '전체회원',
                                                        'level' => '레벨별',
                                                        'individual' => '개별회원'
                                                    ];
                                                    echo $type_names[$log['recipient_type']] ?? $log['recipient_type'];
                                                    ?>
                                                </td>
                                                <td class="text-start">
                                                    <span class="text-truncate d-inline-block" style="max-width: 200px;" 
                                                          title="<?php echo htmlspecialchars($log['subject']); ?>">
                                                        <?php echo htmlspecialchars($log['subject']); ?>
                                                    </span>
                                                </td>
                                                <td><?php echo count(json_decode($log['recipients'], true)); ?>명</td>
                                                <td>
                                                    <span class="badge bg-success"><?php echo $log['success_count']; ?></span>
                                                    <?php if ($log['fail_count'] > 0): ?>
                                                        <span class="badge bg-danger"><?php echo $log['fail_count']; ?></span>
                                                    <?php endif; ?>
                                                </td>
                                                <td><?php echo get_formatDate($log['created_at'], 'Y-m-d H:i'); ?></td>
                                                <td>
                                                    <button type="button" class="btn btn-sm btn-outline-info" 
                                                            onclick="showLogDetail(<?php echo $log['log_id']; ?>)">
                                                        상세보기
                                                    </button>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                            
                            <!-- 페이지네이션 -->
                            <?php if ($total_pages > 1): ?>
                                <nav aria-label="이메일 로그 페이지네이션">
                                    <ul class="pagination justify-content-center">
                                        <?php if ($page > 1): ?>
                                            <li class="page-item">
                                                <a class="page-link" href="?page=<?php echo $page - 1; ?>">이전</a>
                                            </li>
                                        <?php endif; ?>
                                        
                                        <?php for ($i = max(1, $page - 2); $i <= min($total_pages, $page + 2); $i++): ?>
                                            <li class="page-item <?php echo $i == $page ? 'active' : ''; ?>">
                                                <a class="page-link" href="?page=<?php echo $i; ?>"><?php echo $i; ?></a>
                                            </li>
                                        <?php endfor; ?>
                                        
                                        <?php if ($page < $total_pages): ?>
                                            <li class="page-item">
                                                <a class="page-link" href="?page=<?php echo $page + 1; ?>">다음</a>
                                            </li>
                                        <?php endif; ?>
                                    </ul>
                                </nav>
                            <?php endif; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- 로그 상세보기 모달 -->
<div class="modal fade" id="logDetailModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">이메일 발송 상세정보</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body" id="logDetailContent">
                <!-- 상세 내용이 여기에 로드됩니다 -->
            </div>
        </div>
    </div>
</div>

<script>
function showLogDetail(logId) {
    // AJAX로 로그 상세 정보 로드
    fetch(CM.ADMIN_URL + `/ajax/get_email_log_detail.php?log_id=${logId}`)
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                document.getElementById('logDetailContent').innerHTML = data.html;
                new bootstrap.Modal(document.getElementById('logDetailModal')).show();
            } else {
                alert('로그 정보를 불러오는데 실패했습니다.');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('로그 정보를 불러오는데 실패했습니다.');
        });
}
</script>

<?php
include_once CM_ADMIN_PATH.'/admin.tail.php';
?> 