<?php
include_once './_common.php';
$cm_title = "포인트 관리";
include_once CM_ADMIN_PATH.'/admin.head.php';

$options = [
    'table' => 'cm_point',
    'page' => $_GET['page'] ?? 1,
    'per_page' => 20,
    'order_by' => 'id DESC',
    'conditions' => []
];

// 정렬 처리
$sort_field = $_GET['sort'] ?? 'id';
$sort_order = $_GET['order'] ?? 'DESC';

// 정렬 가능한 필드 목록 가져오기
$sortable_fields = get_sortable_fields('cm_point');

// 정렬 필드가 유효한지 확인
if (in_array($sort_field, $sortable_fields)) {
    $options['order_by'] = $sort_field . ' ' . $sort_order;
}

// 검색 조건이 있는 경우에만 conditions에 추가
if (!empty($_GET['search_type']) && !empty($_GET['search_keyword'])) {
    $search_type = $_GET['search_type'];
    $search_keyword = $_GET['search_keyword'];
    
    switch($search_type) {
        case 'user_id':
            $options['conditions'][] = ['field' => 'user_id', 'operator' => 'LIKE', 'value' => "%{$search_keyword}%"];
            break;
        case 'description':
            $options['conditions'][] = ['field' => 'description', 'operator' => 'LIKE', 'value' => "%{$search_keyword}%"];
            break;
    }
}

$result = sql_list($options);
$total_pages = $result['total_pages'];
$page = $result['current_page'];
?>
<input type="hidden" id="sort_field" value="<?php echo $sort_field;?>">
<input type="hidden" id="sort_order" value="<?php echo $sort_order;?>">

    <!-- Main Content -->
    <div class="main-content shifted" id="mainContent">
        <div class="container-fluid">
			<!-- 헤더 카드 -->
            <div class="card shadow-sm mb-4 border-0 card-move">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h2 class="card-title mb-1 text-primary">
                                <i class="bi bi-database-fill-add me-2"></i><?php echo $cm_title;?>
                            </h2>
                            <p class="card-text text-muted mb-0">회원 포인트를 관리합니다.</p>
                        </div>
                    </div>
                </div>
            </div>
			
			<!-- 검색 폼 -->
			<div class="card mb-4">
				<div class="card-body">
					<form method="get" class="row g-3" id="searchForm" onsubmit="return validateSearch()">
						<div class="col-md-3">
							<label for="search_type" class="form-label">검색 구분 <span class="text-danger">*</span></label>
							<select class="form-select" id="search_type" name="search_type" required>
								<option value="">선택하세요</option>
								<option value="user_id" <?php echo (isset($_GET['search_type']) && $_GET['search_type'] === 'user_id') ? 'selected' : ''; ?>>회원 아이디</option>
								<option value="description" <?php echo (isset($_GET['search_type']) && $_GET['search_type'] === 'description') ? 'selected' : ''; ?>>포인트 내용</option>
							</select>
						</div>
						<div class="col-md-6">
							<label for="search_keyword" class="form-label">검색어 <span class="text-danger">*</span></label>
							<input type="text" class="form-control" id="search_keyword" name="search_keyword" value="<?php echo isset($_GET['search_keyword']) ? htmlspecialchars($_GET['search_keyword']) : ''; ?>" required>
						</div>
						<div class="col-md-3 d-flex align-items-end">
							<button type="submit" class="btn btn-primary me-2">검색</button>
							<a href="point_list.php" class="btn btn-secondary">초기화</a>
						</div>
					</form>
				</div>
			</div>

			<div class="table-responsive">
				<table class="table table-sm table-striped table-bordered align-middle" style="min-width:1200px;">
					<thead class="table-dark text-center">
						<tr>
							<th scope="col">No</th>
							<th scope="col" class="sortable" data-field="user_id">
								회원 아이디
								<?php echo get_sort_icon($sort_field, $sort_order, 'user_id'); ?>
							</th>
							<th scope="col" class="sortable" data-field="description">
								포인트 내용
								<?php echo get_sort_icon($sort_field, $sort_order, 'description'); ?>
							</th>
							<th scope="col" class="sortable" data-field="point">
								지급포인트
								<?php echo get_sort_icon($sort_field, $sort_order, 'point'); ?>
							</th>
							<th scope="col" class="sortable" data-field="created_at">
								등록일
								<?php echo get_sort_icon($sort_field, $sort_order, 'created_at'); ?>
							</th>
							<th scope="col">삭제</th>
						</tr>
					</thead>
					<tbody>
						<?php if (empty($result['list'])){ ?>
							<tr>
								<td colspan="6" class="text-center">포인트 내역이 없습니다.</td>
							</tr>
						<?php } else { ?>
							<?php 
							$start_number = $result['total_rows'] - ($page - 1) * $options['per_page'];
							foreach ($result['list'] as $index => $list) {
								$list_no = $start_number - $index;
							?>
							<tr class="text-center">
								<td><?php echo $list_no; ?></td>
								<td><?php echo htmlspecialchars($list['user_id'] ?? ''); ?></td>
								<td><?php echo htmlspecialchars($list['description'] ?? ''); ?></td>
								<td><?php echo number_format($list['point']); ?></td>
								<td><?php echo $list['created_at']; ?></td>
								<td>
									<form action="point_update.php" method="POST" onsubmit="return confirm('정말로 삭제하시겠습니까?');" style="display: inline;">
										<input type="hidden" name="id" value="<?php echo $list['id']; ?>">
										<input type="hidden" name="action" value="delete">
										<button type="submit" class="btn btn-danger btn-sm">삭제</button>
									</form>
								</td>
							</tr>
							<?php } ?>
						<?php } ?>
					</tbody>
				</table>
			</div>
			
			<!-- 페이지네이션 -->
			<?php echo render_pagination($page, $total_pages, $_GET);?>
			<!-- 페이지네이션 끝-->

			<!-- 포인트 지급 폼 -->
			<div class="card mt-5">
				<div class="card-header">
					<h3 class="mb-0">포인트 지급</h3>
				</div>
				<div class="card-body">
					<form action="point_update.php" method="POST" class="row g-3">
						<input type="hidden" name="action" value="add">
						<div class="col-md-4">
							<label for="user_id" class="form-label">회원 아이디</label>
							<input type="text" class="form-control" id="user_id" name="user_id" required>
						</div>
						<div class="col-md-4">
							<label for="description" class="form-label">포인트 내용</label>
							<input type="text" class="form-control" id="description" name="description" required>
						</div>
						<div class="col-md-4">
							<label for="point" class="form-label">지급 포인트</label>
							<input type="number" class="form-control" id="point" name="point" required min="1">
						</div>
						
						<div class="col-12">
							<button type="submit" class="btn btn-primary">포인트 지급</button>
						</div>
					</form>
				</div>
			</div>
		</div>
    </div>

<script>
    function validateSearch() {
        // 검색 유효성 검사 로직이 필요하면 여기에 추가
        return true;
    }
</script>
   
<?php
include_once CM_ADMIN_PATH.'/admin.tail.php';
?>