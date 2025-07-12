<?php
include_once './_common.php';
$cm_title = "회원 관리";
include_once CM_ADMIN_PATH.'/admin.head.php'; 

$options = [
    'table' => 'cm_users',
    'page' => $_GET['page'] ?? 1,
    'per_page' => 20,
    'order_by' => 'user_no DESC',
    'conditions' => []
];

// 정렬 처리
$sort_field = $_GET['sort'] ?? 'user_no';
$sort_order = $_GET['order'] ?? 'DESC';

// 정렬 가능한 필드 목록 가져오기
$sortable_fields = get_sortable_fields('cm_users');

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
        case 'user_name':
            $options['conditions'][] = ['field' => 'user_name', 'operator' => 'LIKE', 'value' => "%{$search_keyword}%"];
            break;
        case 'user_hp':
            $options['conditions'][] = ['field' => 'user_hp', 'operator' => 'LIKE', 'value' => "%{$search_keyword}%"];
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
                                <i class="bi bi-people-fill me-2"></i><?php echo $cm_title;?>
                            </h2>
                            <p class="card-text text-muted mb-0">회원 목록 입니다.</p>
                        </div>
                        <div>
                            <a href="member_form.php" class="btn btn-primary btn-lg shadow-sm">
                                <i class="fas fa-plus me-2"></i>신규회원등록
                            </a>
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
								<option value="user_id" <?php echo (isset($_GET['search_type']) && $_GET['search_type'] === 'user_id') ? 'selected' : ''; ?>>아이디</option>
								<option value="user_name" <?php echo (isset($_GET['search_type']) && $_GET['search_type'] === 'user_name') ? 'selected' : ''; ?>>이름</option>
								<option value="user_hp" <?php echo (isset($_GET['search_type']) && $_GET['search_type'] === 'user_hp') ? 'selected' : ''; ?>>휴대폰</option>
							</select>
						</div>
						<div class="col-md-6">
							<label for="search_keyword" class="form-label">검색어 <span class="text-danger">*</span></label>
							<input type="text" class="form-control" id="search_keyword" name="search_keyword" value="<?php echo isset($_GET['search_keyword']) ? htmlspecialchars($_GET['search_keyword']) : ''; ?>" required>
						</div>
						<div class="col-md-3 d-flex align-items-end">
							<button type="submit" class="btn btn-primary me-2">검색</button>
							<a href="member_list.php" class="btn btn-secondary">초기화</a>
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
								아이디
								<?php echo get_sort_icon($sort_field, $sort_order, 'user_id'); ?>
							</th>
							<th scope="col" class="sortable" data-field="user_name">
								이름
								<?php echo get_sort_icon($sort_field, $sort_order, 'user_name'); ?>
							</th>
							<th scope="col" class="sortable" data-field="user_email">
								이메일
								<?php echo get_sort_icon($sort_field, $sort_order, 'user_email'); ?>
							</th>
							<th scope="col" class="sortable" data-field="user_hp">
								휴대폰 번호
								<?php echo get_sort_icon($sort_field, $sort_order, 'user_hp'); ?>
							</th>
							<th scope="col" class="sortable" data-field="user_lv">
								레벨
								<?php echo get_sort_icon($sort_field, $sort_order, 'user_lv'); ?>
							</th>
							<th scope="col" class="sortable" data-field="user_point">
								포인트
								<?php echo get_sort_icon($sort_field, $sort_order, 'user_point'); ?>
							</th>
							<th scope="col" class="sortable" data-field="created_at">
								가입일
								<?php echo get_sort_icon($sort_field, $sort_order, 'created_at'); ?>
							</th>
							<th scope="col">관리</th>
						</tr>
					</thead>
					<tbody>
						<?php if (empty($result['list'])){ ?>
							<tr>
								<td colspan="9" class="text-center">등록된 회원이 없습니다.</td>
							</tr>
						<?php } else { ?>
							<?php 
							$start_number = $result['total_rows'] - ($page - 1) * $options['per_page'];
							foreach ($result['list'] as $index => $list) {
								$list_no = $start_number - $index;
							?>
							<tr class="text-center">
								<td><?php echo $list_no;?></td>
								<td><?php echo htmlspecialchars($list['user_id'] ?? '');?></td>
								<td><?php echo htmlspecialchars($list['user_name'] ?? '');?></td>
								<td><?php echo htmlspecialchars($list['user_email'] ?? '');?></td>
								<td><?php echo htmlspecialchars($list['user_hp'] ?? '');?></td>
								<td><?php echo $list['user_lv'];?></td>
								<td><?php echo number_format($list['user_point']);?></td>
								<td><?php echo get_formatDate($list['created_at'], 'Y-m-d h:i:s');?></td>
								<td>
									<a href="member_form.php?user_no=<?php echo $list['user_no'];?>" class="btn btn-sm btn-primary me-2">수정</a>
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