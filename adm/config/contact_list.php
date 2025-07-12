<?php
include_once './_common.php';
$cm_title = "문의 관리";
include_once CM_ADMIN_PATH.'/admin.head.php'; 

$options = [
    'table' => 'cm_contact',
    'page' => $_GET['page'] ?? 1,
    'per_page' => 20,
    'order_by' => 'created_at DESC',
    'conditions' => []
];

// 정렬 처리
$sort_field = $_GET['sort'] ?? 'id';
$sort_order = $_GET['order'] ?? 'DESC';

// 정렬 가능한 필드 목록
$sortable_fields = ['name', 'created_at', 'read_chk', 'read_chk_date'];

// 정렬 필드가 유효한지 확인
if (in_array($sort_field, $sortable_fields)) {
    $options['order_by'] = $sort_field . ' ' . $sort_order;
}

// 검색 조건이 있는 경우에만 conditions에 추가
if (!empty($_GET['search_type']) && !empty($_GET['search_keyword'])) {
	$search_type = $_GET['search_type'];
    $search_keyword = $_GET['search_keyword'];
	// 검색 조건이 있는 경우에만 conditions에 추가
	
	switch($search_type) {
        case 'name':
            $options['conditions'][] = ['field' => 'name', 'operator' => 'LIKE', 'value' => "%{$search_keyword}%"];
            break;
        case 'phone':
            $options['conditions'][] = ['field' => 'phone', 'operator' => 'LIKE', 'value' => "%{$search_keyword}%"];
            break;
        case 'email':
            $options['conditions'][] = ['field' => 'email', 'operator' => 'LIKE', 'value' => "%{$search_keyword}%"];
            break;
		case 'subject':
            $options['conditions'][] = ['field' => 'subject', 'operator' => 'LIKE', 'value' => "%{$search_keyword}%"];
            break;
		case 'message':
            $options['conditions'][] = ['field' => 'message', 'operator' => 'LIKE', 'value' => "%{$search_keyword}%"];
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
                                <i class="bi bi-chat-dots me-2"></i><?php echo $cm_title;?>
                            </h2>
                            <p class="card-text text-muted mb-0">문의내역 입니다.</p>
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
								<option value="name" <?php echo (isset($_GET['search_type']) && $_GET['search_type'] === 'name') ? 'selected' : ''; ?>>이름</option>
								<option value="phone" <?php echo (isset($_GET['search_type']) && $_GET['search_type'] === 'phone') ? 'selected' : ''; ?>>연락처</option>
								<option value="email" <?php echo (isset($_GET['search_type']) && $_GET['search_type'] === 'email') ? 'selected' : ''; ?>>이메일</option>
								<option value="subject" <?php echo (isset($_GET['search_type']) && $_GET['search_type'] === 'subject') ? 'selected' : ''; ?>>제목</option>
								<option value="message" <?php echo (isset($_GET['search_type']) && $_GET['search_type'] === 'message') ? 'selected' : ''; ?>>내용</option>
							</select>
						</div>
						<div class="col-md-6">
							<label for="search_keyword" class="form-label">검색어 <span class="text-danger">*</span></label>
							<input type="text" class="form-control" id="search_keyword" name="search_keyword" value="<?php echo isset($_GET['search_keyword']) ? htmlspecialchars($_GET['search_keyword']) : ''; ?>" required>
						</div>
						<div class="col-md-3 d-flex align-items-end">
							<button type="submit" class="btn btn-primary me-2">검색</button>
							<a href="contact_list.php" class="btn btn-secondary">초기화</a>
						</div>
					</form>
				</div>
			</div>

        <div class="table-responsive">
            <table class="table table-sm table-striped table-bordered align-middle" style="min-width:1200px;">
                <thead class="table-dark text-center">
                    <tr>
                        <th scope="col">No</th>
                        <th scope="col">이름</th>
                        <th scope="col">연락처</th>
                        <th scope="col">이메일</th>
                        <th scope="col">제목</th>
						<th scope="col"  class="sortable" data-field="created_at">
							작성일
							<?php echo get_sort_icon($sort_field, $sort_order, 'created_at'); ?>
						</th>
						<th scope="col" class="sortable" data-field="read_chk_date">
							읽음확인일
							<?php echo get_sort_icon($sort_field, $sort_order, 'read_chk_date'); ?>
						</th>
						<th scope="col">확인</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($result['list'])){ ?>
                        <tr>
                            <td colspan="8" class="text-center">등록된 문의내역이 없습니다.</td>
                        </tr>
                    <?php } else { ?>
                        <?php 
                        $start_number = $result['total_rows'] - ($page - 1) * $options['per_page'];
                        foreach ($result['list'] as $index => $list) {
                            $list_no = $start_number - $index;
                        ?>
                        <tr class="text-center">
                            <td rowspan="2"><?php echo $list_no;?></td>
                            <td><?php echo $list['name']; ?></td>
                            <td><?php echo $list['email'];?></td>
                            <td><?php echo $list['phone'];?></td>
                            <td><?php echo $list['subject'];?></td>
							<td><?php echo $list['created_at'];?></td>
							<td><?php echo $list['read_chk_date'];?></td>
							<td rowspan="2">
								<?php if(isset($list['read_chk']) && $list['read_chk'] == 1){?>
								<button type="button" class="btn btn-sm btn-success">읽음</button>
								<?php } else { ?>
								<button type="button" class="btn btn-sm btn-danger" onclick="readChk('<?php echo $list['id']; ?>')">확인</button>
								<?php } ?>
							</td>
                        </tr>
						<tr class="text-start">
							<td colspan="8"><?php echo $list['message'];?></td>
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


<?php
include_once CM_ADMIN_PATH.'/admin.tail.php';
?>