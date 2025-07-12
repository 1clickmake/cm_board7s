<?php
include_once './_common.php';
$cm_title = "게시판 그룹관리";
include_once CM_ADMIN_PATH.'/admin.head.php';

$options = [
    'table' => 'cm_board_group',
    'page' => $_GET['page'] ?? 1,
    'per_page' => 20,
    'order_by' => 'group_name ASC',
    'conditions' => []
];

// 정렬 처리
$sort_field = $_GET['sort'] ?? 'group_name';
$sort_order = $_GET['order'] ?? 'ASC';

// 정렬 가능한 필드 목록
$sortable_fields = ['group_id', 'group_name'];

// 정렬 필드가 유효한지 확인
if (in_array($sort_field, $sortable_fields)) {
    $options['order_by'] = $sort_field . ' ' . $sort_order;
}

// 검색 조건이 있는 경우에만 conditions에 추가
if (!empty($_GET['group'])) {
    $options['conditions'][] = ['field' => 'group_id', 'operator' => 'LIKE', 'value' => $_GET['group']];
}
if (!empty($_GET['group_name'])) {
    $options['conditions'][] = ['field' => 'group_name', 'operator' => 'LIKE', 'value' => $_GET['group_name']];
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
                                <i class="fas fa-window-restore me-2"></i><?php echo $cm_title;?>
                            </h2>
                            <p class="card-text text-muted mb-0">게시판 그룹 목록 입니다.</p>
                        </div>
                        <div>
                            <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#createBoardModal">
								새 게시판그룹 만들기
							</button>
                        </div>
                    </div>
                </div>
            </div>

			<div class="table-responsive">
				<table class="table table-sm table-striped table-bordered align-middle" style="min-width:1200px;">
					<thead class="table-dark text-center">
						<tr>
							<th scope="col">No</th>
							<th scope="col" class="sortable" data-field="group_id">
								그룹 ID
								<?php echo get_sort_icon($sort_field, $sort_order, 'group_id'); ?>
							</th>
							<th scope="col" class="sortable" data-field="group_name">
								그룹 이름
								<?php echo get_sort_icon($sort_field, $sort_order, 'group_name'); ?>
							</th>
							<th scope="col">게시판 수</th>
							<th scope="col">관리</th>
						</tr>
					</thead>
					<tbody>
						<?php if (empty($result['list'])){ ?>
							<tr>
								<td colspan="5" class="text-center">등록된 그룹이 없습니다.</td>
							</tr>
						<?php } else { ?>
							<?php 
							$start_number = $result['total_rows'] - ($page - 1) * $options['per_page'];
							foreach ($result['list'] as $index => $list) {
								$list_no = $start_number - $index;
								// 해당 그룹의 게시판 수 조회
								$boardCount = sql_fetch("SELECT COUNT(*) as cnt FROM cm_board_list WHERE group_id = :group_id", [':group_id' => $list['group_id']]);
							?>
							<tr class="text-center">
								<td><?php echo $list_no;?></td>
								<td><?php echo $list['group_id'];?></td>
								<td><?php echo $list['group_name'];?></td>
								<td><?php echo $boardCount['cnt'];?></td>
								<td>
									<button type="button" class="btn btn-sm btn-primary me-2" onclick="editGroup('<?php echo $list['group_id']; ?>', '<?php echo htmlspecialchars($list['group_name']); ?>')">수정</button>
									<button type="button" class="btn btn-sm btn-danger" onclick="deleteGroup('<?php echo $list['group_id']; ?>', '<?php echo htmlspecialchars($list['group_name']); ?>')">삭제</button>
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

			<!-- 그룹생성/수정 모달 -->
			<div class="modal fade" id="createBoardModal" tabindex="-1" aria-labelledby="createBoardModalLabel" aria-hidden="true">
				<div class="modal-dialog">
					<div class="modal-content">
						<div class="modal-header">
							<h5 class="modal-title" id="createBoardModalLabel">새 그룹 만들기</h5>
							<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
						</div>
						<form action="./board_group_form_update.php" method="POST" id="groupForm">
							<input type="hidden" name="action" id="formMode" value="insert">
							<div class="modal-body">
								<div class="mb-3">
									<label for="groupId" class="form-label">그룹 아이디</label>
									<input type="text" class="form-control" id="groupId" name="group_id" required pattern="^[a-zA-Z0-9!@#$%^&*()_+=\-\[\]{};':\\|,.<>\/?~]*$">
									<small class="form-text text-muted">영문, 숫자, 일부 기호(-,_)만 사용할 수 있습니다.</small>
								</div>
								<div class="mb-3">
									<label for="groupName" class="form-label">그룹 이름</label>
									<input type="text" class="form-control" id="groupName" name="group_name" required>
								</div>
							</div>
							<div class="modal-footer">
								<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">닫기</button>
								<button type="submit" class="btn btn-primary" id="submitButton">그룹 생성</button>
							</div>
						</form>
					</div>
				</div>
			</div>

			<!-- 삭제 확인 모달 -->
			<div class="modal fade" id="deleteModal" tabindex="-1" aria-labelledby="deleteModalLabel" aria-hidden="true">
				<div class="modal-dialog">
					<div class="modal-content">
						<div class="modal-header">
							<h5 class="modal-title" id="deleteModalLabel">그룹 삭제 확인</h5>
							<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
						</div>
						<div class="modal-body">
							<p id="deleteModalMessage"></p>
						</div>
						<div class="modal-footer">
							<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">취소</button>
							<form id="deleteForm" method="post" action="board_group_form_update.php">
								<input type="hidden" name="group_id" id="deleteGroupId" value="">
								<input type="hidden" name="action" value="delete">
								<button type="submit" class="btn btn-danger">삭제</button>
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