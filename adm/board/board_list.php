<?php
include_once './_common.php';
$cm_title = "게시판 관리";
include_once CM_ADMIN_PATH.'/admin.head.php';

$options = [
    'table' => 'cm_board_list',
    'page' => $_GET['page'] ?? 1,
    'per_page' => 20,
    'order_by' => 'created_at DESC',
    'conditions' => []
];

// 정렬 처리
$sort_field = $_GET['sort'] ?? 'created_at';
$sort_order = $_GET['order'] ?? 'DESC';

// 정렬 가능한 필드 목록
$sortable_fields = ['board_id', 'board_name', 'board_skin'];

// 정렬 필드가 유효한지 확인
if (in_array($sort_field, $sortable_fields)) {
    $options['order_by'] = $sort_field . ' ' . $sort_order;
}

// 검색 조건이 있는 경우에만 conditions에 추가
if (!empty($_GET['board_id'])) {
    $options['conditions'][] = ['field' => 'board_id', 'operator' => 'LIKE', 'value' => $_GET['board_id']];
}
if (!empty($_GET['board_name'])) {
    $options['conditions'][] = ['field' => 'board_name', 'operator' => 'LIKE', 'value' => $_GET['board_name']];
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
                            <p class="card-text text-muted mb-0">게시판 목록 입니다.</p>
                        </div>
                        <div>
                            <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#createBoardModal" onclick="resetModal()">
								새 게시판 만들기
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
                        <th scope="col" class="sortable" data-field="board_id">
                            게시판 ID 
                            <?php echo get_sort_icon($sort_field, $sort_order, 'board_id'); ?>
                        </th>
                        <th scope="col" class="sortable" data-field="board_name">
                            게시판 이름
                            <?php echo get_sort_icon($sort_field, $sort_order, 'board_name'); ?>
                        </th>
                        <th scope="col" class="sortable" data-field="board_skin">
                            스킨
                            <?php echo get_sort_icon($sort_field, $sort_order, 'board_skin'); ?>
                        </th>
                        <th scope="col">관리</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($result['list'])){ ?>
                        <tr>
                            <td colspan="5" class="text-center">등록된 게시판이 없습니다.</td>
                        </tr>
                    <?php } else { ?>
                        <?php 
                        $start_number = $result['total_rows'] - ($page - 1) * $options['per_page'];
                        foreach ($result['list'] as $index => $list) {
                            $list_no = $start_number - $index;
                        ?>
                        <tr class="text-center">
                            <td><?php echo $list_no;?></td>
                            <td>
                                <a href="<?php echo get_board_url('list', $list['board_id']);?>">
                                    <?php echo $list['board_id']; ?>
                                </a>
                            </td>
                            <td><?php echo $list['board_name'];?></td>
                            <td><?php echo $list['board_skin'];?></td>
                            <td>
                                <button type="button" class="btn btn-sm btn-primary me-2" onclick="editBoard('<?php echo $list['board_id']; ?>')">수정</button>
                                <button type="button" class="btn btn-sm btn-danger" onclick="deleteBoard('<?php echo $list['board_id']; ?>', '<?php echo htmlspecialchars($list['board_name']); ?>')">삭제</button>
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

        <!-- 게시판 생성/수정 모달 -->
        <div class="modal fade" id="createBoardModal" tabindex="-1" aria-labelledby="createBoardModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="createBoardModalLabel">게시판 관리</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <form action="./board_form_update.php" method="POST" id="boardForm">
                        <input type="hidden" name="action" id="formAction" value="insert">
                        <div class="modal-body">
							<div class="row">
								<div class="col-12 col-md-6">
									<div class="mb-3">
										<label for="groupId" class="form-label">게시판그룹 선택</label>
										<select class="form-select" id="groupId" name="group_id" required>
											<?php
											$grList = sql_all_list("SELECT * FROM `cm_board_group` ORDER BY `group_name` ASC");
											if ($grList !== false && !empty($grList)) {
												foreach ($grList as $row) {
											?>
											<option value="<?php echo $row['group_id'];?>"><?php echo $row['group_name'];?></option>
											<?php } ?>
											<?php } ?>
										</select>
									</div>
								</div>
								<div class="col-12 col-md-6">
									<div class="mb-3">
										<label for="boardId" class="form-label">게시판 아이디</label>
										<input type="text" class="form-control" id="boardId" name="board_id" required pattern="^[a-zA-Z0-9!@#$%^&*()_+=\-\[\]{};':\\|,.<>\/?~]*$">
									</div>
								</div>
								<div class="col-12 col-md-6">
									<div class="mb-3">
										<label for="boardName" class="form-label">게시판 이름</label>
										<input type="text" class="form-control" id="boardName" name="board_name" required>
									</div>
								</div>
								<div class="col-12 col-md-6">
									<div class="mb-3">
										<label for="boardSkin" class="form-label">게시판스킨 선택</label>
										<select class="form-select" id="boardSkin" name="board_skin" required>
											<?php
											$folderDirectory = CM_TEMPLATE_PATH.'/skin/board_skin';
											$folders = getSubdirectories($folderDirectory);
											foreach ($folders as $folder) {
											?>
											<option value="<?php echo $folder;?>"><?php echo $folder;?></option>
											<?php } ?>
										</select>
									</div>
								</div>
							</div>
							<div class="row">
								<div class="col-12 mb-3">
									<label for="board_category" class="form-label">카테고리 (엔터로 구분합니다)</label>
									<textarea name="board_category" id="board_category" class="form-control"  rows="5"><?php echo (isset($row['board_category']) && $row['board_category']) ? $row['board_category'] : ''; ?></textarea>
								</div>
							</div>
							<div class="row">
								<div class="col-12">
									<p>게시판 레벨설정</p>
								</div>
								<div class="col-4">
									<div class="mb-3">
										<label for="write_lv" class="form-label">목록</label>
										<select class="form-select" id="list_lv" name="list_lv" required>
											<?php
											for ($i=1 ; $i<=10; $i++){
											?>
											<option value="<?php echo $i;?>" <?php if(isset($row['list_lv']) && $row['list_lv'] == $i) echo 'selected';?>><?php echo $i;?></option>
											<?php } ?>
										</select>
									</div>
								</div>
								<div class="col-4">
									<div class="mb-3">
										<label for="write_lv" class="form-label">글보기</label>
										<select class="form-select" id="view_lv" name="view_lv" required>
											<?php
											for ($i=1 ; $i<=10; $i++){
											?>
											<option value="<?php echo $i;?>" <?php if(isset($row['view_lv']) && $row['view_lv'] == $i) echo 'selected';?>><?php echo $i;?></option>
											<?php } ?>
										</select>
									</div>
								</div>
								<div class="col-4">
									<div class="mb-3">
										<label for="write_lv" class="form-label">글쓰기</label>
										<select class="form-select" id="write_lv" name="write_lv" required>
											<?php
											for ($i=1 ; $i<=10; $i++){
											?>
											<option value="<?php echo $i;?>" <?php if(isset($row['write_lv']) && $row['write_lv'] == $i) echo 'selected';?>><?php echo $i;?></option>
											<?php } ?>
										</select>
									</div>
								</div>
								
								
							</div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">닫기</button>
                            <button type="submit" class="btn btn-primary" id="submitButton">저장</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>


<?php
include_once CM_ADMIN_PATH.'/admin.tail.php';
?>