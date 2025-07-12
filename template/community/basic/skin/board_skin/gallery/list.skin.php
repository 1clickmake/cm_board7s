<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가
?>

<script src="<?php echo CM_URL?>/js/board.list.js?ver=<?php echo time();?>"></script>
 <!-- Main Content -->
<main class="container my-5">
        <!-- Page Header -->
		<div class="rounded bg-white  px-3 py-1 my-3 shadow-sm">
			<div class="page-header">
				<h1 class="page-title"><i class="bi bi-images"></i> <?php echo $cm_title;?></h1>
			</div>
			<!-- Board Controls -->
			<div class="board-controls">
				<div class="board-info">
					총 <strong><?php echo number_format($total_rows);?></strong>개의 게시글이 있습니다.
				</div>
				<div class="board-actions">
					<form method="get" class="search-form" onsubmit="return validateSearch()">
						<input type="hidden" name="board" value="<?php echo $boardId;?>">
						<select name="search_field" class="search-select">
							<option value="title" <?php echo ($_GET['search_field'] ?? '') === 'title' ? 'selected' : '';?>>제목</option>
							<option value="content" <?php echo ($_GET['search_field'] ?? '') === 'content' ? 'selected' : '';?>>내용</option>
							<option value="name" <?php echo ($_GET['search_field'] ?? '') === 'name' ? 'selected' : '';?>>작성자</option>
							<option value="title_content" <?php echo ($_GET['search_field'] ?? '') === 'title_content' ? 'selected' : '';?>>제목+내용</option>
							<option value="tags" <?php echo ($_GET['search_field'] ?? '') === 'tags' ? 'selected' : '';?>>태그</option>
						</select>
						<input type="text" name="search_keyword" class="search-input-small" value="<?php echo htmlspecialchars($_GET['search_keyword'] ?? '');?>" placeholder="검색어를 입력하세요">
						<button type="submit" class="btn btn-dark btn-outline">검색</button>
						<?php if ($has_search): ?>
							<a href="?board=<?php echo $boardId;?>" class="btn btn-secondary">전체</a>
						<?php endif; ?>
					</form>
				</div>
			</div>
		</div>

        <!-- Board Table -->
        <form id="boardListForm" action="<?php echo CM_BOARD_URL; ?>/list_delete.php" method="post" onsubmit="return confirmDeleteSelected();">
        <input type="hidden" name="board_id" value="<?php echo htmlspecialchars($boardId); ?>">
        <input type="hidden" name="current_page" value="<?php echo htmlspecialchars($page); // 삭제 후 현재 페이지로 돌아오기 위해 ?>">

        <div class="row">
                    <?php if (empty($rows) && empty($notice_posts)): ?>
                    <div class="col-12">
						<div class="py-5 text-center">등록된 게시글이 없습니다.</div>
					</div>
                    <?php else: ?>

                        <?php 
						foreach ($rows as $index => $list) {
							$images = get_image_post('cm_board', 'board_num', $list['board_num'], $list['content'], $boardId);
						?>
                        <div class="col-6 col-md-3 mb-3">
							<div class="card w-100 h-100">
								<a href="<?php echo get_board_url('view', $boardId, $list['board_num']);?>">
								<img src="<?php echo $images;?>" class="card-img-top w-100" alt="<?php echo htmlspecialchars($list['title']); ?>">
								</a>
								<div class="card-body">
									<p class="card-text">
										<?php if($is_admin){?><span><input type="checkbox" name="selected_posts[]" value="<?php echo $list['board_num']; ?>"></span><?php } ?>
										<a href="<?php echo get_board_url('view', $boardId, $list['board_num']);?>" class="text-decoration-none">
											<?php echo htmlspecialchars($list['title']); ?>
										</a>
									</p>
								</div>
								<div class="card-footer bg-white">
									<div class="text-end"><?php echo htmlspecialchars($list['name']) ?> <?php echo date('Y-m-d', strtotime($list['reg_date'])) ?></div>
								</div>
							</div>
                        </div>
                        <?php } //endforeach ?>
                    <?php endif; ?>
            </table>
        </div>
        
        <!-- 글쓰기 버튼 -->
        <div class="d-flex justify-content-end mt-3">
            <?php if($is_admin){?><button type="submit" class="btn btn-danger me-2">선택 삭제</button><?php } ?>
            <a href="<?php echo get_board_url('write',$boardId);?>" class="btn btn-primary">글쓰기</a>
        </div>
        </form>
		
        <!-- 페이지네이션 -->
        <?php echo render_pagination($page, $total_pages, $_GET);?>
        <!-- 페이지네이션 끝-->
    
</main>

    