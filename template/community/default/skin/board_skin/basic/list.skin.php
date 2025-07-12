<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가 
?>
    <div class="container my-5">
        <!-- Page Header -->
		<div class="rounded bg-white px-3 py-3 my-3 shadow-sm">
    <div class="row align-items-center mb-3 mb-md-0">
        <!-- 페이지 제목 -->
        <div class="col-12">
            <h1 class="page-title h4 mb-3">
                <i class="fa fa-list"></i> <?php echo $cm_title;?>
            </h1>
        </div>
        
        <!-- 총 게시글 수 -->
        <div class="col-12 col-md-6 mb-3 mb-md-0">
            <div class="text-muted">
                총 <strong><?php echo number_format($total_rows);?></strong>개의 게시글
            </div>
        </div>
        
        <!-- 검색 폼 -->
        <div class="col-12 col-md-6">
            <form method="get" class="row g-2" onsubmit="return validateSearch()">
                <input type="hidden" name="board" value="<?php echo $boardId;?>">
                
                <div class="col-12 col-sm-4">
                    <select name="search_field" class="form-select form-select-sm">
                        <option value="title" <?php echo ($_GET['search_field'] ?? '') === 'title' ? 'selected' : '';?>>제목</option>
                        <option value="content" <?php echo ($_GET['search_field'] ?? '') === 'content' ? 'selected' : '';?>>내용</option>
                        <option value="name" <?php echo ($_GET['search_field'] ?? '') === 'name' ? 'selected' : '';?>>작성자</option>
                        <option value="title_content" <?php echo ($_GET['search_field'] ?? '') === 'title_content' ? 'selected' : '';?>>제목+내용</option>
                    </select>
                </div>
                
                <div class="col-12 col-sm-5">
                    <input type="text" name="search_keyword" class="form-control form-control-sm" 
                           value="<?php echo htmlspecialchars($_GET['search_keyword'] ?? '');?>" 
                           placeholder="검색어를 입력하세요">
                </div>
                
                <div class="col-12 col-sm-3 d-flex gap-2">
                    <button type="submit" class="btn btn-dark btn-sm flex-grow-1">검색</button>
                    <?php if ($has_search): ?>
                        <a href="?board=<?php echo $boardId;?>" class="btn btn-outline-secondary btn-sm">
                            <i class="fa fa-rotate-left"></i>
                            <span class="d-none d-sm-inline">전체</span>
                        </a>
                    <?php endif; ?>
                </div>
            </form>
        </div>
    </div>
		</div>

        <!-- Board Table -->
        <form id="boardListForm" action="<?php echo CM_BOARD_URL; ?>/list_delete.php" method="post" onsubmit="return confirmDeleteSelected();">
        <input type="hidden" name="board_id" value="<?php echo htmlspecialchars($boardId); ?>">
        <input type="hidden" name="current_page" value="<?php echo htmlspecialchars($page); // 삭제 후 현재 페이지로 돌아오기 위해 ?>">

        <div class="board-table">
            <table class="table">
                <thead class="text-center">
                    <tr class="text-center">
                        <?php if($is_admin){?><th width="50" class="text-center"><input type="checkbox" id="selectAllPosts" onclick="toggleAllCheckBoxes(this);" title="전체 선택/해제"></th><?php } ?>
                        <th width="80" class="text-center">번호</th>
                        <th class="text-center">제목</th>
                        <th width="120" class="hide-mobile text-center">작성자</th>
                        <th width="120" class="hide-mobile text-center">작성일</th>
                        <th width="80" class="hide-mobile text-center ">조회</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($rows) && empty($notice_posts)): ?>
                    <tr>
                        <td colspan="5" class="text-center">등록된 게시글이 없습니다.</td>
                    </tr>
                    <?php else: ?>
						<!-- 공지 출력 { -->
						<?php
						if ($notice_posts) {
							foreach ($notice_posts as $notice) {
						?>
						<tr class="table-light">
                            <?php if($is_admin){?><td class="text-center"></td><?php } ?> <!-- 공지사항은 선택 불가 -->
                            <td class="text-center"><span class="text-danger fw-bold">공지</span></td>
                            <td>
                                <a href="<?php echo get_board_url('view', $boardId, $notice['board_num']);?>" class="text-decoration-none">
                                    <?php echo  htmlspecialchars($notice['title']); ?>
                                </a>
                            </td>
                            <td class="text-center hide-mobile"><?= htmlspecialchars($notice['name']) ?></td>
                            <td class="text-center hide-mobile"><?= date('Y-m-d', strtotime($notice['reg_date'])) ?></td>
                            <td class="text-center hide-mobile"><?= $notice['view_count'] ?></td>
                        </tr>
						<?php }
						} 
						?>
						<!-- } 공지 출력 끝 -->
						
                        <?php foreach ($rows as $index => $list): 
                            $list_no = ($start_number - $index);
                            // 답변글 여부 확인
                            $is_reply = !empty($list['parent_num']);
                            $reply_depth = $list['reply_depth'] ?? 0;
                            $reply_indent = str_repeat('&nbsp;&nbsp;&nbsp;&nbsp;', $reply_depth);
                            $reply_icon = str_repeat('<i class="fa fa-share"></i>', $reply_depth);
                            
                            // 같은 thread_id의 게시글인지 확인
                            $same_thread = isset($prev_thread_id) && $prev_thread_id == $list['thread_id'];
                            $prev_thread_id = $list['thread_id'];
                        ?>
                        <tr>
                            <?php if($is_admin){?><td class="text-center"><input type="checkbox" name="selected_posts[]" value="<?php echo $list['board_num']; ?>"></td><?php } ?>
                            <td class="text-center"><?php if($list['notice_chk'] == 1){?>공지<?php } else {?><?php echo $list_no;?><?php } ?></td>
                            <td>
                                <?php if ($is_reply): ?>
                                <span class="text-muted"><?php echo $reply_indent; ?><?php echo $reply_icon; ?></span>
                                <?php endif; ?>
								<?php if(isset($list['category']) && $list['category']){?><span class="text-info mw-2">[<?php echo $list['category'];?>]</span><?php } ?>
                                <a href="<?php echo get_board_url('view', $boardId, $list['board_num']);?>" class="text-decoration-none">
                                    <?php echo htmlspecialchars($list['title']); ?>
                                    <?php echo get_post_icons($list, $boardId); ?>
                                </a>
                            </td>
                            <td class="text-center hide-mobile"><?= htmlspecialchars($list['name']) ?></td>
                            <td class="text-center hide-mobile"><?= date('Y-m-d', strtotime($list['reg_date'])) ?></td>
                            <td class="text-center hide-mobile"><?= $list['view_count'] ?></td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        
        <!-- 글쓰기 버튼 -->
        <div class="d-flex justify-content-end mt-3">
            <?php if($is_admin){?><button type="submit" class="btn btn-sm btn-danger me-2">선택 삭제</button><?php } ?>
            <a href="<?php echo get_board_url('write',$boardId);?>" class="btn btn-sm btn-primary">글쓰기</a>
        </div>
        </form>
		
        <!-- 페이지네이션 -->
        <?php echo render_pagination($page, $total_pages, $_GET);?>
        <!-- 페이지네이션 끝-->
    
    </div>