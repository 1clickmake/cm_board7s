<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가
?>
	
		<div class="comments-section rounded bg-white mb-2 px-3 py-1 shadow-sm">
            <div class="comments-header mb-2">
				댓글 <span style="color: #2563eb;"><?php echo $comment_count; ?></span>개
			</div>
			
			<!-- 코멘트 입력 폼 { -->
            <div id="cmtId" class="comment-form">
                <form id="commentForm" action="comment_update.php" method="post">
                    <input type="hidden" name="board_id" value="<?php echo $boardId;?>">
                    <input type="hidden" name="board_num" value="<?php echo $boardNum;?>">
                    <input type="hidden" name="action" value="write">
                    <input type="hidden" name="comment_id" value="">
                    <?php if ($is_member): ?>
                        <input type="hidden" name="user_id" value="<?php echo $member['user_id'];?>">
                        <input type="hidden" name="name" value="<?php echo htmlspecialchars($member['user_name']);?>">
                        <input type="hidden" name="email" value="<?php echo htmlspecialchars($member['user_email']);?>">
                        <input type="hidden" name="password" value="<?php echo $member['user_password'];?>">
                    <?php else: ?>
                        <div class="row mb-3">
                            <div class="col-md-4">
                                <input type="text" class="form-control" name="name" placeholder="이름" required>
                            </div>
                            <div class="col-md-4">
                                <input type="email" class="form-control" name="email" placeholder="이메일" required>
                            </div>
                            <div class="col-md-4">
                                <input type="password" class="form-control" name="password" placeholder="비밀번호" required>
                            </div>
                        </div>
                    <?php endif; ?>
                    <div class="mb-3">
                        <textarea id="commentContent" name="content" class="form-control" rows="3" required></textarea>
						
						<div class="comment-actions">
							<div class="comment-info text-center text-warning py-2">
								<i class="bi bi-exclamation-triangle"></i> 욕설, 비방, 광고 등의 댓글은 삭제될 수 있습니다.
							</div>
							<div class="text-center">
								<button type="submit" class="btn btn-primary">댓글 작성</button>
							</div>
						</div>
                    </div>
                </form>
            </div>
			<!-- } 코멘트 입력 폼 끝 -->
			
			
			<!-- 코멘트 목록 { -->
			<div class="comments-list  ">
				
					<!-- 코멘트 출력 { -->
					<?php if (!empty($comments)): ?>
						<?php foreach ($comments as $comment): ?>
						<div class="comment-item rounded border mb-2 p-2" id="cmtId<?= $comment['comment_id'] ?>">

							<div class="comment-header">
								<span class="comment-author"><?= htmlspecialchars($comment['name']) ?></span>
								<span class="comment-date"><?= date('Y-m-d H:i', strtotime($comment['reg_date'])) ?></span>
							</div>
							<div class="comment-content" id="comment-content-<?= $comment['comment_id'] ?>">
								<?= $comment['content'] ?>
							</div>
								<?php if ($is_member && ($member['user_id'] == $comment['user_id'] || $is_admin)): ?>
								<div class="comment-actions-small text-end">
									<button type="button" class="comment-action edit-comment" 
											data-comment-id="<?= $comment['comment_id'] ?>">수정</button>
									<button type="button" class="comment-action delete-comment" 
											data-comment-id="<?= $comment['comment_id'] ?>">삭제</button>
								</div>
								<?php endif; ?>
							
						</div>
						<?php endforeach; ?>
						<!-- } 코멘트 출력 끝 -->

						<!-- 페이지네이션 { -->
						<?php if ($total_pages > 1): ?>
						<nav aria-label="댓글 페이지네이션" class="mt-4">
							<ul class="pagination justify-content-center">
								<?php if ($comment_page > 1): ?>
								<li class="page-item">
									<a class="page-link" href="?board=<?php echo $boardId; ?>&id=<?php echo $boardNum; ?>&comment_page=<?php echo ($comment_page - 1); ?>" aria-label="이전">
										<span aria-hidden="true">&laquo;</span>
									</a>
								</li>
								<?php endif; ?>

								<?php for ($i = $start_page; $i <= $end_page; $i++): ?>
								<li class="page-item <?php echo ($i == $comment_page) ? 'active' : ''; ?>">
									<a class="page-link" href="?board=<?php echo $boardId; ?>&id=<?php echo $boardNum; ?>&comment_page=<?php echo $i; ?>"><?php echo $i; ?></a>
								</li>
								<?php endfor; ?>

								<?php if ($comment_page < $total_pages): ?>
								<li class="page-item">
									<a class="page-link" href="?board=<?php echo $boardId; ?>&id=<?php echo $boardNum; ?>&comment_page=<?php echo ($comment_page + 1); ?>" aria-label="다음">
										<span aria-hidden="true">&raquo;</span>
									</a>
								</li>
								<?php endif; ?>
							</ul>
						</nav>
						<?php endif; ?>
					<?php else: ?>
						<div class="border rounded mt-5 mb-3 py-3 text-center text-muted">등록된 댓글이 없습니다.</div>
					<?php endif; ?>
					<!-- } 페이지네이션 끝-->
			</div>
			<!-- } 코멘트 목록 끝-->
		</div>

