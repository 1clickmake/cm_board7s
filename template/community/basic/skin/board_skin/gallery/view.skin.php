<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가 
?>

<div class="container py-4">
    <!-- Breadcrumb -->
    <nav aria-label="breadcrumb" class="mb-4">
        <ol class="breadcrumb justify-content-end">
            <li class="breadcrumb-item">
                <a href="<?php echo CM_URL?>" class="text-secondary">홈</a>
            </li>
            <li class="breadcrumb-item">
                <a href="<?php echo get_board_url('list', $boardId);?>" class="text-primary"><?php echo htmlspecialchars($bo['board_name'] ?? ''); ?></a>
            </li>
            <li class="breadcrumb-item active" aria-current="page">
                <?php echo htmlspecialchars($bo_title ?? ''); ?>
            </li>
        </ol>
    </nav>

    <!-- 게시글 헤더 -->
    <div class="mb-4">
        <?php if(isset($view['notice_chk']) && $view['notice_chk'] == 1): ?>
            <span class="badge bg-danger mb-2">공지</span>
        <?php endif; ?>
        
        <h1 class="h3 mb-3">
            <?php echo htmlspecialchars($view['title'] ?? ''); ?>
        </h1>
        
        <div class="d-flex flex-wrap gap-3 text-muted small mb-4 pb-3 border-bottom">
            <span><i class="bi bi-person me-1"></i> <?php echo htmlspecialchars($view['name'] ?? '알 수 없음'); ?></span>
            <span><i class="bi bi-calendar me-1"></i> <?php echo date('Y-m-d H:i', strtotime($view['reg_date'] ?? 'now')); ?></span>
            <span><i class="bi bi-eye me-1"></i> <?php echo number_format($view['view_count'] ?? 0); ?></span>
            <span><i class="bi bi-chat-dots me-1"></i> <?php echo number_format($comment_count ?? 0); ?></span>
        </div>

        <?php if (!empty($view['tags'])): ?>
            <div class="mb-2">
                <div>
                    <?php foreach (explode(',', $view['tags']) as $tag): ?>
                        <?php $tag = trim($tag); if ($tag): ?>
                            <span class="tag-badge"><?= htmlspecialchars($tag) ?></span>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <!-- 게시글 내용 -->
    <div class="mb-5">
        <div class="post-content mb-4">
            <?php if($file_image_view !== false): ?>
                <div class="mb-4 text-center">
                    <?php echo get_board_file_image_view($boardId, $boardNum); ?>
                </div>
            <?php endif; ?>
            <?php echo $view['content'] ?? ''; ?>
        </div>

        <!-- 첨부파일 -->
        <?php if (!empty($files)): ?>
            <div class="mb-4 py-3 border-top">
                <h6 class="mb-3 text-muted"><i class="bi bi-paperclip me-2"></i>첨부파일</h6>
                <div class="d-flex flex-column gap-2">
                    <?php foreach ($files as $file): 
                        $is_image = is_image_file($file['original_filename']);
                        $icon_class = get_file_icon_class($file['original_filename']);
                        $file_size = number_format($file['file_size'] / 1024, 2);
                    ?>
                        <div class="d-flex justify-content-between align-items-center p-2 bg-light rounded">
                            <div class="d-flex align-items-center">
                                <?php if ($is_image): ?>
                                    <img src="download.php?board=<?php echo $boardId;?>&file_id=<?php echo $file['file_id']; ?>" 
                                        class="me-2" style="width: 24px; height: 24px; object-fit: cover;">
                                <?php else: ?>
                                    <i class="fas <?php echo $icon_class; ?> me-2 text-muted" style="font-size: 1.1rem;"></i>
                                <?php endif; ?>
                                <span class="text-truncate" style="max-width: 300px;">
                                    <?php echo htmlspecialchars($file['original_filename']); ?>
                                </span>
                                <small class="text-muted ms-2">(<?php echo $file_size; ?> KB)</small>
                            </div>
                            <a href="download.php?board=<?php echo $boardId;?>&file_id=<?php echo $file['file_id']; ?>" 
                               class="btn btn-sm btn-outline-secondary">
                                <i class="bi bi-download"></i> 다운로드
                            </a>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

        <!-- 추천/비추천 버튼 -->
        <div class="d-flex justify-content-center gap-3 py-3 border-top border-bottom mb-4">
            <button class="btn btn-sm btn-outline-primary btn-like" id="goodBtn">
                <i class="bi bi-hand-thumbs-up"></i> 
                <span>추천</span>
                <span class="badge bg-primary ms-1" id="likeCount"><?php echo (int)($view['good'] ?? 0); ?></span>
            </button>
            <button class="btn btn-sm btn-outline-danger btn-dislike" id="badBtn">
                <i class="bi bi-hand-thumbs-down"></i> 
                <span>비추천</span>
                <span class="badge bg-danger ms-1" id="dislikeCount"><?php echo (int)($view['bad'] ?? 0); ?></span>
            </button>
        </div>
    </div>

    <!-- 버튼 그룹 -->
    <div class="d-flex justify-content-between mb-4">
        <div>
            <a href="<?php echo get_board_url('list', $boardId); ?>" class="btn btn-outline-secondary">
                <i class="bi bi-list-ul me-1"></i> 목록
            </a>
        </div>
        <div class="btn-group">
            <?php if($is_admin || ($is_member && $member['user_id'] == $view['user_id'])): ?>
                <a href="<?php echo CM_BOARD_URL?>/edit.php?board=<?php echo $boardId; ?>&id=<?php echo $boardNum; ?>" class="btn btn-outline-primary">
                    <i class="bi bi-pencil-square me-1"></i> 수정
                </a>
            <?php else: ?>
                <button type="button" class="btn btn-outline-primary"  value="edit" onclick="boardToPass(this, '<?php echo $boardId; ?>','<?php echo $boardNum; ?>');" >
                    <i class="bi bi-pencil-square me-1"></i> 수정
                </button>
            <?php endif; ?>

            <?php if($is_admin): ?>
                <button type="button" class="btn btn-outline-danger" onclick="confirmDelete('<?php echo $boardId; ?>', <?php echo $boardNum; ?>)">
                    <i class="bi bi-trash me-1"></i> 삭제
                </button>
            <?php else: ?>
                <button type="button" class="btn btn-outline-danger" value="delete" onclick="boardToPass(this, '<?php echo $boardId; ?>','<?php echo $boardNum; ?>');">
                    <i class="bi bi-trash me-1"></i> 삭제
                </button>
            <?php endif; ?>

            <a href="<?php echo get_board_url('write', $boardId); ?>" class="btn btn-primary">
                <i class="bi bi-pencil me-1"></i> 글쓰기
            </a>

            <?php if(isset($view['notice_chk']) && $view['notice_chk'] == 0 && $view['reply_chk'] == 1): ?>
                <a href="<?php echo get_board_url('write', $boardId, $boardNum) . '&parent=' . $boardNum; ?>" class="btn btn-info text-white">
                    <i class="bi bi-reply me-1"></i> 답변
                </a>
            <?php endif; ?>
        </div>
    </div>

    <!-- 댓글 영역 -->
    <?php 
	if(isset($view['comment_chk']) && $view['comment_chk'] == 1){
        include_once('comment.skin.php');
	} ?>
</div>
