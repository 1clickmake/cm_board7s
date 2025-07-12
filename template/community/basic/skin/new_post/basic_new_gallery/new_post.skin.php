<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가
/**
 ** 기본 갤러리 최신글 스킨 
 **/
 
//제목글자수 자르기
$title_stripped = strip_tags(htmlspecialchars($list['title'])); // 태그 제거.
$title =  mb_substr($title_stripped, 0, 30); // 0번째부터 30글자까지 출력.

//내용글자수 자르기
$content_stripped = strip_tags($list['content']); // 태그 제거.
$content =  mb_substr($content_stripped, 0, 60); // 0번째부터 60글자까지 출력.
?>
<div class="col-12 col-md-6">
    <div class="card shadow-sm h-100">
        <div class="card-body p-md-3">
			<a href="<?php echo get_board_url('view', $list['board_id'], $list['board_num']);?>">
            <?php if (!empty($images) && is_array($images)): ?>
                <div class="new-post-image-container">
                    <img alt="<?php echo htmlspecialchars($list['title']); ?>" 
                         class="new-post-image" 
                         src="<?php echo $images[0]['file']; ?>">
                </div>
            <?php else: ?>
                <div class="new-post-image-container">
                    <div class="new-post-placeholder">
                        <i class="bi bi-image"></i>
                    </div>
                </div>
            <?php endif; ?>
			</a> 
        </div>
    </div>
</div>