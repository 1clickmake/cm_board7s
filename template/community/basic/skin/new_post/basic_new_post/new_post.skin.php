<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가
/**
 ** 기본 최신글 스킨 
 **/
 
//제목글자수 자르기
$title_stripped = strip_tags(htmlspecialchars($list['title'])); // 태그 제거.
$title =  mb_substr($title_stripped, 0, 30); // 0번째부터 30글자까지 출력.

//내용글자수 자르기
$content_stripped = strip_tags($list['content']); // 태그 제거.
$content =  mb_substr($content_stripped, 0, 60); // 0번째부터 60글자까지 출력.
?>
<div class="col-12 col-sm-6 mb-4">
	<div class="card h-100">
		<div class="card-body">
			<h4 class="card-title">
				<a href="<?php echo get_board_url('view', $list['board_id'], $list['board_num']);?>" class="text-dark">
					<?php if(isset($list['notice_chk']) && $list['notice_chk'] == 1){?>
						<span class="badge text-bg-danger rounded-pill"><?php echo htmlspecialchars('공지'); ?></span>
					<?php }else{ ?>
						<?php if(isset($list['category']) && $list['category']){?>
							<span class="badge text-bg-primary rounded-pill"><?php echo htmlspecialchars($list['category']); ?></span>
						<?php } ?>
					<?php } ?>
					<?php echo $title; ?>
				</a>
			</h4>
			<p class="card-text">
				<a href="<?php echo get_board_url('view', $list['board_id'], $list['board_num']);?>" class="text-dark">
					<?php echo $content; ?>
					<div class="text-end">
						<?php echo $list['name'];?> / <?php echo $list['view_count'];?> / <?php echo get_formatDate($list['reg_date'], 'Y-m-d H:i:s');?>
					</div>
				</a>
			</p>
		</div>
	</div>
</div>

