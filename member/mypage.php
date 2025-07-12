<?php
include_once('./_common.php');

if(!$is_member){
	alert('회원만 접근 가능합니다.');
}
$cm_title = '마이페이지';
include_once(CM_PATH.'/head.php');
//css 경로
echo '<link rel="stylesheet" href="'.CM_TEMPLATE_URL.'/skin/member_skin/style.css?ver='.time().'">';

//마이페이지 스킨
include_once(CM_TEMPLATE_PATH.'/skin/member_skin/mypage.skin.php');

//js 경로
echo '<script>
    const user_id = "'.htmlspecialchars($member['user_id']).'";
</script>';
echo '<script src="'.CM_URL.'/js/mypage.js?ver='.time().'"></script>';

include_once(CM_PATH.'/tail.php');