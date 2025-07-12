<?php
include_once('./_common.php');

$cm_title = '포인트';
include_once(CM_PATH.'/head.php');

//css 경로
echo '<link rel="stylesheet" href="'.CM_TEMPLATE_URL.'/skin/member_skin/style.css?ver='.time().'">';
//로그인 스킨
$action = CM_MB_URL."/register_form_update.php";
include_once(CM_TEMPLATE_PATH.'/skin/member_skin/point.skin.php');

include_once(CM_PATH.'/tail.php');