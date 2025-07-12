<?php
include_once('./_common.php');

$cm_title = '로그인';
include_once(CM_PATH.'/head_sub.php');

//css 경로
echo '<link rel="stylesheet" href="'.CM_TEMPLATE_URL.'/skin/member_skin/style.css?ver='.time().'">';
//로그인 스킨
$action = CM_MB_URL."/login_check.php";
include_once(CM_TEMPLATE_PATH.'/skin/member_skin/login.skin.php');
//js 경로
echo '<script>
const recaptcha_site	= ' . json_encode($recaptcha_site) . ';
const recaptcha_secret	= ' . json_encode($recaptcha_secret) . ';
</script>';
echo '<script src="'.CM_URL.'/js/login.js?ver='.time().'"></script>';
include_once(CM_PATH.'/tail_sub.php');