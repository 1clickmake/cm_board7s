<?php
include_once('./_common.php');

$w = isset($_GET['w']) ? $_GET['w'] : '';

$update = false;
$cm_title = '회원가입';

if ($w == 'update') {
	$update = true;
    $cm_title = '회원정보 수정';
}

include_once(CM_PATH.'/head.php');
//css 경로
echo '<link rel="stylesheet" href="'.CM_TEMPLATE_URL.'/skin/member_skin/style.css?ver='.time().'">';
//회원가입/수정 스킨
$action = CM_MB_URL."/register_form_update.php";
include_once(CM_TEMPLATE_PATH.'/skin/member_skin/register_form.skin.php');
//js 경로
echo '<script>
const recaptchaSiteKey = ' . json_encode($recaptcha_site) . ';
const registerUpdate = ' . json_encode($update) . '; 
</script>';
echo '<script src="'.CM_URL.'/js/register.js?ver='.time().'"></script>';
include_once(CM_PATH.'/tail.php'); 