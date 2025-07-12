<?php
include_once('./_common.php');
include_once(CM_PATH.'/head.php');
$pages = isset($_GET['p']) ? $_GET['p'] : 1;
echo '<link rel="stylesheet" href="'.CM_TEMPLATE_URL.'/skin/page/style.css?ver='.time().'">';
include_once(CM_TEMPLATE_PATH.'/skin/page/p'.$pages.'.php');
include_once(CM_PATH.'/tail.php'); 