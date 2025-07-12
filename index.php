<?php
include_once './common.php';

define('_INDEX_', true);

include_once CM_PATH.'/head.php';
include_once CM_ADMIN_PATH.'/config/popup.php'; 
display_popups(); 
include_once CM_TEMPLATE_PATH.'/index.php';
include_once CM_PATH.'/tail.php';