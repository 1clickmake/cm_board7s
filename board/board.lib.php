<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가


// 게시글 ID 확인
$boardId = isset($_GET['board']) ? $_GET['board'] : '';
$boardNum = isset($_GET['id']) ? intval($_GET['id']) : 0;
$ip = $_SERVER['REMOTE_ADDR']; 

if(empty($boardId)){
	alert('게시판아이디가 없습니다.');
}

$bo = get_board($boardId); //게시판 정보
if(empty($bo)){
	alert('잘못된 접근입니다.');
}

//현재 url 파일 순수 파일명 write.php --> write 출력
$currentFilename = get_current_filename();