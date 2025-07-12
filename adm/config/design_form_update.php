<?php
include_once './_common.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $template_id = filter_input(INPUT_POST, 'template_id', FILTER_SANITIZE_SPECIAL_CHARS);
	$shop_template_id = filter_input(INPUT_POST, 'shop_template_id', FILTER_SANITIZE_SPECIAL_CHARS);
   
	$DataToUpdate = [
		'template_id' => $template_id,
		'shop_template_id' => $shop_template_id
	];
	// 업데이트 조건 where
	$where = [
		'id' => 1 
	];
	$data_update = process_data_update('cm_config', $DataToUpdate, $where); // $pdo 인자 없이 호출
	
	// 업데이트 결과 확인
    if ($data_update !== false) {
        // 업데이트 성공
		alert('업데이트 되었습니다.', './design_form.php');
    } else {
        // 업데이트 실패 
        alert('오류가 발생했습니다.');
    }
}