<?php
include_once('./_common.php');

// JSON 응답 헤더 설정
header('Content-Type: application/json');

$response = array('status' => 'error', 'message' => '');

// 필수 파라미터 체크
if (!isset($_POST['board_id']) || !isset($_POST['board_num'])) {
    $response['message'] = '필수 파라미터가 누락되었습니다.';
    echo json_encode($response);
    exit;
}

$board_id = $_POST['board_id'];
$board_num = (int)$_POST['board_num'];
$action = isset($_POST['act']) ? $_POST['act'] : 'write';

// 게시글 존재 여부 확인
$sql = "SELECT COUNT(*) as cnt FROM cm_board WHERE board_id = :board_id AND board_num = :board_num";
$params = [
    ':board_id' => $board_id,
    ':board_num' => $board_num
];
$result = sql_fetch($sql, $params);

if ($result['cnt'] == 0) {
    $response['message'] = '존재하지 않는 게시글입니다.';
    echo json_encode($response);
    exit;
}

switch ($action) {
    case 'write':
        // 필수 입력값 체크
        if (!isset($_POST['name']) || !isset($_POST['content'])) {
            $response['message'] = '필수 입력값이 누락되었습니다.';
            break;
        }

        // 회원/비회원 구분
        if ($is_member) {
            $user_id = $member['user_id'];
            $name = $member['user_name'];
            $email = $member['user_email'];
            $password = $member['user_password'];
        } else {
            if (!isset($_POST['email']) || !isset($_POST['password'])) {
                $response['message'] = '비회원은 이메일과 비밀번호를 입력해야 합니다.';
                break;
            }
            $user_id = '';
            $name = $_POST['name'];
            $email = $_POST['email'];
            $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
        }

        // 코멘트 등록
        $data = [
            'board_id' => $board_id,
            'board_num' => $board_num,
            'user_id' => $user_id,
            'name' => $name,
            'email' => $email,
            'password' => $password,
            'content' => $_POST['content'],
            'ip' => $_SERVER['REMOTE_ADDR'],
			'reg_date' => date('Y-m-d H:i:s')
        ];

        $comment_id = process_data_insert('cm_board_comment', $data);
		
		// 결과 확인
		if ($comment_id !== false) {
			// 성공
			$response['status'] = 'success';
            $response['message'] = '댓글이 등록되었습니다.';
			$response['comment_id'] = $comment_id;
		} else {
			// 실패 (함수 내부에서 오류 로그는 남겼을 겁니다)
			error_log("댓글 등록 실패: process_data_insert가 false를 반환했습니다.");
            $response['message'] = '댓글 등록에 실패했습니다.';
		}
		
        
        break;

    case 'edit':
        if (!isset($_POST['comment_id']) || !isset($_POST['content'])) {
            $response['message'] = '필수 입력값이 누락되었습니다.';
            break;
        }

        $comment_id = (int)$_POST['comment_id'];

        // 코멘트 존재 여부 및 권한 체크
        $sql = "SELECT * FROM cm_board_comment WHERE comment_id = :comment_id";
        $params = [':comment_id' => $comment_id];
        $comment = sql_fetch($sql, $params);

        if (!$comment) {
            $response['message'] = '존재하지 않는 댓글입니다.';
            break;
        }

        // 권한 체크
        if ($is_member) {
            if ($member['user_id'] != $comment['user_id'] && !$is_admin) {
                $response['message'] = '수정 권한이 없습니다.';
                break;
            }
        } else {
            if (!isset($_POST['password']) || !password_verify($_POST['password'], $comment['password'])) {
                $response['message'] = '비밀번호가 일치하지 않습니다.';
                break;
            }
        }

        // 코멘트 수정
        $data = [
            'content' => $_POST['content'],
            'update_date' => date('Y-m-d H:i:s')
        ];
        $where = ['comment_id' => $comment_id];
		
        if (process_data_update('cm_board_comment', $data, $where)) {
            $response['status'] = 'success';
            $response['message'] = '댓글이 수정되었습니다.';
			$response['comment_id'] = $comment_id;
        } else {
            $response['message'] = '댓글 수정에 실패했습니다.';
        }
        break;

    case 'delete':
        if (!isset($_POST['comment_id'])) {
            $response['message'] = '필수 입력값이 누락되었습니다1.';
            break;
        }

        $comment_id = (int)$_POST['comment_id'];

        // 코멘트 존재 여부 및 권한 체크
        $sql = "SELECT * FROM cm_board_comment WHERE comment_id = :comment_id";
        $params = [':comment_id' => $comment_id];
        $comment = sql_fetch($sql, $params);

        if (!$comment) {
            $response['message'] = '존재하지 않는 댓글입니다.';
            break;
        }

        // 권한 체크
        if ($is_member) {
            if ($member['user_id'] != $comment['user_id'] && !$is_admin) {
                $response['message'] = '삭제 권한이 없습니다.';
                break;
            }
        } else {
            if (!isset($_POST['password']) || !password_verify($_POST['password'], $comment['password'])) {
                $response['message'] = '비밀번호가 일치하지 않습니다.';
                break;
            }
        }

        // 코멘트 삭제
        $where = ['comment_id' => $comment_id];

        if (process_data_delete('cm_board_comment', $where)) {
            $response['status'] = 'success';
            $response['message'] = '댓글이 삭제되었습니다.';
        } else {
            $response['message'] = '댓글 삭제에 실패했습니다.';
        }
        break;

    default:
        $response['message'] = '잘못된 요청입니다.';
        break;
}

echo json_encode($response);