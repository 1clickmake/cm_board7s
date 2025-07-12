<?php
include_once './_common.php';


try {
    $action = $_POST['action'] ?? '';

    if ($action === 'add') {
        $user_id = $_POST['user_id'] ?? '';
        $point = (int)($_POST['point'] ?? 0);
        $description = $_POST['description'] ?? '';

        // get_UserPoint 함수로 포인트 지급
        get_UserPoint($user_id, $point, $description, 'add');
        $message = "포인트가 성공적으로 지급되었습니다.";
    } elseif ($action === 'delete') {
        $id = (int)($_POST['id'] ?? 0);

        if ($id <= 0) {
            throw new Exception("유효하지 않은 포인트 ID입니다.");
        }

        // cm_point에서 삭제할 포인트 정보 가져오기
        $stmt = $pdo->prepare("SELECT user_id, point, description FROM cm_point WHERE id = :id");
        $stmt->execute(['id' => $id]);
        $point_data = $stmt->fetch();

        if (!$point_data) {
            throw new Exception("해당 포인트 내역을 찾을 수 없습니다.");
        }

        $user_id = $point_data['user_id'];
        $point = abs((int)$point_data['point']); // 절대값으로 처리
        $description = $point_data['description'];

        // get_UserPoint 함수로 포인트 내역 삭제
        get_UserPoint($user_id, $point, $description, 'cut');

        $message = "포인트 내역이 성공적으로 삭제되었습니다.";
    } else {
        throw new Exception("잘못된 요청입니다.");
    }

    // 성공 메시지와 함께 리스트 페이지로 리다이렉트
    echo "<script>alert('$message'); location.href='point_list.php';</script>";
} catch (Exception $e) {
    // 에러 메시지 출력
    echo "<script>alert('오류: " . addslashes($e->getMessage()) . "'); history.back();</script>";
}
