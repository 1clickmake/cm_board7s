<?php
include_once './_common.php';
// CSRF 토큰 검증 (예시)
// if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
//     echo json_encode(['status' => 'error', 'message' => '잘못된 접근입니다. (CSRF 토큰 오류)']);
//     exit;
// }

$action = isset($_POST['action']) ? $_POST['action'] : '';

try {
    if ($action === 'add') {
        $parent_id = (int)$_POST['parent_id'];
        // XSS 방지를 위해 입력값 처리
        $menu_name = isset($_POST['menu_name']) ? strip_tags(trim($_POST['menu_name'])) : '';
        $menu_url = isset($_POST['menu_url']) ? filter_var(trim($_POST['menu_url']), FILTER_SANITIZE_URL) : '';
		$menu_icon = $_POST['menu_icon'] ?? '';
        $target_blank = isset($_POST['target_blank']) && $_POST['target_blank'] == '1' ? 1 : 0;
        $is_disabled = isset($_POST['is_disabled']) && $_POST['is_disabled'] == '1' ? 1 : 0;

        if (empty($menu_name)) {
            echo json_encode(['status' => 'error', 'message' => '메뉴 이름을 입력해주세요.']);
            exit;
        }
        
        // 메뉴 레벨 계산 (최대 깊이 제한)
        $menu_level = 1;
        if ($parent_id > 0) {
            $stmt = $pdo->prepare("SELECT menu_level FROM cm_menu WHERE menu_id = ?");
            $stmt->execute([$parent_id]);
            $parent = $stmt->fetch();
            if ($parent) {
                $menu_level = $parent['menu_level'] + 1;
                // 최대 깊이 체크
                if ($menu_level > CM_MAX_MENU_DEPTH) {
                    echo json_encode(['status' => 'error', 'message' => '메뉴는 최대 ' . CM_MAX_MENU_DEPTH . '뎁스까지만 생성할 수 있습니다.']);
                    exit;
                }
            } else {
                throw new PDOException("상위 메뉴를 찾을 수 없습니다.");
            }
        }
        
        // sort_order 계산
        $stmt = $pdo->prepare("SELECT MAX(sort_order) as max_sort FROM cm_menu WHERE parent_id = ?");
        $stmt->execute([$parent_id]);
        $sort_order = ($stmt->fetch()['max_sort'] ?? 0) + 1;
        
        $stmt = $pdo->prepare("INSERT INTO cm_menu (parent_id, menu_name, menu_url, menu_icon, target_blank, is_disabled, menu_level, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$parent_id, $menu_name, $menu_url, $menu_icon, $target_blank, $is_disabled, $menu_level, $sort_order]);
        
        echo json_encode(['status' => 'success']);
    }
    elseif ($action === 'get') {
        $menu_id = (int)$_POST['menu_id'];
        $stmt = $pdo->prepare("SELECT * FROM cm_menu WHERE menu_id = ?");
        $stmt->execute([$menu_id]);
        $menu = $stmt->fetch();
        if ($menu) {
            echo json_encode($menu);
        } else {
            echo json_encode(['status' => 'error', 'message' => '메뉴를 찾을 수 없습니다.']);
        }
    }
    elseif ($action === 'get_menu_options') {
        $current_menu_id = (int)$_POST['current_menu_id'];
        
        function get_menu_options_recursive($pdo, $current_menu_id, $parent_id = 0, $level = 0, $prefix = '') {
            $stmt = $pdo->prepare("SELECT * FROM cm_menu WHERE parent_id = ? AND menu_id != ? ORDER BY sort_order");
            $stmt->execute([$parent_id, $current_menu_id]);
            $menus = $stmt->fetchAll();
            
            $options = [];
            foreach ($menus as $menu) {
                $option = [
                    'menu_id' => $menu['menu_id'],
                    'menu_name' => $menu['menu_name'],
                    'menu_level' => $menu['menu_level'],
                    'prefix' => $prefix,
                    'disabled' => ($menu['menu_level'] >= CM_MAX_MENU_DEPTH)
                ];
                $options[] = $option;
                
                // 하위 메뉴 재귀 호출
                $sub_options = get_menu_options_recursive($pdo, $current_menu_id, $menu['menu_id'], $level + 1, $prefix . '—&nbsp;');
                $options = array_merge($options, $sub_options);
            }
            return $options;
        }
        
        $options = get_menu_options_recursive($pdo, $current_menu_id);
        echo json_encode($options);
    }
    elseif ($action === 'edit') {
        $menu_id = (int)$_POST['menu_id'];
        $parent_id = (int)$_POST['parent_id'];
        // XSS 방지를 위해 입력값 처리
        $menu_name = isset($_POST['menu_name']) ? strip_tags(trim($_POST['menu_name'])) : '';
        $menu_url = isset($_POST['menu_url']) ? filter_var(trim($_POST['menu_url']), FILTER_SANITIZE_URL) : '';
		$menu_icon = $_POST['menu_icon'] ?? '';
        $target_blank = isset($_POST['target_blank']) && $_POST['target_blank'] == '1' ? 1 : 0;
        $is_disabled = isset($_POST['is_disabled']) && $_POST['is_disabled'] == '1' ? 1 : 0;

        if (empty($menu_name)) {
            echo json_encode(['status' => 'error', 'message' => '메뉴 이름을 입력해주세요.']);
            exit;
        }
        
        // 메뉴 레벨 계산 (최대 깊이 제한)
        $menu_level = 1;
        if ($parent_id > 0) {
            $stmt = $pdo->prepare("SELECT menu_level FROM cm_menu WHERE menu_id = ?");
            $stmt->execute([$parent_id]);
            $parent = $stmt->fetch();
            if ($parent) {
                $menu_level = $parent['menu_level'] + 1;
                // 최대 깊이 체크
                if ($menu_level > CM_MAX_MENU_DEPTH) {
                    echo json_encode(['status' => 'error', 'message' => '메뉴는 최대 ' . CM_MAX_MENU_DEPTH . '뎁스까지만 생성할 수 있습니다.']);
                    exit;
                }
            } else {
                throw new PDOException("상위 메뉴를 찾을 수 없습니다.");
            }
        }
        
        $stmt = $pdo->prepare("UPDATE cm_menu SET parent_id = ?, menu_name = ?, menu_url = ?, menu_icon = ?, target_blank = ?, is_disabled = ?, menu_level = ? WHERE menu_id = ?");
        $stmt->execute([$parent_id, $menu_name, $menu_url, $menu_icon, $target_blank, $is_disabled, $menu_level, $menu_id]);
        
        if ($stmt->rowCount() > 0) {
            echo json_encode(['status' => 'success']);
        } else {
            echo json_encode(['status' => 'error', 'message' => '변경된 내용이 없거나 메뉴를 찾을 수 없습니다.']);
        }
    }
    elseif ($action === 'delete') {
        $menu_id = (int)$_POST['menu_id'];
        
        // 하위 메뉴 확인
        $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM cm_menu WHERE parent_id = ?");
        $stmt->execute([$menu_id]);
        if ($stmt->fetch()['count'] > 0) {
            echo json_encode(['status' => 'error', 'message' => '하위 메뉴가 있어 삭제할 수 없습니다.']);
            exit;
        }
        
        $stmt = $pdo->prepare("DELETE FROM cm_menu WHERE menu_id = ?");
        $stmt->execute([$menu_id]);
        
        if ($stmt->rowCount() > 0) {
            echo json_encode(['status' => 'success']);
        } else {
            echo json_encode(['status' => 'error', 'message' => '메뉴를 찾을 수 없습니다.']);
        }
    }
    elseif ($action === 'update_order') {
        $parent_id = (int)$_POST['parent_id'];
        $menu_ids = $_POST['menu_ids'];
        
        if (is_array($menu_ids) && !empty($menu_ids)) {
            $pdo->beginTransaction(); // 트랜잭션 시작
            $stmt = $pdo->prepare("UPDATE cm_menu SET sort_order = ? WHERE menu_id = ? AND parent_id = ?");
            foreach ($menu_ids as $index => $menu_id) {
                if (!$stmt->execute([$index + 1, (int)$menu_id, $parent_id])) {
                    $pdo->rollBack(); // 오류 발생 시 롤백
                    echo json_encode(['status' => 'error', 'message' => '순서 업데이트 중 오류가 발생했습니다.']);
                    exit;
                }
            }
            $pdo->commit(); // 모든 작업 성공 시 커밋
            echo json_encode(['status' => 'success']);
        } else {
            echo json_encode(['status' => 'error', 'message' => '잘못된 메뉴 ID 배열']);
        }
    }
} catch (PDOException $e) {
    echo json_encode(['status' => 'error', 'message' => '데이터베이스 오류: ' . $e->getMessage()]);
}
?>