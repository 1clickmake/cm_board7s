<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가

// 아코디언 메뉴 생성 함수 (재귀적)
function generateAccordionMenu($parent_id = 0, $level = 1, $max_depth = 3) {
    global $pdo;
    
    // 최대 깊이를 초과하면 빈 문자열 반환
    if ($level > $max_depth) {
        return '';
    }
    
    $sql = "SELECT * FROM cm_menu 
             WHERE parent_id = :parent_id AND is_disabled = 0 
             ORDER BY sort_order ASC";
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['parent_id' => $parent_id]);
    $menus = $stmt->fetchAll();

    if (empty($menus)) {
        return '';
    }

    $output = '';
    $is_submenu = $level > 1;
    
    // 1차 메뉴인 경우에만 accordion 클래스 추가
    if ($level === 1) {
        $output .= '<div class="accordion" id="sidebarMenu">';
    }

    foreach ($menus as $index => $menu) {
        // 서브메뉴 확인
        $submenu_sql = "SELECT * FROM cm_menu WHERE parent_id = :menu_id AND is_disabled = 0 LIMIT 1";
        $submenu_stmt = $pdo->prepare($submenu_sql);
        $submenu_stmt->execute(['menu_id' => $menu['menu_id']]);
        $has_children = $submenu_stmt->rowCount() > 0;
        
        // 동적 마진 계산: 2차 메뉴는 10px, 3차 메뉴는 20px
        $margin_left = ($level > 1) ? (15 * ($level - 1)) : 0;
        $menu_class = $is_submenu ? 'ps-4' : '';
        // 하위 메뉴가 없는 경우 no-arrow 클래스 추가
        $arrow_class = $has_children ? '' : 'no-arrow';
        
        $output .= '<div class="accordion-item border-0">';
        $output .= '  <h2 class="accordion-header" id="heading' . $menu['menu_id'] . '">';
        $output .= '    <button class="accordion-button collapsed ' . $menu_class . ' ' . $arrow_class . '" type="button" data-bs-toggle="collapse" ';
        $output .= '            data-bs-target="#collapse' . $menu['menu_id'] . '" aria-expanded="false" ';
        $output .= '            aria-controls="collapse' . $menu['menu_id'] . '" data-bs-parent="' . ($level === 1 ? '#sidebarMenu' : '#collapse' . $parent_id) . '">';
        $output .= '      <span style="display: inline-block; margin-left: ' . $margin_left . 'px; font-weight: ' . ($is_submenu ? 'normal' : '500') . ';">';
        $output .= '        <a href="' . htmlspecialchars($menu['menu_url'], ENT_QUOTES, 'UTF-8') . '" style="text-decoration: none; color: inherit;">';
        // 아이콘이 있을 때만 출력
        if (!empty($menu['menu_icon'])) {
            $output .= '          ' . $menu['menu_icon'] . ' ';
        }
        $output .= '          ' . htmlspecialchars($menu['menu_name'], ENT_QUOTES, 'UTF-8');
        $output .= '        </a>';
        $output .= '      </span>';
        $output .= '    </button>';
        $output .= '  </h2>';
        
        if ($has_children) {
            $output .= '  <div id="collapse' . $menu['menu_id'] . '" class="accordion-collapse collapse" ';
            $output .= '       aria-labelledby="heading' . $menu['menu_id'] . '" ';
            $output .= '       data-bs-parent="' . ($level === 1 ? '#sidebarMenu' : '#collapse' . $parent_id) . '">';
            $output .= '    <div class="accordion-body p-0">';
            $output .= '      <div class="list-group list-group-flush">';
            $output .= generateAccordionMenu($menu['menu_id'], $level + 1, $max_depth);
            $output .= '      </div>';
            $output .= '    </div>';
            $output .= '  </div>';
        }
        
        $output .= '</div>';
    }
    
    // 1차 메뉴인 경우에만 닫는 태그 추가
    if ($level === 1) {
        $output .= '</div>';
    }
    
    return $output;
}

// 메뉴 데이터를 조회하고 계층 구조로 출력하는 함수
function generateMegaMenu($parent_id = 0, $level = 1, $max_depth = 3) {
    global $pdo;
    global $is_admin, $is_member, $is_guest;

    // 메뉴 조회 쿼리: 비활성화되지 않은 메뉴를 sort_order 기준으로 정렬
    $sql = "SELECT * 
            FROM cm_menu
            WHERE parent_id = :parent_id AND is_disabled = 0
            ORDER BY sort_order ASC";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute(['parent_id' => $parent_id]);
    $menus = $stmt->fetchAll();

    // 메뉴가 없으면 종료
    if (empty($menus)) {
        return;
    }

    // 최대 뎁스 제한
    if ($level > $max_depth) {
        return;
    }

    // 1차 메뉴 레벨에서는 navbar-nav 구조 시작
    if ($level == 1) {
        echo '<ul class="navbar-nav ms-auto">';
    }

    foreach ($menus as $row) {
        $menu_id = $row['menu_id'];
        $menu_name = htmlspecialchars($row['menu_name']);
        $menu_url = htmlspecialchars($row['menu_url']);
        $target = ($row['target_blank'] == 1) ? ' target="_blank"' : '';

        // 자기 참조 방지
        if ($menu_id == $parent_id) {
            continue;
        }

        // 서브메뉴 존재 여부 확인
        $sub_sql = "SELECT COUNT(*) as count FROM cm_menu WHERE parent_id = :parent_id AND is_disabled = 0";
        $sub_stmt = $pdo->prepare($sub_sql);
        $sub_stmt->execute(['parent_id' => $menu_id]);
        $sub_count = $sub_stmt->fetch()['count'];

        if ($level == 1) {
            // 1차 메뉴
            if ($sub_count > 0) {
                // 드롭다운이 있는 1차 메뉴
                echo '<li class="nav-item dropdown">';
                echo '<a class="nav-link dropdown-toggle text-white" href="' . $menu_url . '" id="navbarDropdown' . $menu_id . '" role="button" data-bs-toggle="dropdown" aria-expanded="false"' . $target . '>';
                if (!empty($row['menu_icon'])) {
                    echo $row['menu_icon'] . ' ';
                }
                echo $menu_name;
                echo '</a>';
                echo '<ul class="dropdown-menu" aria-labelledby="navbarDropdown' . $menu_id . '">';
                
                // 서브메뉴 재귀 호출
                generateMegaMenu($menu_id, $level + 1, $max_depth);
                
                echo '</ul>';
                echo '</li>';
            } else {
                // 드롭다운이 없는 1차 메뉴
                echo '<li class="nav-item">';
                echo '<a class="nav-link text-white" href="' . $menu_url . '"' . $target . '>';
                if (!empty($row['menu_icon'])) {
                    echo $row['menu_icon'] . ' ';
                }
                echo $menu_name;
                echo '</a>';
                echo '</li>';
            }
        } else {
            // 2차 이상 메뉴
            if ($sub_count > 0) {
                // 모든 뎁스에서 드롭다운 지원
                echo '<li class="dropend">';
                echo '<a class="dropdown-item dropdown-toggle" href="' . $menu_url . '" id="navbarDropdown' . $menu_id . '" role="button" data-bs-toggle="dropdown" aria-expanded="false"' . $target . '">';
                if (!empty($row['menu_icon'])) {
                    echo $row['menu_icon'] . ' ';
                }
                echo $menu_name;
                echo '</a>';
                echo '<ul class="dropdown-menu" aria-labelledby="navbarDropdown' . $menu_id . '">';
                // 서브메뉴 재귀 호출
                generateMegaMenu($menu_id, $level + 1, $max_depth);
                echo '</ul>';
                echo '</li>';
            } else {
                // 서브메뉴가 없는 경우
                echo '<li>';
                echo '<a class="dropdown-item" href="' . $menu_url . '"' . $target . '">';
                if (!empty($row['menu_icon'])) {
                    echo $row['menu_icon'] . ' ';
                }
                echo $menu_name;
                echo '</a>';
                echo '</li>';
            }
        }
    }
    
    // 회원 관련 메뉴 추가 (1차 메뉴 레벨에서만)
    if ($parent_id == 0) {
        echo '<li class="nav-item dropdown">';
        echo '<a class="nav-link dropdown-toggle text-white" href="#" id="navbarDropdownUser" role="button" data-bs-toggle="dropdown" aria-expanded="false">';
        echo '<i class="bi bi-person-circle me-1"></i> 내정보';
        echo '</a>';
        echo '<ul class="dropdown-menu dropdown-menu-end" aria-labelledby="navbarDropdownUser">';

        if($is_member){
            echo '<li><a class="dropdown-item" href="' . CM_MB_URL . '/mypage.php"><i class="bi bi-person-lines-fill me-2"></i>마이페이지</a></li>';
            echo '<li><a class="dropdown-item" href="' . CM_MB_URL . '/logout.php"><i class="bi bi-box-arrow-right me-2"></i>로그아웃</a></li>';
            if($is_admin){
                echo '<li><hr class="dropdown-divider"></hr></li>';
                echo '<li><a class="dropdown-item" href="' . CM_ADMIN_URL . '"><i class="bi bi-shield-lock me-2"></i>관리자</a></li>';
            }
        } else {
            echo '<li><a class="dropdown-item" href="' . CM_MB_URL . '/register_form.php"><i class="bi bi-person-plus me-2"></i>회원가입</a></li>';
            echo '<li><a class="dropdown-item" href="' . CM_MB_URL . '/login.php"><i class="bi bi-box-arrow-in-right me-2"></i>로그인</a></li>';
        }
        
        echo '</ul>';
        echo '</li>';
        
        // 오프캔버스 토글 버튼
        echo '<li class="nav-item">';
        echo '<button type="button" class="btn btn-link text-white p-0 ms-3" data-bs-toggle="offcanvas" data-bs-target="#site-menu">';
        echo '<i class="bi bi-list fs-4"></i>';
        echo '</button>';
        echo '</li>';
    }
    
    // 1차 메뉴 레벨에서는 navbar-nav 구조 종료
    if ($level == 1) {
        echo '</ul>';
    }
}