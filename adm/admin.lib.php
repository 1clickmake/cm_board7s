<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가 

if(!$is_admin){
	alert('접근하실 수 없습니다.', CM_URL);
}


/***********************************/
// 테이블 데이터를 가져오는 함수
/***********************************/
// 테이블 데이터를 가져오는 함수 (구간 선택 및 정렬 기능 추가)
function getTableData($table_name, $limit_start = null, $limit_end = null, $order_direction = 'asc') {
    global $pdo;
    
    try {
        // 테이블명 유효성 검사는 displayTableFromGet에서 이미 수행되므로 여기서는 직접 사용
        // 하지만 더 강력한 보호를 위해 여기서 다시 한번 정규식 검사를 하거나,
        // displayTableFromGet에서 검사된 테이블 이름을 그대로 사용하는 것을 전제로 합니다.
        // 현재 코드에서는 displayTableFromGet에서 유효하지 않은 테이블명은 미리 걸러집니다.

        // 테이블 존재 확인 (바인딩 대신 직접 삽입)
        // displayTableFromGet에서 이미 테이블명 유효성 검증 (preg_match)을 하므로 안전하다고 가정
        $checkSql = "SHOW TABLES LIKE '$table_name'"; // 변경된 부분
        $checkStmt = $pdo->prepare($checkSql);
        $checkStmt->execute();
        
        if ($checkStmt->rowCount() == 0) {
            return ['error' => "테이블 '$table_name'이 존재하지 않습니다."];
        }
        
        // 전체 행 수 조회
        $countSql = "SELECT COUNT(*) as total_rows FROM `$table_name`";
        $countStmt = $pdo->prepare($countSql);
        $countStmt->execute();
        $totalRows = $countStmt->fetch(PDO::FETCH_ASSOC)['total_rows'];
        
        // 테이블의 첫 번째 컬럼명 가져오기 (정렬용)
        $columnSql = "SHOW COLUMNS FROM `$table_name`";
        $columnStmt = $pdo->prepare($columnSql);
        $columnStmt->execute();
        $firstColumnData = $columnStmt->fetch(PDO::FETCH_ASSOC); // null 체크 추가
        $firstColumn = $firstColumnData ? $firstColumnData['Field'] : null;

        if (!$firstColumn) {
            return ['error' => "테이블 '$table_name'에 컬럼이 없습니다."];
        }
        
        // 데이터 조회 쿼리 작성
        $sql = "SELECT * FROM `$table_name`";
        
        // 정렬 방향 설정 (기본값: ASC)
        $orderDirection = strtoupper($order_direction) === 'DESC' ? 'DESC' : 'ASC';
        $sql .= " ORDER BY `$firstColumn` $orderDirection";
        
        // LIMIT 구간 설정
        if ($limit_start !== null && $limit_end !== null) {
            $start = intval($limit_start);
            $end = intval($limit_end);
            
            if ($start > 0 && $end > 0 && $start <= $end) {
                $offset = $start - 1; // MySQL OFFSET은 0부터 시작
                $count = $end - $start + 1; // 구간에 포함되는 행 수
                $sql .= " LIMIT $offset, $count";
            }
        }
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute();
        
        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        return [
            'data' => $data,
            'total_rows' => $totalRows,
            'displayed_rows' => count($data),
            'limit_start' => $limit_start,
            'limit_end' => $limit_end,
            'order_direction' => $orderDirection,
            'limited' => ($limit_start !== null && $limit_end !== null)
        ];
        
    } catch (PDOException $e) {
        return ['error' => "쿼리 실행 오류: " . $e->getMessage()];
    }
}

// 명령프롬프트 스타일로 테이블 렌더링하는 함수 (수정됨)
function renderTableAsCliStyle($table_name, $limit_start = null, $limit_end = null, $order_direction = 'asc') {
    $result = getTableData($table_name, $limit_start, $limit_end, $order_direction);
    
    // 오류 처리
    if (isset($result['error'])) {
        return '<pre style="color: red; font-family: monospace; background-color: #000; padding: 15px; border-radius: 5px;">' . 
               htmlspecialchars($result['error']) . '</pre>';
    }
    
    $tableData = $result['data'];
    $totalRows = $result['total_rows'];
    $displayedRows = $result['displayed_rows'];
    $isLimited = $result['limited'];
    $orderDirection = $result['order_direction'];
    
    if (empty($tableData)) {
        return '<pre style="color: #00ff00; font-family: monospace; background-color: #000; padding: 15px; border-radius: 5px;">' .
               "테이블 '$table_name'에 데이터가 없습니다." . '</pre>';
    }
    
    // 컬럼명 추출
    $columns = array_keys($tableData[0]);
    
    // 각 컬럼의 최대 너비 계산
    $columnWidths = [];
    foreach ($columns as $column) {
        $columnWidths[$column] = strlen($column);
    }
    
    // 데이터를 통해 최대 너비 업데이트
    foreach ($tableData as $row) {
        foreach ($columns as $column) {
            $dataLength = strlen((string)$row[$column]);
            if ($dataLength > $columnWidths[$column]) {
                $columnWidths[$column] = $dataLength;
            }
        }
    }
    
    // 최소 너비 설정 (가독성을 위해)
    foreach ($columnWidths as $column => $width) {
        if ($width < 8) {
            $columnWidths[$column] = 8;
        }
    }
    
    $output = '';
    
    // 테이블 정보 헤더
    $infoLine = "Table: $table_name | Order: $orderDirection";
    if ($isLimited && $limit_start && $limit_end) {
        $infoLine .= " | Range: $limit_start-$limit_end | Showing: $displayedRows of $totalRows rows";
    } else {
        $infoLine .= " | Total rows: $totalRows";
    }
    $output .= $infoLine . "\n";
    $output .= str_repeat('=', strlen($infoLine)) . "\n\n";
    
    // 헤더 라인 생성
    $headerLine = '';
    $separatorLine = '';
    
    foreach ($columns as $i => $column) {
        $width = $columnWidths[$column];
        $paddedColumn = str_pad($column, $width, ' ', STR_PAD_RIGHT);
        
        if ($i == 0) {
            $headerLine .= $paddedColumn;
            $separatorLine .= str_repeat('-', $width);
        } else {
            $headerLine .= ' | ' . $paddedColumn;
            $separatorLine .= '-+-' . str_repeat('-', $width);
        }
    }
    
    $output .= $headerLine . "\n";
    $output .= $separatorLine . "\n";
    
    // 데이터 라인 생성
    foreach ($tableData as $row) {
        $dataLine = '';
        foreach ($columns as $i => $column) {
            $width = $columnWidths[$column];
            $value = $row[$column] ?? '';
            $paddedValue = str_pad((string)$value, $width, ' ', STR_PAD_RIGHT);
            
            if ($i == 0) {
                $dataLine .= $paddedValue;
            } else {
                $dataLine .= ' | ' . $paddedValue;
            }
        }
        $output .= $dataLine . "\n";
    }
    
    // 제한된 결과일 경우 하단에 안내 메시지
    if ($isLimited && $limit_start && $limit_end) {
        $output .= "\n" . str_repeat('-', 50) . "\n";
        $output .= "※ Displaying rows $limit_start to $limit_end of $totalRows total rows";
    }
    
    // CLI 스타일로 감싸기
    $styledOutput = '<pre style="
        font-family: \'Courier New\', Consolas, monospace; 
        background-color: #000; 
        color: #00ff00; 
        padding: 20px; 
        border-radius: 8px; 
        overflow-x: auto; 
        white-space: pre; 
        border: 2px solid #333;
        box-shadow: 0 4px 8px rgba(0,0,0,0.3);
        font-size: 14px;
        line-height: 1.2;
    ">' . htmlspecialchars($output) . '</pre>';
    
    return $styledOutput;
}

// 메인 함수 - GET 파라미터로 테이블명, 구간, 정렬방향 받아서 처리
function displayTableFromGet() {
    if (isset($_GET['table']) && !empty($_GET['table'])) {
        $table_name = trim($_GET['table']);
        $limit_start = isset($_GET['limit_start']) && !empty($_GET['limit_start']) ? intval($_GET['limit_start']) : null;
        $limit_end = isset($_GET['limit_end']) && !empty($_GET['limit_end']) ? intval($_GET['limit_end']) : null;
        $order_direction = isset($_GET['order']) && !empty($_GET['order']) ? $_GET['order'] : 'asc';
        
        // 테이블명 검증 (SQL 인젝션 방지)
        if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $table_name)) {
            return '<pre style="color: red; font-family: monospace; background-color: #000; padding: 15px; border-radius: 5px;">' .
                   '유효하지 않은 테이블명입니다. 영문자, 숫자, 언더스코어만 사용 가능합니다.' . '</pre>';
        }
        
        // 구간 검증
        if (($limit_start !== null || $limit_end !== null)) {
            if ($limit_start === null || $limit_end === null) {
                return '<pre style="color: red; font-family: monospace; background-color: #000; padding: 15px; border-radius: 5px;">' .
                       '시작과 끝 구간을 모두 입력해주세요.' . '</pre>';
            }
            
            if ($limit_start <= 0 || $limit_end <= 0) {
                return '<pre style="color: red; font-family: monospace; background-color: #000; padding: 15px; border-radius: 5px;">' .
                       '구간 값은 1 이상이어야 합니다.' . '</pre>';
            }
            
            if ($limit_start > $limit_end) {
                return '<pre style="color: red; font-family: monospace; background-color: #000; padding: 15px; border-radius: 5px;">' .
                       '시작 구간이 끝 구간보다 클 수 없습니다.' . '</pre>';
            }
            
            if ($limit_end > 10000) {
                return '<pre style="color: red; font-family: monospace; background-color: #000; padding: 15px; border-radius: 5px;">' .
                       '구간은 10000 이하여야 합니다.' . '</pre>';
            }
        }
        
        // 정렬 방향 검증
        if (!in_array(strtolower($order_direction), ['asc', 'desc'])) {
            $order_direction = 'asc';
        }
        
        return renderTableAsCliStyle($table_name, $limit_start, $limit_end, $order_direction);
    }
    
    return '<pre style="color: #ffff00; font-family: monospace; background-color: #000; padding: 15px; border-radius: 5px;">' .
           '테이블명을 입력해주세요.' . '</pre>';
}
/*************************************/

// 최근 7일간의 방문자 통계 조회
$sql = "SELECT 
            DATE(visit_time) as visit_date,
            COUNT(*) as visit_count
        FROM cm_visit
        WHERE visit_time >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
        GROUP BY DATE(visit_time)
        ORDER BY visit_date ASC";
$result = sql_all_list($sql);

// 최근 7일간 시간대별 방문자 통계 조회
$hourly_sql = "SELECT 
                DATE(visit_time) as visit_date,
                HOUR(visit_time) as visit_hour,
                COUNT(*) as visit_count
               FROM cm_visit
               WHERE visit_time >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
               GROUP BY DATE(visit_time), HOUR(visit_time)
               ORDER BY visit_date ASC, visit_hour ASC";
$hourly_result = sql_all_list($hourly_sql);

$visit_dates = [];
$visit_counts = [];
$total_visits = 0;

// 시간대별 데이터 초기화 (7일 x 24시간)
$hourly_data = [];
$dates = [];
for ($i = 6; $i >= 0; $i--) {
    $date = date('Y-m-d', strtotime("-$i days"));
    $dates[] = date('m/d', strtotime($date));
    $hourly_data[$date] = array_fill(0, 24, 0);
}

if ($result) {
    foreach ($result as $row) {
        $visit_dates[] = date('m/d', strtotime($row['visit_date']));
        $visit_counts[] = (int)$row['visit_count'];
        $total_visits += $row['visit_count'];
    }
}

// 시간대별 데이터 채우기
if ($hourly_result) {
    foreach ($hourly_result as $row) {
        $date = date('Y-m-d', strtotime($row['visit_date']));
        if (isset($hourly_data[$date])) {
            $hourly_data[$date][$row['visit_hour']] = (int)$row['visit_count'];
        }
    }
}

// 오늘 방문자 수
$today_sql = "SELECT COUNT(*) as cnt FROM cm_visit WHERE DATE(visit_time) = CURDATE()";
$today_result = sql_fetch($today_sql);
$today_visits = $today_result ? $today_result['cnt'] : 0;

// 어제 방문자 수
$yesterday_sql = "SELECT COUNT(*) as cnt FROM cm_visit WHERE DATE(visit_time) = DATE_SUB(CURDATE(), INTERVAL 1 DAY)";
$yesterday_result = sql_fetch($yesterday_sql);
$yesterday_visits = $yesterday_result ? $yesterday_result['cnt'] : 0;

// 어제 작성된 게시물 수
$yesterday_posts_sql = "SELECT COUNT(*) as cnt FROM cm_board WHERE DATE(reg_date) = DATE_SUB(CURDATE(), INTERVAL 1 DAY)";
$yesterday_posts_result = sql_fetch($yesterday_posts_sql);
$yesterday_posts = $yesterday_posts_result ? $yesterday_posts_result['cnt'] : 0;