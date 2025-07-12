<?php
include_once("./_common.php");

$uid = $member['user_id'];
$user_id = $member['user_id'];
if (!empty($_GET['uid'])) {
    $user_id = $_GET['uid'];
	$uid = $_GET['uid'];
}

$sortfield = 7;
$viewLine = 5; // 표시할 하위 단계 수
$cell[0][0] = "";
$cell[0][1] = "";
$cell[1][0] = "";
$cell[1][1] = "";
$colcount = 2;
$rowcount = 10;
$vid = isset($_GET['vid']) ? $_GET['vid'] : 0; // vid 변수 초기화

// SQL 쿼리 작성
$sql = "SELECT * FROM `cm_users` WHERE user_block = 0 AND user_leave = 0 ORDER BY user_no";
$params = [];

// sql_all_list 함수를 사용하여 회원 목록 조회
$result = sql_all_list($sql, $params);

if ($result) {
    $pos = 0;
    foreach ($result as $row) {
        $db_no = $row['user_no'];
        $db_id = $row['user_id'];
        $db_recommend = $row['user_recommend'];
        $re_user = get_member($db_recommend);
        $re_user_no = $re_user['user_no'] ?? 0;
        $db_date = $row['created_at'];
        $db_lv = $row['user_lv'];
        $db_point = $row['user_point'];

        if ($user_id) {
            if ($db_id == $user_id) {
                $ss_user_no = $db_no;
            }
        } else if ($vid) {
            if ($db_no == $vid) {
                $ss_user_no = $db_no;
            }
        }

        $data[$pos] = array($db_no, $db_id, $db_id, $db_date, $db_lv, $db_point, $re_user_no, $re_user_no);
        $pos++;
    }

    if (!$vid) $vid = $ss_user_no;
    $rcount = $pos;

    for ($j = 0; $j < $rcount; $j++) {
        if (isset($data[$j][0]) && $data[$j][0] == $vid) {
            $del = (isset($data[$j][1]) && $data[$j][1] == "") ? "o" : "x";
            $custcode = $data[$j][0];
            $custname = isset($data[$j][1]) ? $data[$j][1] : '';
            $custid = isset($data[$j][2]) ? $data[$j][2] : '';
            $custdate = isset($data[$j][3]) ? $data[$j][3] : '';
            $custgrant = isset($data[$j][4]) ? $data[$j][4] : '';
            $custpoint = isset($data[$j][5]) ? $data[$j][5] : '';

            $cell[0][1] = ($del . "|" . $custcode . "|" . $custname . "|" . $custid . "|" . $custdate . "|" . $custgrant . "|" . $custpoint);
            FindNet($custcode, 1);
            break;
        }
    }

    $k = 0;
    for ($j = ($rowcount - 1); $j >= 1; $j--) {
        if (!($j % 2 == 0)) {
            for ($i = $colcount - 1; $i >= 0; $i--) {
                if (isset($cell[$j][$i])) {
                    if ($cell[$j][$i] == "d") {
                        $k = $i;
                    } else if ($cell[$j][$i] == "a") {
                        ChangeLine($i, $j - 1, (int)(($k - $i) / 2));
                        $k = 0;
                    } else if ($k > 0 && $cell[$j][$i] == "") {
                        $cell[$j][$i] = "b";
                    }
                }
            }
        }
    }

    include "./make_network.php";
}

function ChangeLine($col, $row, $incn) {
    global $cell;
    for ($j = $row; $j >= 0; $j--) {
        if (isset($cell[$j][$col])) {
            $cell[$j][$col + $incn] = $cell[$j][$col];
            $cell[$j][$col] = "";
        }
    }
    if (isset($cell[$row + 1][$col + $incn])) {
        if ($cell[$row + 1][$col + $incn] == "b") {
            $cell[$row + 1][$col + $incn] = "c";
        } else {
            $cell[$row + 1][$col + $incn] = "f";
        }
    }
}

function FindNet($code, $step) {
    global $data, $sortfield, $viewLine, $rcount, $cell, $colcount, $rowcount;
    $nal = 0;

    for ($j = 0; $j < $rcount; $j++) {
        if (isset($data[$j][$sortfield]) && $data[$j][$sortfield] == $code) {
            $nal++;
            if ($nal == 1) $str = "e";
            if ($nal > 1) {
                $colcount += 2;
                for ($m = 0; $m < $rowcount; $m++) {
                    $cell[$m][$colcount - 1] = "";
                    $cell[$m][$colcount - 2] = "";
                }
                for ($k = $colcount - 1; $k >= 0; $k--) {
                    if (isset($cell[($step * 2) - 1][$k])) {
                        $str = $cell[($step * 2) - 1][$k];
                        if ($str == "e") {
                            $cell[($step * 2) - 1][$k] = "a";
                            break;
                        }
                        if ($str == "d") {
                            $cell[($step * 2) - 1][$k] = "g";
                            break;
                        }
                    }
                }
                $str = "d";
            }

            $del = (isset($data[$j][1]) && $data[$j][1] == "") ? "o" : "x";
            $custcode = isset($data[$j][0]) ? $data[$j][0] : '';
            $custname = isset($data[$j][1]) ? $data[$j][1] : '';
            $custid = isset($data[$j][2]) ? $data[$j][2] : '';
            $custdate = isset($data[$j][3]) ? $data[$j][3] : '';
            $custgrant = isset($data[$j][4]) ? $data[$j][4] : '';
            $custpoint = isset($data[$j][5]) ? $data[$j][5] : '';

            $cell[$step * 2][$colcount - 1] = ($del . "|" . $custcode . "|" . $custname . "|" . $custid . "|" . $custdate . "|" . $custgrant . "|" . $custpoint);
            $cell[$step * 2 - 1][$colcount - 1] = $str;
            if ($step <= $viewLine) {
                FindNet($custcode, $step + 1);
            }

            if ($rowcount < (($step * 2) + 1)) {
                $rowcount = (($step * 2) + 1);
                for ($t = 0; $t < $colcount; $t++) {
                    $cell[$rowcount][$t] = "";
                }
            }
        }
    }
}
?>

<script>
function backbtn() {
    history.back(-1);
}

function net_mb_link(user_id) {
    location.href = "./?uid=" + user_id;
}
</script>