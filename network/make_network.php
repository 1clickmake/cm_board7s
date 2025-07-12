<?php
include_once('./_common.php');

$td_width = 70;
$tr_height = 50;
$sl = 0;
$sr = $colcount - 1;
$sb = count($cell) - 1;
?>
<style>
.borderless td, .borderless th { border: none; }
.bg_a { background-image: url('<?php echo CM_URL?>/network/img/line1.gif'); }
.bg_b { background-image: url('<?php echo CM_URL?>/network/img/line0.gif'); }
.bg_c { background-image: url('<?php echo CM_URL?>/network/img/line2.gif'); }
.bg_d { background-image: url('<?php echo CM_URL?>/network/img/line3.gif'); }
.bg_e { background-image: url('<?php echo CM_URL?>/network/img/line00.gif'); }
.bg_f { background-image: url('<?php echo CM_URL?>/network/img/line4.gif'); }
.bg_g { background-image: url('<?php echo CM_URL?>/network/img/line5.gif'); }
.list-group-item-cm { padding: 0 !important; height: 22px !important; line-height: 22px !important; width: 68px !important; overflow: hidden; }
</style>
<div id="divName" class="" style="max-width: 99.99%; overflow-y: auto; padding: 10px 15px 150px 15px;">
    <div class="bg-white py-4 px-3 vh-100 rounded" style="overflow-x: auto;">
        <?php
        // 테이블 너비는 열 수에 따라 결정
        echo '<table class="borderless" style="margin: 0 auto; width: ' . (($sr + 1) * $td_width) . 'px !important;">';
        for ($j = 0; $j <= $sb; $j++) {
            if ($j % 2 == 0) {
                echo "<tr>";
            } else {
                echo "<tr height=" . ($tr_height / 2) . ">";
            }
            for ($i = 0; $i <= $sr; $i++) {
                $s = isset($cell[$j][$i]) ? $cell[$j][$i] : '';
                if ($s === '') {
                    echo "<td style='width: " . $td_width . "px; height: " . $tr_height . "'></td>";
                    continue;
                }

                $legtxt = explode("|", $s);
                $gugan = isset($legtxt[0]) ? $legtxt[0] : '';
                $user_id = isset($legtxt[3]) ? $legtxt[3] : '';

                if ($gugan === '') {
                    echo "<td style='width: " . $td_width . "px; height: " . $tr_height . "'></td>";
                    continue;
                }

                $user = get_member($user_id);
                $colors = "info";
                
                if ($gugan == "x" || $gugan == "o") {
                    echo "<td style='width: " . $td_width . "px; padding: 0;'>";
                    $divs = $td_width - 4;
                    $boxis = "";
                    $boxis .= "<div class='card border-" . $colors . " p-0 text-center' style='font-size: 11px; cursor: pointer;' onclick=\"net_mb_link('" . $user_id . "')\">";
                    $boxis .= "<div class='card-header bg-" . $colors . " text-white list-group-item-cm'>";
                    $boxis .= "<div class='px-1'>" . $user_id . "</div>";
                    $boxis .= "</div>";
                    $boxis .= "<ul class='list-group list-group-flush p-0 m-0'>";
                    $boxis .= "<li class='list-group-item list-group-item-cm'>";
                    $boxis .= "<div class='px-1'>" . ($user['user_name'] ?? '') . "</div>";
                    $boxis .= "</li>";
                    $boxis .= "<li class='list-group-item list-group-item-cm'>";
                    $boxis .= ($user['user_lv'] ?? '0') . ".Lv";
                    $boxis .= "</li>";
                    $boxis .= "<li class='list-group-item list-group-item-cm'>";
                    $boxis .= number_format($user['user_point'] ?? 0) . "P";
                    $boxis .= "</li>";
                    $boxis .= "</ul>";
                    $boxis .= "</div>";
                    echo $boxis;
                    echo "</td>";
                }
                if ($gugan == "a") { echo "<td class='bg_a'></td>"; }
                if ($gugan == "b") { echo "<td class='bg_b'></td>"; }
                if ($gugan == "c") { echo "<td class='bg_c'></td>"; }
                if ($gugan == "d") { echo "<td class='bg_d'></td>"; }
                if ($gugan == "e") { echo "<td class='bg_e'></td>"; }
                if ($gugan == "f") { echo "<td class='bg_f'></td>"; }
                if ($gugan == "g") { echo "<td class='bg_g'></td>"; }
            }
            echo "</tr>";
        }
        echo "</table>";
        ?>
    </div>
</div>