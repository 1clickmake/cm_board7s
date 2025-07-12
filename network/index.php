<?php
include_once("./_common.php");

$cm_title = '추천레그';
include_once(CM_PATH.'/head.php');
$legUrl = "./tree.php";

if (isset($_GET['uid']) && $_GET['uid']) {
	$uid = $_GET['uid'];
    $legUrl .= "?uid=" . $_GET['uid'];
}
?>
<div class="content-wrapper">
    <div class="row">
        <div class="col-12 grid-margin stretch-card">
            <div class="card bg-skin1">
                <div class="card-body fs-4 py-2 px-0 px-sm-3 text-light">
                    <?php echo $cm_title ?>
                </div>
            </div>
        </div>
    </div>

    <div class="alert alert-danger py-2 text-13" role="alert">
        빨간색으로 표시된 회원은 현재 구독중인 회원입니다
    </div>
    <form name="fsearch" id="fsearch" class="local_sch01 local_sch" method="get">
        <div class="border-container shadow table-responsive mb-3">
            <table class="table table-bordered table-small table-dark mb-0 align-middle" style="min-width:1200px;">
                <tr>
                    <td class="text-center">
                        <div class="input-group">
                            <input type="text" name="uid" value="<?php echo $uid ?? '';?>" class="form-control border" placeholder="회원아이디" aria-label="회원아이디" aria-describedby="button-addon2">
                            <button class="btn btn-outline-light" type="submit" id="button-addon2">검색</button>
                            <button type="button" class="btn btn-outline-light" onclick="javascript:history.back();">뒤로</button>
                        </div>
                    </td>
                </tr>
            </table>
        </div>
    </form>

    <div id="zoombox" class="mb-3 px-3">
        <button id="btn_ZoomReset" class="zoombtn btn btn-light"><i class="fa fa-retweet" aria-hidden="true"></i></button>
        <button id="btn_ZoomOut" class="zoombtn btn btn-light"><i class="fa fa-minus" aria-hidden="true"></i></button>
        <button id="btn_ZoomIn" class="zoombtn btn btn-light"><i class="fa fa-plus" aria-hidden="true"></i></button>
    </div>

    <div class="border-container shadow table-responsive">
        <div class="leg"></div>
    </div>
</div>
<script>
jQuery(function(){
    $('.leg').load("./<?php echo $legUrl?>", {
        url: '<?php echo $_SERVER['PHP_SELF'];?>'
    });
});
</script>
<script>
var currentZoom = 1.0;
$(document).ready(function () {
    $('#btn_ZoomIn').click(function(){
        $('.leg').css({ 'zoom': currentZoom += 0.1 });
    });
    $('#btn_ZoomOut').click(function(){
        $('.leg').css({ 'zoom': currentZoom -= 0.1 });
    });
    $('#btn_ZoomReset').click(function(){
        currentZoom = 1.0;
        $('.leg').css({ 'zoom': 1 });
    });
});
</script>
<?php
include_once(CM_PATH.'/tail.php');
?>