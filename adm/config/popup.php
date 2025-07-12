<?php
/**
 * 팝업레이어 출력 함수
 * index.php 파일에 포함시켜 사용
 */
function display_popups() {
    global $pdo;
    
    // 오늘 날짜
    $today = date('Y-m-d');
    
    try {
        // 활성화된 팝업 조회
        $sql = "SELECT * FROM cm_popup 
                WHERE po_use = 1 
                AND po_start_date <= :today
                AND po_end_date >= :today
                ORDER BY po_id DESC";
        
        $stmt = $pdo->prepare($sql);
        $stmt->bindParam(':today', $today);
        $stmt->execute();
        $popups = $stmt->fetchAll();
        
        if (empty($popups)) {
            return;
        }
        
        // CSS 및 스크립트 출력
        echo '<style>
        .popup-layer {
            position: absolute;
            z-index: 9999;
            background: #fff;
            border: none;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
            display: none;
           
            transition: all 0.3s ease;
        }
        .popup-header {
            background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%);
            padding: 12px 15px;
            color: #fff;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: move; /* 이동 커서 추가 */
        }
        .popup-title {
            font-weight: bold;
            margin: 0;
            font-size: 16px;
            text-shadow: 0 1px 2px rgba(0,0,0,0.2);
        }
        .popup-close {
            cursor: pointer;
            font-size: 20px;
            line-height: 1;
            color: rgba(255,255,255,0.8);
            transition: all 0.2s ease;
            width: 24px;
            height: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
        }
        .popup-close:hover {
            background-color: rgba(255,255,255,0.2);
            color: #fff;
        }
        .popup-content {
            padding: 10px;
            overflow-y: auto;
            background-color: #fff;
            color: #333;
            line-height: 1.5;
        }
		
		.popup-content img{
			max-width: 100%;
			height: auto;
		}
		
        .popup-footer {
			padding: 7px 20px; /* Increased padding for more space */
			min-height: 50px; /* Added minimum height to ensure text fits */
			background: #333;
			color:#fff;
			border-top: 1px solid #eaeaea;
			display: flex;
			justify-content: space-between;
			align-items: center;
			line-height: 1.6; /* Adjusted line height for better text rendering */
			box-sizing: border-box; /* Ensure padding is included in height calculations */
		}
        .popup-today-close {
            cursor: pointer;
            font-size: 13px;
            color: #555;
            display: flex;
            align-items: center;
        }
        .popup-today-close input[type="checkbox"] {
            margin-right: 5px;
        }
        .popup-btn .btn {
            padding: 5px 12px;
            border-radius: 4px;
            font-size: 13px;
            font-weight: 500;
            transition: all 0.2s ease;
        }
        .popup-btn .btn-secondary {
            background-color: #6c757d;
            border-color: #6c757d;
        }
        .popup-btn .btn-secondary:hover {
            background-color: #5a6268;
            border-color: #545b62;
        }
        </style>';
        
        // 팝업 HTML 출력
        foreach ($popups as $popup) {
            $po_id = $popup['po_id'];
            $popup_cookie = 'popup_' . $po_id;
            
            // 쿠키 체크
            if (isset($_COOKIE[$popup_cookie])) {
                continue;
            }
            
            $po_title = htmlspecialchars($popup['po_title']);
            $po_content = $popup['po_content'];
            $po_top = intval($popup['po_top']);
            $po_left = intval($popup['po_left']);
            $po_width = intval($popup['po_width']);
            $po_height = intval($popup['po_height']);
            $po_url = $popup['po_url'];
            $po_target = $popup['po_target'];
            $po_cookie_time = intval($popup['po_cookie_time']);
            
            // 팝업 내용 높이 (헤더, 푸터 높이 제외)
            $content_height = $po_height - 80;
            
            echo '<div id="popup_' . $po_id . '" class="popup-layer" style="width: ' . $po_width . 'px; height: ' . $po_height . 'px; top: ' . $po_top . 'px; left: ' . $po_left . 'px;">
                <div class="popup-header">
                    <h5 class="popup-title">' . $po_title . '</h5>
                    <span class="popup-close" onclick="closePopup(' . $po_id . ')">&times;</span>
                </div>
                <div class="popup-content" style="height: ' . $content_height . 'px;">';
            
            if (!empty($po_url)) {
                echo '<div onclick="openPopupUrl(' . $po_id . ')" style="cursor:pointer;">';
            }
            
            echo $po_content;
            
            if (!empty($po_url)) {
                echo '</div>';
            }
            
            echo '</div>
                <div class="popup-footer">
                    <div class="popup-today-close">
                        <input type="checkbox" id="chk_today_' . $po_id . '"> 
                        <label class="text-light" for="chk_today_' . $po_id . '">' . $po_cookie_time . '시간 동안 보지 않기</label>
                    </div>
                    <div class="popup-btn">
                        <button type="button" class="btn btn-sm btn-secondary" onclick="closePopup(' . $po_id . ')">닫기</button>
                    </div>
                </div>
            </div>';
            
            // URL 저장
            if (!empty($po_url)) {
                // JavaScript 변수 생성 시 json_encode를 사용하여 안전하게 처리
                echo '<script>';
                echo 'if (typeof popupsData === "undefined") { var popupsData = {}; }';
                echo 'popupsData[' . $po_id . '] = { url: ' . json_encode($po_url) . ', target: ' . json_encode($po_target) . ' };';
                echo '</script>';
            }
        }
        
        // 공통 자바스크립트
        echo '<script>
        $(document).ready(function() {
            if (typeof popupsData === "undefined") { // popupsData가 정의되지 않았을 경우를 대비
                window.popupsData = {};
            }
            $(".popup-layer").show();
            
            // 드래그 가능하도록 설정
            $(".popup-layer").draggable({
                handle: ".popup-header",
                containment: "window",
                start: function() {
                    $(this).css("opacity", "0.8");
                },
                stop: function() {
                    $(this).css("opacity", "1");
                }
            });
            
            // 체크박스 이벤트
            $(".popup-today-close input[type=checkbox]").on("change", function() {
                var id = $(this).attr("id").replace("chk_today_", "");
                var hours = $(this).next("label").text().replace(/[^0-9]/g, "");
                if($(this).is(":checked")) {
                    setPopupCookie(id, hours);
                }
            });
        });
        
        // 팝업 닫기
        function closePopup(id) {
            $("#popup_" + id).fadeOut(300);
        }
        
        // URL 열기
        function openPopupUrl(id) {
            var popupData = popupsData[id];
            
            if (popupData && popupData.url) {
                window.open(popupData.url, popupData.target);
            }
        }
        
        // 오늘 하루 보지 않기
        function setPopupCookie(id, hours) {
            var expires = new Date();
            expires.setTime(expires.getTime() + (hours * 60 * 60 * 1000));
            document.cookie = "popup_" + id + "=1; expires=" + expires.toUTCString() + "; path=/";
            $("#popup_" + id).fadeOut(300);
        }
        </script>';
        
    } catch (PDOException $e) {
        error_log('팝업 표시 중 오류 발생: ' . $e->getMessage());
        return;
    }
}

/**
 * index.php 파일에서 아래와 같이 사용하면 됩니다:
 * 
 * <?php
 * include_once './_common.php';
 * include_once './popup.php';  // 이 파일을 팝업 함수 파일로 저장
 * include_once './header.php';
 * ?>
 * 
 * <body>
 * <?php display_popups(); // 팝업 표시 함수 호출 ?>
 * 
 * ... 나머지 index.php 내용 ...
 * 
 * <?php include_once './footer.php'; ?>
 * </body>
 */
?>