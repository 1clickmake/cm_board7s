<?php
include_once './_common.php';
$cm_title = "내용관리";
include_once CM_ADMIN_PATH.'/admin.head.php';

// 초기화
$mode = 'insert';
$content = [
    'id' => '',
    'co_id' => '',
    'co_subject' => '',
    'co_content' => '',
    'co_editor' => 0,
    'co_width' => 1
];

// 수정 모드인 경우 데이터 가져오기
if (isset($_GET['id']) && !empty($_GET['id'])) {
    $id = intval($_GET['id']);
    $mode = 'update';
    
    try {
        $sql = "SELECT * FROM cm_content WHERE id = :id";
        $stmt = $pdo->prepare($sql);
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->execute();
        
        if ($row = $stmt->fetch()) {
            $content = $row;
        } else {
            echo '<script>alert("존재하지 않는 내용입니다."); location.href="content_list.php";</script>';
            exit;
        }
    } catch (PDOException $e) {
        echo '<div class="alert alert-danger">데이터 조회 중 오류가 발생했습니다: ' . $e->getMessage() . '</div>';
    }
}
?>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.56.0/codemirror.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.56.0/theme/eclipse.css">

<!-- Main Content -->
<div class="main-content shifted" id="mainContent">
    <div class="container-fluid">

		<!-- 헤더 카드 -->
            <div class="card shadow-sm mb-4 border-0 card-move">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h2 class="card-title mb-1 text-primary">
                                <i class="fas fa-window-restore me-2"></i><?php echo $cm_title;?>
                            </h2>
                            <p class="card-text text-muted mb-0">페이지를 추가 / 관리 / 설정할 수 있습니다.</p>
                        </div>
                        <div>
                            <a href="content_list.php" class="btn btn-primary btn-lg shadow-sm">
                                <i class="fas fa-list me-2"></i>목록으로
                            </a>
                        </div>
                    </div>
                </div>
            </div>

        <div class="row">
            <div class="col-12">
                <div class="card shadow-sm">
                    <div class="card-header bg-light">
                        <h5 class="card-title mb-0">
                            <i class="fas fa-cog me-2"></i>
                            내용 설정
                        </h5>
                    </div>
                    <div class="card-body p-4">
                        <form name="frmcontentform" action="./content_form_update.php" onsubmit="return frmcontentform_check(this);" method="post">
                            <input type="hidden" name="w" value="<?php echo $mode; ?>">
                            <input type="hidden" name="id" value="<?php echo $content['id']; ?>">
                            
                            <div class="mb-3">
                                <label for="co_id" class="form-label">ID</label>
                                <div class="input-group">
                                    <input type="text" class="form-control" id="co_id" name="co_id" value="<?php echo htmlspecialchars($content['co_id'], ENT_QUOTES, 'UTF-8'); ?>" required readonly>
                                    <?php if (!empty($content['co_id'])) { ?>
                                    <a href="<?php echo CM_URL?>/content/content.php?co_id=<?php echo urlencode($content['co_id']); ?>" class="btn btn-outline-secondary" id="checkIdBtn" target="_blank">내용확인</a>
                                    <?php } ?>
                                </div>
                                <div class="form-text">
                                    <i class="fas fa-info-circle me-1"></i>
                                    ID는 영문 또는 숫자만 입력 가능하며, 10단위로 자동 생성됩니다.
                                </div>
                                <div id="idCheckResult" class="form-text mt-1"></div>
                            </div>

                            <div class="mb-3">
                                <label for="co_subject" class="form-label">제목</label>
                                <input type="text" class="form-control" id="co_subject" name="co_subject" value="<?php echo $content['co_subject']; ?>" required>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">에디터 선택</label>
                                <div class="form-check form-check-inline">
                                    <input class="form-check-input" type="radio" name="co_editor" id="co_editor0" value="0" <?php echo ($content['co_editor'] == 0) ? 'checked' : ''; ?>>
                                    <label class="form-check-label" for="co_editor0">기본에디터</label>
                                </div>
                                <div class="form-check form-check-inline">
                                    <input class="form-check-input" type="radio" name="co_editor" id="co_editor1" value="1" <?php echo ($content['co_editor'] == 1) ? 'checked' : ''; ?>>
                                    <label class="form-check-label" for="co_editor1">개발자용에디터</label>
                                </div>
                            </div>

                            <div class="mb-3 co_content_html">
                                <label for="co_content" class="form-label">내용</label>
                                <div class="border rounded p-2">
                                    <div id="editor" style="height: 300px;"><?php echo $content['co_content']; ?></div>
                                    <input type="hidden" name="co_content" value="<?php echo htmlspecialchars($content['co_content']); ?>">
                                </div>
                            </div>

                            <div class="mb-3 co_add_html" style="display: none;">
                                <label for="co_add_html" class="form-label">개발자용 에디터</label>
                                <div class="alert alert-warning mb-2">
                                    <i class="fas fa-exclamation-triangle me-2"></i>
                                    기본에디터로 원하는 기능을 구현하지 못할 경우 개발자용 에디터에서 <span class="text-primary fw-bold">HTML+PHP+JS+CSS</span> 등 언어로 페이지 개발을 할수 있습니다.
                                    <br>
                                    <span class="text-danger">작성한 소스의 오류시 사이트에 심각한 에러가 발생할 수 있으니 주의해서 작성해 주시길 바랍니다.</span>
                                </div>
                                <textarea id="co_add_html" rows="10" class="form-control"><?php echo $content['co_content']; ?></textarea>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">레이아웃 설정</label>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" name="co_width" id="co_width" value="1" <?php echo ($content['co_width'] == 1) ? 'checked' : ''; ?>>
                                    <label class="form-check-label" for="co_width">
                                        전체 너비 사용 (width: 100%)
                                    </label>
                                </div>
                            </div>

                            <div class="d-flex justify-content-end gap-2 mt-4">
                                <a href="content_list.php" class="btn btn-secondary">
                                    <i class="fas fa-list me-2"></i>목록
                                </a>
                                <?php if ($mode == 'update') { ?>
                                <button type="button" class="btn btn-danger" onclick="deleteContent(<?php echo $content['id'];?>, '<?php echo htmlspecialchars($content['co_id']);?>')">
                                    <i class="fas fa-trash-alt me-2"></i>삭제
                                </button>
                                <?php } ?>
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-save me-2"></i>저장
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.56.0/codemirror.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.56.0/addon/edit/matchbrackets.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.56.0/mode/htmlmixed/htmlmixed.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.56.0/mode/xml/xml.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.56.0/mode/javascript/javascript.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.56.0/mode/css/css.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.56.0/mode/clike/clike.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.56.0/mode/php/php.js"></script>

<script>
document.addEventListener('DOMContentLoaded', function() {
    // 수정 모드 여부 확인
    const isEditMode = <?php echo isset($_GET['id']) ? 'true' : 'false'; ?>;
    
    // ID 중복 체크 함수
    function checkIdDuplicate(co_id) {
        if (!co_id || isEditMode) return; // 수정 모드일 경우 중복 체크 하지 않음
        
        fetch('<?php echo CM_ADMIN_URL;?>/ajax/check_content_id.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'co_id=' + encodeURIComponent(co_id)
        })
        .then(response => response.json())
        .then(response => {
            const resultDiv = document.getElementById('idCheckResult');
            if (response.exists) {
                resultDiv.innerHTML = '<span class="text-danger"><i class="fas fa-times-circle me-1"></i>이미 사용 중인 ID입니다.</span>';
                document.getElementById('co_id').classList.add('is-invalid');
            } else {
                resultDiv.innerHTML = '<span class="text-success"><i class="fas fa-check-circle me-1"></i>사용 가능한 ID입니다.</span>';
                document.getElementById('co_id').classList.remove('is-invalid');
                document.getElementById('co_id').classList.add('is-valid');
            }
        })
        .catch(() => {
            document.getElementById('idCheckResult').innerHTML = '<span class="text-danger"><i class="fas fa-exclamation-circle me-1"></i>ID 확인 중 오류가 발생했습니다.</span>';
        });
    }

    // ID 자동 생성 함수
    function generateNextId() {
        if (isEditMode) return; // 수정 모드일 경우 자동 생성 하지 않음
        
        fetch('<?php echo CM_ADMIN_URL;?>/ajax/get_next_content_id.php')
        .then(response => response.json())
        .then(response => {
            if(response.success) {
                document.getElementById('co_id').value = response.next_id;
                checkIdDuplicate(response.next_id);
            } else {
                alert('ID 생성 중 오류가 발생했습니다.');
            }
        })
        .catch(() => {
            alert('서버 통신 중 오류가 발생했습니다.');
        });
    }

    // 페이지 로드 시 ID가 비어있으면 자동 생성
    if(document.getElementById('co_id').value === '' && !isEditMode) {
        generateNextId();
    } else if (!isEditMode) {
        // 신규 등록 모드일 경우에만 중복 체크
        checkIdDuplicate(document.getElementById('co_id').value);
    }

    // Quill 에디터 초기화
    const quill = new Quill('#editor', {
        theme: 'snow',
        modules: {
            toolbar: [
                [{ 'header': [1, 2, 3, 4, 5, 6, false] }],
                ['bold', 'italic', 'underline', 'strike'],
                [{ 'color': [] }, { 'background': [] }],
                [{ 'align': [] }],
                ['link', 'image'],
                ['clean']
            ]
        },
        placeholder: '내용을 입력하세요...'
    });

    // 이미지 업로드 핸들러
    const toolbar = quill.getModule('toolbar');
    toolbar.addHandler('image', function() {
        const input = document.createElement('input');
        input.setAttribute('type', 'file');
        input.setAttribute('accept', 'image/*');
        input.click();

        input.onchange = async function() {
            const file = input.files[0];
            if (file) {
                const formData = new FormData();
                formData.append('image', file);
                formData.append('board_id', 'content');

                try {
                    const response = await fetch(CM.LIB_URL + '/quill_upload.php', {
                        method: 'POST',
                        body: formData
                    });
                    const data = await response.json();
                    
                    if (data.url) {
                        const range = quill.getSelection(true);
                        quill.insertEmbed(range.index, 'image', data.url);
                    } else {
                        alert('이미지 업로드 실패: ' + (data.error || '알 수 없는 오류'));
                    }
                } catch (error) {
                    alert('이미지 업로드 실패: ' + error.message);
                }
            }
        };
    });

    // Quill 에디터 내용 변경 이벤트
    quill.on('text-change', function() {
        document.querySelector('input[name="co_content"]').value = quill.root.innerHTML;
    });

    // CodeMirror 에디터 초기화
    var editor = CodeMirror.fromTextArea(document.getElementById("co_add_html"), {
        theme: "eclipse",
        lineNumbers: true,
        matchBrackets: true,
        mode: "application/x-httpd-php",
        indentUnit: 4,
        indentWithTabs: true,
        lineWrapping: true,
        extraKeys: {"Ctrl-Space": "autocomplete"},
        autoCloseBrackets: true,
        matchBrackets: true,
        indentWithTabs: true,
        smartIndent: true,
        tabSize: 4,
        lineNumbers: true,
        foldGutter: true,
        gutters: ["CodeMirror-linenumbers", "CodeMirror-foldgutter"]
    });

    // 에디터 초기 상태 설정
    <?php if($content['co_editor'] == 1) { ?>
        document.querySelector('.co_add_html').style.display = 'block';
        document.querySelector('.co_content_html').style.display = 'none';
        // 개발자용 에디터에 기존 내용 설정
        setTimeout(function() {
            editor.setValue(<?php echo json_encode($content['co_content']); ?>);
            editor.refresh();
            // 초기 내용을 hidden input에 설정
            document.querySelector('input[name="co_content"]').value = <?php echo json_encode($content['co_content']); ?>;
        }, 100);
    <?php } else { ?>
        document.querySelector('.co_content_html').style.display = 'block';
        document.querySelector('.co_add_html').style.display = 'none';
        // Quill에 기존 내용 설정
        quill.root.innerHTML = <?php echo json_encode($content['co_content']); ?>;
        // 초기 내용을 hidden input에 설정
        document.querySelector('input[name="co_content"]').value = <?php echo json_encode($content['co_content']); ?>;
    <?php } ?>

    // 라디오 버튼 변경 이벤트
    document.querySelectorAll('input[name="co_editor"]').forEach(radio => {
        radio.addEventListener('change', function() {
            if(this.value == '0') {
                document.querySelector('.co_content_html').style.display = 'block';
                document.querySelector('.co_add_html').style.display = 'none';
                // 개발자용 에디터의 내용을 Quill로 복사
                const editorContent = editor.getValue();
                quill.root.innerHTML = editorContent;
                document.querySelector('input[name="co_content"]').value = editorContent;
            } else {
                document.querySelector('.co_content_html').style.display = 'none';
                document.querySelector('.co_add_html').style.display = 'block';
                // Quill의 내용을 개발자용 에디터로 복사
                const quillContent = quill.root.innerHTML;
                setTimeout(function() {
                    editor.setValue(quillContent);
                    editor.refresh();
                    document.querySelector('input[name="co_content"]').value = quillContent;
                }, 100);
            }
        });
    });

    // CodeMirror 에디터 내용 변경 이벤트
    editor.on('change', function() {
        const content = editor.getValue();
        document.querySelector('input[name="co_content"]').value = content;
    });

    // 폼 제출 전 내용 확인
    document.querySelector('form[name="frmcontentform"]').addEventListener('submit', function(e) {
        if (document.querySelector('input[name="co_editor"]:checked').value == '0') {
            const content = quill.root.innerHTML.trim();
            if (!content) {
                alert("내용을 입력하세요.");
                quill.focus();
                e.preventDefault();
                return false;
            }
            document.querySelector('input[name="co_content"]').value = content;
        } else {
            const content = editor.getValue().trim();
            if (!content) {
                alert("내용을 입력하세요.");
                editor.focus();
                e.preventDefault();
                return false;
            }
            document.querySelector('input[name="co_content"]').value = content;
        }
        return true;
    });

    // 창 크기 변경 시 에디터 리프레시
    window.addEventListener('resize', function() {
        editor.refresh();
    });
});

function frmcontentform_check(f) {
    if (!f.co_id.value) {
        alert("ID를 입력하세요.");
        f.co_id.focus();
        return false;
    }

    // 신규 등록 모드일 경우에만 ID 중복 체크
    if (!isEditMode) {
        const idCheckResult = document.getElementById('idCheckResult').textContent;
        if (idCheckResult.includes('이미 사용 중인 ID입니다')) {
            alert("이미 사용 중인 ID입니다. 다른 ID를 사용해주세요.");
            f.co_id.focus();
            return false;
        }
    }

    if (!f.co_subject.value) {
        alert("제목을 입력하세요.");
        f.co_subject.focus();
        return false;
    }
    
    // 에디터 타입에 따른 내용 검증
    if (f.co_editor[0].checked) { // 기본 에디터
        const content = quill.root.innerHTML.trim();
        if (!content) {
            alert("내용을 입력하세요.");
            quill.focus();
            return false;
        }
        // Quill 내용을 hidden input에 복사
        f.co_content.value = content;
    } else { // 개발자용 에디터
        const editorContent = editor.getValue().trim();
        if (!editorContent) {
            alert("내용을 입력하세요.");
            editor.focus();
            return false;
        }
        // CodeMirror 내용을 hidden input에 복사
        f.co_content.value = editorContent;
    }
    return true;
}

function deleteContent(id, co_id) {
    if (confirm(`정말로 "${co_id}" 내용을 삭제하시겠습니까?`)) {
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = 'content_form_update.php';
        
        const wInput = document.createElement('input');
        wInput.type = 'hidden';
        wInput.name = 'w';
        wInput.value = 'delete';
        
        const idInput = document.createElement('input');
        idInput.type = 'hidden';
        idInput.name = 'id';
        idInput.value = id;
        
        form.appendChild(wInput);
        form.appendChild(idInput);
        document.body.appendChild(form);
        form.submit();
    }
}
</script>

<?php
include_once CM_ADMIN_PATH.'/admin.tail.php';
?>