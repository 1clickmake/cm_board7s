// 게시글 작성, 파일 미리보기, Quill 에디터 + HTML 소스 보기/편집

document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('writeForm');
    const fileInput = document.getElementById('fileInput');
    const filePreview = document.getElementById('filePreview');
    
    // 파일 미리보기 기능
    fileInput.addEventListener('change', function(e) {
        filePreview.innerHTML = ''; // 기존 미리보기 초기화
        
        Array.from(e.target.files).forEach((file, index) => {
            const reader = new FileReader();
            const col = document.createElement('div');
            col.className = 'file-preview-item';
            
            reader.onload = function(e) {
                let previewContent = '';
                
                if (file.type.startsWith('image/')) {
                    // 이미지 파일인 경우
                    previewContent = `
                        <div class="preview-card">
                            <div class="preview-image-container">
                                <img src="${e.target.result}" class="preview-image">
                                <button type="button" class="delete-file-btn delete-file" data-index="${index}">
                                    <span class="delete-icon">×</span>
                                </button>
                            </div>
                            <div class="preview-info">
                                <h6 class="preview-title">${file.name}</h6>
                                <p class="preview-size">${(file.size / 1024).toFixed(2)} KB</p>
                            </div>
                        </div>`;
                } else {
                    // 이미지가 아닌 파일인 경우
                    const fileIcon = getFileIcon(file.type);
                    previewContent = `
                        <div class="preview-card">
                            <div class="preview-icon-container">
                                <i class="file-icon ${fileIcon}"></i>
                                <button type="button" class="delete-file-btn delete-file" data-index="${index}">
                                    <span class="delete-icon">×</span>
                                </button>
                            </div>
                            <div class="preview-info">
                                <h6 class="preview-title">${file.name}</h6>
                                <p class="preview-size">${(file.size / 1024).toFixed(2)} KB</p>
                            </div>
                        </div>`;
                }
                
                col.innerHTML = previewContent;
                filePreview.appendChild(col);
            };
            
            reader.readAsDataURL(file);
        });
    });
    
    // 파일 타입에 따른 아이콘 반환 함수
    function getFileIcon(fileType) {
        if (fileType.includes('pdf')) return 'file-pdf';
        if (fileType.includes('word') || fileType.includes('document')) return 'file-word';
        if (fileType.includes('excel') || fileType.includes('sheet')) return 'file-excel';
        if (fileType.includes('powerpoint') || fileType.includes('presentation')) return 'file-ppt';
        if (fileType.includes('zip') || fileType.includes('compressed')) return 'file-zip';
        return 'file-default';
    }
    
    // 파일 삭제 이벤트 처리
    filePreview.addEventListener('click', function(e) {
        if (e.target.closest('.delete-file')) {
            const deleteButton = e.target.closest('.delete-file');
            const index = parseInt(deleteButton.dataset.index);
            
            // DataTransfer 객체를 사용하여 파일 목록 업데이트
            const dt = new DataTransfer();
            const files = fileInput.files;
            
            for (let i = 0; i < files.length; i++) {
                if (i !== index) {
                    dt.items.add(files[i]);
                }
            }
            
            // 파일 input 업데이트
            fileInput.files = dt.files;
            
            // 미리보기 업데이트를 위해 change 이벤트 발생
            const event = new Event('change');
            fileInput.dispatchEvent(event);
        }
    });

    // Quill 에디터 + HTML 버튼
    const toolbarOptions = [
        [{ 'header': [1, 2, 3, 4, 5, 6, false] }],
        ['bold', 'italic', 'underline', 'strike'],
        [{ 'list': 'ordered'}, { 'list': 'bullet' }],
        [{ 'color': [] }, { 'background': [] }],
        ['link', 'image']
    ];
    const quill = new Quill('#editor', {
        theme: 'snow',
        modules: {
            toolbar: {
                container: toolbarOptions,
                handlers: {
                    html: function() {
                        showHtmlModal();
                    }
                }
            }
        }
    });

    // HTML 모달 생성
    function showHtmlModal() {
        let modal = document.getElementById('quill-html-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'quill-html-modal';
            modal.style.position = 'fixed';
            modal.style.top = '50%';
            modal.style.left = '50%';
            modal.style.transform = 'translate(-50%, -50%)';
            modal.style.background = '#fff';
            modal.style.border = '1px solid #ccc';
            modal.style.zIndex = '9999';
            modal.style.padding = '20px';
            modal.style.boxShadow = '0 2px 8px rgba(0,0,0,0.2)';
            modal.innerHTML = `
                <div style="margin-bottom:8px;font-weight:bold;">HTML 소스 편집</div>
                <textarea id="quill-html-source" style="width:400px;height:200px;"></textarea><br>
                <button id="quill-html-apply">적용</button>
                <button id="quill-html-cancel">닫기</button>
            `;
            document.body.appendChild(modal);
        }
        document.getElementById('quill-html-source').value = quill.root.innerHTML;
        modal.style.display = 'block';
        document.getElementById('quill-html-apply').onclick = function() {
            quill.root.innerHTML = document.getElementById('quill-html-source').value;
            modal.style.display = 'none';
        };
        document.getElementById('quill-html-cancel').onclick = function() {
            modal.style.display = 'none';
        };
    }

    // 툴바에 HTML 버튼(폰트어썸 fa-code) 우측에 추가
    const toolbar = quill.getModule('toolbar');
    const htmlBtn = document.createElement('button');
    htmlBtn.type = 'button';
    htmlBtn.title = 'HTML';
    htmlBtn.innerHTML = '<i class="fa fa-code"></i>';
    htmlBtn.onclick = showHtmlModal;
    // 툴바 가장 마지막에 추가
    const toolbarElem = quill.container.previousSibling;
    if (toolbarElem && toolbarElem.classList.contains('ql-toolbar')) {
        let lastFormats = toolbarElem.querySelectorAll('.ql-formats');
        let lastGroup = lastFormats[lastFormats.length - 1];
        // 새 그룹 생성해서 마지막에 붙임
        const group = document.createElement('span');
        group.className = 'ql-formats';
        group.appendChild(htmlBtn);
        toolbarElem.appendChild(group);
    }

    // 이미지 업로드 핸들러
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
                formData.append('board_id', document.querySelector('input[name="board_id"]').value);

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
                        alert('이미지 업로드 실패: ' + (data.error || '오류'));
                    }
                } catch (error) {
                    alert('이미지 업로드 실패: ' + error.message);
                }
            }
        };
    });

    // 폼 제출 시 에디터 내용을 hidden input에 설정
    form.addEventListener('submit', function(e) {
        const content = document.querySelector('input[name="content"]');
        content.value = quill.root.innerHTML;
    });

    if(recaptcha_site && recaptcha_secret){
        form.addEventListener('submit', function (e) {
            e.preventDefault(); // 폼 제출 막기
            grecaptcha.ready(function() {
                grecaptcha.execute(recaptchaSiteKey, {action: 'submit'}).then(function(token) {
                    document.getElementById('g-recaptcha-response').value = token;
                    form.submit(); // 토큰 설정 후 폼 제출
                });
            });
        });
    }

    // 태그 입력 및 표시 기능
    const tagInput = document.getElementById('tags');
    const tagListDiv = document.getElementById('tagList');
    let tags = [];

    if (tagInput && tagListDiv) {
        // 기존 값이 있으면 초기화
        if (tagInput.value.trim() !== '') {
            tags = tagInput.value.split(',').map(t => t.trim()).filter(t => t);
            renderTags();
        }

        tagInput.addEventListener('keydown', function(e) {
            if (e.key === ' ' || e.key === 'Spacebar') {
                e.preventDefault();
                const value = tagInput.value.trim();
                if (value && !tags.includes(value)) {
                    tags.push(value);
                    renderTags();
                }
                tagInput.value = '';
            } else if (e.key === 'Backspace' && tagInput.value === '') {
                // 입력창이 비어있고 백스페이스 누르면 마지막 태그 삭제
                tags.pop();
                renderTags();
            }
        });

        function renderTags() {
            tagListDiv.innerHTML = '';
            tags.forEach((tag, idx) => {
                const tagEl = document.createElement('span');
                tagEl.className = 'tag-badge';
                tagEl.textContent = tag;
                // X 버튼
                const removeBtn = document.createElement('button');
                removeBtn.type = 'button';
                removeBtn.className = 'tag-remove-btn';
                removeBtn.innerHTML = '&times;';
                removeBtn.onclick = function() {
                    tags.splice(idx, 1);
                    renderTags();
                };
                tagEl.appendChild(removeBtn);
                tagListDiv.appendChild(tagEl);
            });
            tagInput.value = tags.join(',');
        }

        // form submit 시 쉼표로 연결
        tagInput.form && tagInput.form.addEventListener('submit', function() {
            tagInput.value = tags.join(',');
        });
    }
});