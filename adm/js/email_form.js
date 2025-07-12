// 이메일 발송 폼 

document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('emailForm');
    const fileInput = document.getElementById('fileInput');
    const filePreview = document.getElementById('filePreview');
    
    // 수신자 타입 변경 이벤트
    const recipientRadios = document.querySelectorAll('input[name="recipient_type"]');
    const allMembersOption = document.getElementById('allMembersOption');
    const levelMembersOption = document.getElementById('levelMembersOption');
    const individualMembersOption = document.getElementById('individualMembersOption');
    
    recipientRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            // 모든 옵션 숨기기
            allMembersOption.style.display = 'none';
            levelMembersOption.style.display = 'none';
            individualMembersOption.style.display = 'none';
            
            // 선택된 옵션만 보이기
            switch(this.value) {
                case 'all':
                    allMembersOption.style.display = 'block';
                    break;
                case 'level':
                    levelMembersOption.style.display = 'block';
                    break;
                case 'individual':
                    individualMembersOption.style.display = 'block';
                    break;
            }
        });
    });
    
    

    // Quill 에디터 초기화
    let quill = null;
    const editorElement = document.getElementById('editor');
    if (editorElement) {
        const toolbarOptions = [
            [{ 'header': [1, 2, 3, 4, 5, 6, false] }],
            ['bold', 'italic', 'underline', 'strike'],
            [{ 'list': 'ordered'}, { 'list': 'bullet' }],
            [{ 'color': [] }, { 'background': [] }],
            ['link', 'image']
        ];
        
        quill = new Quill('#editor', {
            theme: 'snow',
            modules: {
                toolbar: toolbarOptions
            }
        });
    }

    // 폼 제출 시 에디터 내용을 hidden input에 설정
    form.addEventListener('submit', function(e) {
        const content = document.getElementById('content');
        if (quill) {
            content.value = quill.root.innerHTML;
        }
        
        // 수신자 수 확인
        const recipientType = document.querySelector('input[name="recipient_type"]:checked').value;
        let recipientCount = 0;
        
        if (recipientType === 'individual') {
            const emails = document.getElementById('individual_emails').value;
            const emailArray = emails.split(',').filter(email => email.trim() !== '');
            recipientCount = emailArray.length;
        } else {
            // 전체회원 또는 레벨별 회원의 경우 서버에서 확인
            recipientCount = '확인 중...';
        }
        
        if (recipientCount === 0 && recipientType === 'individual') {
            e.preventDefault();
            alert('수신자 이메일을 입력해주세요.');
            return;
        }
        
        // 발송 확인
        if (recipientType === 'all' || recipientType === 'level') {
            if (!confirm('선택한 회원들에게 이메일을 발송하시겠습니까?')) {
                e.preventDefault();
                return;
            }
        } else {
            if (!confirm(`${recipientCount}명에게 이메일을 발송하시겠습니까?`)) {
                e.preventDefault();
                return;
            }
        }
    });
    
    // 개별 회원 이메일 입력 시 실시간 수신자 수 표시
    const individualEmailsInput = document.getElementById('individual_emails');
    if (individualEmailsInput) {
        individualEmailsInput.addEventListener('input', function() {
            const emails = this.value;
            const emailArray = emails.split(',').filter(email => email.trim() !== '');
            const count = emailArray.length;
            
            // 수신자 수 표시 (옵션)
            let countDisplay = document.getElementById('recipientCount');
            if (!countDisplay) {
                countDisplay = document.createElement('small');
                countDisplay.id = 'recipientCount';
                countDisplay.className = 'text-muted';
                individualEmailsInput.parentNode.appendChild(countDisplay);
            }
            
            if (count > 0) {
                countDisplay.textContent = `수신자: ${count}명`;
                countDisplay.className = 'text-success';
            } else {
                countDisplay.textContent = '';
            }
        });
    }
    
    // 레벨 구간 유효성 검사
    const levelStartInput = document.getElementById('level_start');
    const levelEndInput = document.getElementById('level_end');
    
    if (levelStartInput && levelEndInput) {
        function validateLevelRange() {
            const startLevel = parseInt(levelStartInput.value);
            const endLevel = parseInt(levelEndInput.value);
            
            if (startLevel > endLevel) {
                levelEndInput.setCustomValidity('끝 레벨은 시작 레벨보다 크거나 같아야 합니다.');
                levelEndInput.reportValidity();
            } else {
                levelEndInput.setCustomValidity('');
            }
        }
        
        levelStartInput.addEventListener('input', validateLevelRange);
        levelEndInput.addEventListener('input', validateLevelRange);
    }
}); 