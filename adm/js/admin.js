

//게시판 그룹관련 생성,수정,삭제
function resetModal() {
    document.getElementById('groupForm').reset();
    document.getElementById('formMode').value = 'insert';
    document.getElementById('groupId').removeAttribute('readonly');
    document.getElementById('createBoardModalLabel').innerText = '새 그룹 만들기';
    document.getElementById('submitButton').innerText = '그룹 생성';
}

function editGroup(groupId, groupName) {
    document.getElementById('formMode').value = 'update';
    document.getElementById('groupId').value = groupId;
    document.getElementById('groupId').setAttribute('readonly', 'readonly');
    document.getElementById('groupName').value = groupName;
    document.getElementById('createBoardModalLabel').innerText = '그룹 수정';
    document.getElementById('submitButton').innerText = '수정 저장';
    new bootstrap.Modal(document.getElementById('createBoardModal')).show();
}

function deleteGroup(groupId, groupName) {
    if (confirm(`"${groupName}" 그룹을 정말 삭제하시겠습니까?`)) {
        fetch(CM.ADMIN_URL + '/board/board_group_form_update.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'action=delete&group_id=' + encodeURIComponent(groupId)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('그룹이 삭제되었습니다.');
                window.location.reload();
            } else {
                alert(data.error || '삭제 중 오류가 발생했습니다.');
            }
        })
        .catch(error => alert('삭제 중 오류가 발생했습니다.'));
    }
}

//게시판 관련 생성,수정,삭제
function resetModal() {
    document.getElementById('boardForm').reset();
    document.getElementById('formAction').value = 'insert';
    document.getElementById('boardId').removeAttribute('readonly');
    document.getElementById('createBoardModalLabel').innerText = '새 게시판 만들기';
    document.getElementById('submitButton').innerText = '게시판 생성';
}

function editBoard(boardId) {
    fetch(CM.ADMIN_URL + '/ajax/get_board_data.php?board_id=' + encodeURIComponent(boardId))
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert(data.error);
                return;
            }
            document.getElementById('formAction').value = 'update';
            document.getElementById('groupId').value = data.group_id;
            document.getElementById('boardId').value = data.board_id;
            document.getElementById('boardId').setAttribute('readonly', 'readonly');
            document.getElementById('boardName').value = data.board_name;
            document.getElementById('boardSkin').value = data.board_skin;
			document.getElementById('board_category').value = data.board_category;
            document.getElementById('write_lv').value = data.write_lv;
            document.getElementById('list_lv').value = data.list_lv;
            document.getElementById('view_lv').value = data.view_lv;
            document.getElementById('createBoardModalLabel').innerText = '게시판 수정';
            document.getElementById('submitButton').innerText = '수정 저장';
            new bootstrap.Modal(document.getElementById('createBoardModal')).show();
        })
        .catch(error => alert('데이터를 불러오는 중 오류가 발생했습니다.'));
}

function deleteBoard(boardId, boardName) {
    if (confirm(`게시판 "${boardName}"을(를) 정말 삭제하시겠습니까?`)) {
        fetch(CM.ADMIN_URL + '/board/board_form_update.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'action=delete&board_id=' + encodeURIComponent(boardId)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('게시판이 삭제되었습니다.');
                window.location.reload();
            } else {
                alert(data.error || '삭제 중 오류가 발생했습니다.');
            }
        })
        .catch(error => alert('삭제 중 오류가 발생했습니다.'));
    }
}

//내용관리 관련
function deleteContent(id, co_id) {
    if (confirm(`정말로 "${co_id}" 내용을 삭제하시겠습니까?`)) {
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = CM.ADMIN_URL + '/board/content_form_update.php';
        
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

// visit_list.php 삭제 확인 함수
function confirmVisitDelete() {
    if (confirm('정말로 삭제하시겠습니까?')) {
        const form = document.getElementById('searchForm');
        const deleteForm = document.createElement('form');
        deleteForm.method = 'POST';
        deleteForm.action = window.location.pathname;
        
        // 검색 폼의 모든 입력값을 복사
        const inputs = form.querySelectorAll('input');
        inputs.forEach(input => {
            const hiddenInput = document.createElement('input');
            hiddenInput.type = 'hidden';
            hiddenInput.name = input.name;
            hiddenInput.value = input.value;
            deleteForm.appendChild(hiddenInput);
        });
        
        // 삭제 액션 추가
        const actionInput = document.createElement('input');
        actionInput.type = 'hidden';
        actionInput.name = 'delete_by_date';
        actionInput.value = '1';
        deleteForm.appendChild(actionInput);
        
        document.body.appendChild(deleteForm);
        deleteForm.submit();
    }
}


//contact
function readChk(id) {
    if (confirm(`해당 문의를 읽음으로 처리하시겠습니까?`)) {
        fetch(CM.ADMIN_URL + '/config/contact_update.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'action=update&id=' + encodeURIComponent(id)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('읽음 처리 되었습니다.');
                window.location.reload();
            } else {
                alert(data.error || '처리 중 오류가 발생했습니다.');
            }
        })
        .catch(error => alert('처리 중 오류가 발생했습니다.'));
    }
}