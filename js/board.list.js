// 게시판 리스트

function toggleAllCheckBoxes(source) {
    const checkboxes = document.getElementsByName('selected_posts[]');
    for(let i=0; i < checkboxes.length; i++) {
        checkboxes[i].checked = source.checked;
    }
}

function confirmDeleteSelected() {
    const checkedCount = document.querySelectorAll('input[name="selected_posts[]"]:checked').length;
    if (checkedCount === 0) {
        alert('삭제할 게시물을 선택하세요.');
        return false;
    }
    return confirm(checkedCount + '개 게시물 삭제?\n삭제된 데이터는 복구 불가.');
}
