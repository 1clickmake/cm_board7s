//board view 관련 js

/*패스워스 입력폼 이동*/
function boardToPass(btnVal, board_id, board_num) {
    const actValue = btnVal.value;
    const targetUrl = CM.BOARD_URL + '/password.php?act='+actValue+'&board='+board_id+'&id='+board_num;
    window.location.href = targetUrl;
}

document.addEventListener('DOMContentLoaded', function() {
    const confirmPasswordButton = document.getElementById('confirmPassword');
    if (confirmPasswordButton) {
        confirmPasswordButton.addEventListener('click', function() {
            showLoadingSpinner();
            const email = document.getElementById('checkEmail').value;
            const password = document.getElementById('checkPassword').value;
            const action = document.getElementById('actionType').value;
            const board_id = boardId;
            const board_num = boardNum;
            if (!is_member) {
                if (!email.trim()) {
                    document.getElementById('emailError').textContent = '이메일 입력';
                    document.getElementById('checkEmail').focus();
                    return;
                }
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailRegex.test(email)) {
                    document.getElementById('emailError').textContent = '이메일 형식 확인';
                    document.getElementById('checkEmail').focus();
                    return;
                }
            }
            if (!password.trim()) {
                document.getElementById('passwordError').textContent = '비밀번호 입력';
                document.getElementById('checkPassword').focus();
                return;
            }
            fetch(CM.BOARD_URL + '/check_password.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: new URLSearchParams({board_id, board_num, email, password})
            })
            .then(response => response.json())
            .then(data => {
                hideLoadingSpinner();
                if (data.status === 'success') {
                    if (action === 'edit') {
                        window.location.href = CM.BOARD_URL + '/edit.php?board=' + board_id + '&id=' + board_num;
                    } else {
                        if (confirm('정말 삭제하시겠습니까?')) {
                            window.location.href = CM.BOARD_URL + '/delete.php?board=' + board_id + '&id=' + board_num;
                        }
                    }
                } else {
                    if (data.field === 'email') {
                        document.getElementById('emailError').textContent = data.message;
                        document.getElementById('checkEmail').focus();
                    } else {
                        document.getElementById('passwordError').textContent = data.message || '비밀번호 불일치';
                        document.getElementById('checkPassword').focus();
                    }
                }
            })
            .catch(() => {
                document.getElementById('passwordError').textContent = '서버 오류. 다시 시도.';
            });
        });
    }

    const deleteButton = document.getElementById('deletePostButton');
    if (deleteButton) {
        deleteButton.addEventListener('click', function(e) {
            e.preventDefault();
            if (confirm('정말 삭제하시겠습니까?')) {
                window.location.href = CM.BOARD_URL + '/delete.php?board=' + boardId + '&id=' + boardNum;
            }
        });
    }

	if(comment_chk == 1){
		// Quill 에디터 초기화
		const quill = new Quill('#editor', {
			theme: 'snow',
			modules: {
				toolbar: [
					['bold', 'italic', 'underline'],
					[{ 'color': [] }],
					[{ 'list': 'ordered'}, { 'list': 'bullet' }],
					['link', 'image'],
					['clean']
				]
			}
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
							alert('이미지 업로드 실패: ' + (data.error || '알 수 없는 오류'));
						}
					} catch (error) {
						alert('이미지 업로드 실패: ' + error.message);
					}
				}
			};
		});

		// 코멘트 수정
		document.querySelectorAll('.edit-comment').forEach(button => {
			button.addEventListener('click', function() {
				const commentId = this.dataset.commentId;
				const content = document.getElementById('comment-content-' + commentId).innerHTML;
				quill.root.innerHTML = content;
				document.querySelector('input[name="comment_id"]').value = commentId;
				document.querySelector('input[name="act"]').value = 'edit';
				document.querySelector('button[type="submit"]').textContent = '댓글 수정';
				document.getElementById('commentForm').scrollIntoView({ behavior: 'smooth' });
			});
		});

		// 코멘트 폼 제출
		document.getElementById('commentForm').addEventListener('submit', function(e) {
			
			//스피너 시작
			showLoadingSpinner();
			
			e.preventDefault();

			const content = document.querySelector('input[name="content"]');
			content.value = quill.root.innerHTML;
			
			const formData = new FormData(this);

			fetch(this.action, {
				method: 'POST',
				body: formData
			})
			.then(response => response.json())
			.then(data => {
				
				//스피너 종료
				hideLoadingSpinner();
				
				if (data.status === 'success') {
					const timestamp = new Date().getTime();
					const targetUrl = CM.BOARD_URL + '/view.php?board=' + boardId + '&id=' + boardNum + '&comment_page=1&_t=' + timestamp + '#cmtId' + data.comment_id;
					window.location.href = targetUrl;
				} else {
					alert(data.message || '댓글 등록에 실패했습니다.');
				}
			})
			.catch(error => {
				console.error('Error:', error);
				alert('서버 오류가 발생했습니다.');
			});
		});

		// 폼 초기화 함수
		function resetCommentForm() {
			quill.root.innerHTML = '';
			document.querySelector('input[name="comment_id"]').value = '';
			document.querySelector('input[name="act"]').value = 'write';
			document.querySelector('button[type="submit"]').textContent = '댓글 작성';
		}

		// 새 댓글 작성 시 폼 초기화
		document.getElementById('content').addEventListener('focus', function() {
			if (document.querySelector('input[name="act"]').value === 'edit') {
				resetCommentForm();
			}
		});

		// 코멘트 삭제
		document.querySelectorAll('.delete-comment').forEach(button => {
			button.addEventListener('click', function() {
				if (confirm('댓글을 삭제하시겠습니까?')) {
					const commentId = this.dataset.commentId;
					
					//스피너 시작
					showLoadingSpinner();
					
					fetch(CM.BOARD_URL + '/comment_update.php', {
						method: 'POST',
						headers: {
							'Content-Type': 'application/x-www-form-urlencoded',
						},
						body: new URLSearchParams({
							act: 'delete',
							comment_id: commentId,
							board_id: boardId,
							board_num: boardNum
						})
					})
					.then(response => response.json())
					.then(data => {
						if (data.status === 'success') {
							const currentPage = comment_page;
							window.location.href = CM.BOARD_URL + '/view.php?board=' + boardId + '&id=' + boardNum + '&comment_page=' + currentPage;
						} else {
							alert(data.message || '댓글 삭제에 실패했습니다.');
						}
					})
					.catch(error => {
						console.error('Error:', error);
						alert('서버 오류가 발생했습니다.');
					});
				}
			});
		});
	}

    // 좋아요/싫어요 버튼 이벤트
    function handleVote(action) {
        fetch(CM.BOARD_URL + '/good_bad.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                board_id: boardId,
                board_num: boardNum,
                action: action
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                document.getElementById('likeCount').textContent = data.good;
                document.getElementById('likeCountMain').textContent = data.good;
                document.getElementById('dislikeCount').textContent = data.bad;
            } else {
                alert(data.message || '오류가 발생했습니다.');
            }
        })
        .catch(error => {
            console.error('Vote Error:', error);
            alert('서버 오류가 발생했습니다.');
        });
    }

    // 좋아요/싫어요 버튼 이벤트 리스너
    document.getElementById('goodBtn')?.addEventListener('click', () => handleVote('good'));
    document.getElementById('badBtn')?.addEventListener('click', () => handleVote('bad'));
});

// 관리자 삭제 확인 함수
function confirmDelete(board_id, board_num) {
    if (confirm('정말 삭제하시겠습니까?')) {
        window.location.href = CM.BOARD_URL + '/delete.php?board=' + board_id + '&id=' + board_num;
    }
}