// 마이페이지

/*패스워스 입력폼 이동*/
function redirectToPass(btnVal) {
    const actValue = btnVal.value;
    const targetUrl = CM.MB_URL + '/password.php?act='+actValue;
    window.location.href = targetUrl;
}

/*회원정보수정 . 회원탈퇴 패스워드 입력 폼*/
document.addEventListener('DOMContentLoaded', function() {
    const passwordCheckForm = document.getElementById('passwordCheckForm');
    const userPasswordInput = document.getElementById('user_password');
    const passwordErrorDiv = document.getElementById('passwordError');

    function fetchData(url, options) {
        return fetch(url, options)
            .then(response => {
                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                return response.json();
            })
            .catch(error => { throw error; });
    }

    if (passwordCheckForm) {
        passwordCheckForm.addEventListener('submit', function(e) {
            e.preventDefault();
            passwordErrorDiv.textContent = '';
            const userPassword = userPasswordInput.value;
            if (!userPassword) {
                passwordErrorDiv.textContent = '비밀번호 입력';
                return;
            }
            const currentAction = new URLSearchParams(window.location.search).get('act');
            showLoadingSpinner();
            fetchData(CM.MB_URL + '/password_check.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: `user_id=${encodeURIComponent(user_id)}&user_password=${encodeURIComponent(userPassword)}`
            })
            .then(response => {
                hideLoadingSpinner();
                if (response.status === 'success') {
                    if (currentAction === 'update') {
                        window.location.href = CM.MB_URL + '/register_form.php?w=update';
                    } else if (currentAction === 'leave') {
                        if (confirm('정말로 회원 탈퇴?')) {
                            fetchData(CM.MB_URL + '/member_leave.php', {method: 'POST'})
                            .then(leaveResponse => {
                                if (leaveResponse.status === 'success') {
                                    alert(leaveResponse.message);
                                    window.location.href = CM.URL;
                                } else {
                                    alert(leaveResponse.message || '회원 탈퇴 오류');
                                }
                            })
                            .catch(() => { alert('회원 탈퇴 서버 오류'); });
                        }
                    }
                } else {
                    passwordErrorDiv.textContent = response.message || '비밀번호 불일치';
                }
            })
            .catch(() => {
                passwordErrorDiv.textContent = '비밀번호 확인 서버 오류';
            });
        });
    }
});