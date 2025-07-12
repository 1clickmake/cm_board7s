// 비밀번호 찾기 폼

document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('forgotPasswordSubmit').addEventListener('click', function() {
        const form = document.getElementById('forgotPasswordForm');
        const formData = new FormData(form);
        const errorDiv = document.getElementById('forgotPasswordError');
        const tempPasswordDisplay = document.getElementById('tempPasswordDisplay');

        fetch(CM.MB_URL + '/lost_password_check.php', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                errorDiv.classList.add('d-none');
                tempPasswordDisplay.textContent = '임시 비밀번호: ' + data.temp_password;
            } else {
                errorDiv.classList.remove('d-none');
                errorDiv.textContent = data.message;
            }
        })
        .catch(() => {
            errorDiv.classList.remove('d-none');
            errorDiv.textContent = '서버 오류. 잠시 후 다시 시도.';
        });
    });
});