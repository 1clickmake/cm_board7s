// 로그인 폼

document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('loginForm').addEventListener('submit', function(e) {
        showLoadingSpinner();
        e.preventDefault();
        const formData = new FormData(this);
        const errorDiv = document.getElementById('loginError');
        fetch(CM.MB_URL + '/login_check.php', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            hideLoadingSpinner();
            if (data.status === 'success') {
                window.location.href = data.redirect || CM.URL;
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