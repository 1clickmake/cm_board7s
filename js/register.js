//회원가입/수정 
document.addEventListener('DOMContentLoaded', function() {

    // 이 변수에 따라 회원가입 폼인지, 회원정보 수정 폼인지 구분.
    const registerForm = document.getElementById('registerForm');
    const submitButton = document.getElementById('submitButton');

    // 폼이 존재하고 'g-recaptcha-response' 필드가 있는지 확인
    const gRecaptchaResponseInput = document.getElementById('g-recaptcha-response');
    const hasRecaptcha = gRecaptchaResponseInput !== null;

    // 초기 버튼 텍스트 설정 (PHP에서 설정되지만, JS에서 필요시 오버라이드 가능)
    if (submitButton) {
        if (typeof registerUpdate !== 'undefined' && registerUpdate) {
            submitButton.textContent = '수정';
			var moveUrl = CM.MB_URL + '/mypage.php';
        } else {
            submitButton.textContent = '가입';
			var moveUrl = CM.URL + '/mypage.php';
        }
    }

    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
			
			//스피너 시작
			showLoadingSpinner();
			
            e.preventDefault(); // 폼 기본 제출 방지

            // 오류 메시지 초기화
            const errorFields = ['user_id', 'user_name', 'user_password', 'password_confirm', 'user_email', 'user_hp'];
            errorFields.forEach(field => {
                const errorElement = document.getElementById(field + 'Error');
                if (errorElement) {
                    errorElement.textContent = '';
                }
            });

            // 비밀번호 일치 여부 확인
            const passwordInput = document.getElementById('user_password');
            const passwordConfirmInput = document.getElementById('password_confirm');
            const passwordErrorElement = document.getElementById('password_confirmError');

            if (passwordInput && passwordConfirmInput && passwordErrorElement) {
                if (passwordInput.value !== passwordConfirmInput.value) {
                    passwordErrorElement.textContent = '비밀번호가 일치하지 않습니다.';
                    passwordConfirmInput.focus(); // 불일치 시 확인 필드에 포커스
                    return; // 폼 제출 중단
                }
            }

            const handleSubmit = function() {
                const formData = new FormData(registerForm); // FormData 객체 생성

                fetch(registerForm.action, {
                    method: 'POST',
                    body: formData // FormData 객체를 body에 직접 전달
                })
                .then(response => {
                    // HTTP 상태 코드가 200-299 범위가 아닐 경우 에러 처리
                    if (!response.ok) {
                        return response.json().then(errorData => {
                            throw new Error(errorData.message || '네트워크 응답 오류');
                        });
                    }
                    return response.json(); // JSON 응답 파싱
                })
                .then(data => {
					//스피너 종료
					hideLoadingSpinner();
					
                    if (data.status === 'success') {
                        alert(typeof registerUpdate !== 'undefined' && registerUpdate ? '회원정보가 수정되었습니다.' : '회원가입이 완료되었습니다.');
                        window.location.href = moveUrl;
                    } else {
                        // 서버에서 특정 필드 오류를 반환한 경우 해당 필드에 오류 메시지 표시
                        if (data.field && document.getElementById(data.field + 'Error')) {
                            document.getElementById(data.field + 'Error').textContent = data.message;
                            const errorFieldElement = document.getElementById(data.field);
                            if (errorFieldElement) {
                                errorFieldElement.focus(); // 오류 필드에 포커스
                            }
                        } else {
							hideLoadingSpinner();
                            // 일반적인 오류 메시지 (필드 특정하지 않은 경우)
                            alert(data.message || (typeof registerUpdate !== 'undefined' && registerUpdate ? '회원정보 수정에 실패했습니다.' : '회원가입에 실패했습니다.'));
                        }
                    }
                })
                .catch(error => {
                    console.error('AJAX 오류:', error);
                    alert('서버 오류가 발생했습니다. 잠시 후 다시 시도해주세요. (' + error.message + ')');
                });
            };

            // reCAPTCHA 유무에 따라 제출 로직 분기
            if (hasRecaptcha && typeof grecaptcha !== 'undefined' && grecaptcha.ready) {
                grecaptcha.ready(function() {
                    // recaptchaSiteKey 변수는 PHP에서 넘어오는 전역 변수라고 가정
                    grecaptcha.execute(window.recaptchaSiteKey, { action: 'submit' }).then(function(token) {
                        if (gRecaptchaResponseInput) {
                            gRecaptchaResponseInput.value = token;
                        }
                        handleSubmit();
                    }).catch(function(error) {
                        console.error('reCAPTCHA 실행 오류:', error);
                        alert('reCAPTCHA 인증 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.');
                    });
                });
            } else {
                // reCAPTCHA 키가 없거나 grecaptcha가 로드되지 않은 경우 바로 제출
                handleSubmit();
            }
        });

        // 실시간 입력 검증 (blur 이벤트 사용)
        const userIdInput = document.getElementById('user_id');
        const userIdError = document.getElementById('user_idError');
        if (userIdInput && userIdError) {
            userIdInput.addEventListener('blur', function() {
                if (this.value.length < 4 && this.value.length > 0) { // 입력값이 있을 때만 검사
                    userIdError.textContent = '아이디는 최소 4자 이상이어야 합니다';
                } else {
                    userIdError.textContent = '';
                }
            });
        }

        const userPasswordInput = document.getElementById('user_password');
        const userPasswordError = document.getElementById('user_passwordError');
        if (userPasswordInput && userPasswordError) {
            userPasswordInput.addEventListener('blur', function() {
                if (this.value.length < 8 && this.value.length > 0) { // 입력값이 있을 때만 검사
                    userPasswordError.textContent = '비밀번호는 최소 8자 이상이어야 합니다';
                } else {
                    userPasswordError.textContent = '';
                }
            });
        }

        const passwordConfirmInput = document.getElementById('password_confirm');
        const passwordConfirmError = document.getElementById('password_confirmError');
        if (passwordConfirmInput && passwordConfirmError && userPasswordInput) {
            passwordConfirmInput.addEventListener('blur', function() {
                if (userPasswordInput.value !== this.value && this.value.length > 0) { // 입력값이 있을 때만 검사
                    passwordConfirmError.textContent = '비밀번호가 일치하지 않습니다';
                } else {
                    passwordConfirmError.textContent = '';
                }
            });
        }

        const userEmailInput = document.getElementById('user_email');
        const userEmailError = document.getElementById('user_emailError');
        if (userEmailInput && userEmailError) {
            userEmailInput.addEventListener('blur', function() {
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailRegex.test(this.value) && this.value.length > 0) { // 입력값이 있을 때만 검사
                    userEmailError.textContent = '유효한 이메일 주소를 입력해주세요';
                } else {
                    userEmailError.textContent = '';
                }
            });
        }
    }
});