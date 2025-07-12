/**
 * 메뉴 관련 JavaScript
 * 3뎁스 이상 드롭다운 메뉴 지원
 */

document.addEventListener('DOMContentLoaded', function() {
    // 3뎁스 이상 드롭다운 메뉴 초기화
    initNestedDropdowns();
    
    // 모바일에서 드롭다운 메뉴 처리
    initMobileDropdowns();
});

/**
 * 중첩 드롭다운 메뉴 초기화
 */
function initNestedDropdowns() {
    // 3뎁스 이상 드롭다운 메뉴 요소들 선택
    const nestedDropdowns = document.querySelectorAll('.dropdown-menu .dropend');
    
    nestedDropdowns.forEach(function(dropdown) {
        const submenu = dropdown.querySelector('.dropdown-menu');
        const link = dropdown.querySelector('.dropdown-toggle');
        
        if (submenu && link) {
            // 마우스 진입 시 하위 메뉴 표시
            dropdown.addEventListener('mouseenter', function() {
                // 다른 열린 하위 메뉴들 닫기
                closeOtherNestedDropdowns(dropdown);
                
                // 현재 하위 메뉴 표시
                submenu.classList.add('show');
                submenu.style.display = 'block';
                
                // 위치 조정
                adjustDropdownPosition(submenu, dropdown);
            });
            
            // 마우스 이탈 시 하위 메뉴 숨김
            dropdown.addEventListener('mouseleave', function() {
                setTimeout(function() {
                    if (!dropdown.matches(':hover')) {
                        submenu.classList.remove('show');
                        submenu.style.display = 'none';
                    }
                }, 100);
            });
            
            // 하위 메뉴 내부에서도 마우스 이탈 처리
            submenu.addEventListener('mouseleave', function() {
                setTimeout(function() {
                    if (!dropdown.matches(':hover') && !submenu.matches(':hover')) {
                        submenu.classList.remove('show');
                        submenu.style.display = 'none';
                    }
                }, 100);
            });
        }
    });
}

/**
 * 다른 중첩 드롭다운 메뉴들 닫기
 */
function closeOtherNestedDropdowns(currentDropdown) {
    const allNestedDropdowns = document.querySelectorAll('.dropdown-menu .dropend .dropdown-menu');
    
    allNestedDropdowns.forEach(function(submenu) {
        if (submenu !== currentDropdown.querySelector('.dropdown-menu')) {
            submenu.classList.remove('show');
            submenu.style.display = 'none';
        }
    });
}

/**
 * 드롭다운 위치 조정
 */
function adjustDropdownPosition(submenu, parentDropdown) {
    const parentRect = parentDropdown.getBoundingClientRect();
    const submenuRect = submenu.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    
    // 화면 오른쪽 끝에 닿을 경우 왼쪽으로 표시
    if (parentRect.right + submenuRect.width > viewportWidth) {
        submenu.style.left = 'auto';
        submenu.style.right = '100%';
        submenu.style.marginLeft = '0';
        submenu.style.marginRight = '2px';
    } else {
        submenu.style.left = '100%';
        submenu.style.right = 'auto';
        submenu.style.marginLeft = '2px';
        submenu.style.marginRight = '0';
    }
    
    // 화면 위/아래 끝에 닿을 경우 위치 조정
    const viewportHeight = window.innerHeight;
    if (parentRect.bottom + submenuRect.height > viewportHeight) {
        submenu.style.top = 'auto';
        submenu.style.bottom = '0';
    } else {
        submenu.style.top = '0';
        submenu.style.bottom = 'auto';
    }
}

/**
 * 모바일 드롭다운 메뉴 초기화
 */
function initMobileDropdowns() {
    // 모바일에서 클릭으로 드롭다운 토글
    const mobileDropdownToggles = document.querySelectorAll('.dropdown-toggle');
    
    mobileDropdownToggles.forEach(function(toggle) {
        toggle.addEventListener('click', function(e) {
            // 데스크톱에서는 기본 동작 유지
            if (window.innerWidth > 768) {
                return;
            }
            
            // 모바일에서만 커스텀 처리
            e.preventDefault();
            e.stopPropagation();
            
            const dropdown = this.closest('.dropdown, .dropend');
            const submenu = dropdown.querySelector('.dropdown-menu');
            
            if (submenu) {
                const isOpen = submenu.classList.contains('show');
                
                // 다른 열린 드롭다운들 닫기
                document.querySelectorAll('.dropdown-menu.show').forEach(function(menu) {
                    if (menu !== submenu) {
                        menu.classList.remove('show');
                    }
                });
                
                // 현재 드롭다운 토글
                if (isOpen) {
                    submenu.classList.remove('show');
                } else {
                    submenu.classList.add('show');
                }
            }
        });
    });
    
    // 모바일에서 드롭다운 외부 클릭 시 닫기
    document.addEventListener('click', function(e) {
        if (window.innerWidth <= 768) {
            if (!e.target.closest('.dropdown, .dropend')) {
                document.querySelectorAll('.dropdown-menu.show').forEach(function(menu) {
                    menu.classList.remove('show');
                });
            }
        }
    });
}

/**
 * 윈도우 리사이즈 시 드롭다운 상태 초기화
 */
window.addEventListener('resize', function() {
    // 모든 열린 드롭다운 닫기
    document.querySelectorAll('.dropdown-menu.show').forEach(function(menu) {
        menu.classList.remove('show');
        menu.style.display = '';
    });
    
    // 모바일 드롭다운 재초기화
    if (window.innerWidth <= 768) {
        initMobileDropdowns();
    }
});

/**
 * 키보드 접근성 지원
 */
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        // ESC 키로 열린 드롭다운 닫기
        document.querySelectorAll('.dropdown-menu.show').forEach(function(menu) {
            menu.classList.remove('show');
        });
    }
}); 