// 맨 위로 스크롤, 로딩 스피너

document.addEventListener('DOMContentLoaded', function() {
    const topBtn = document.getElementById('top_btn');
    if (topBtn) {
        topBtn.addEventListener('click', function(e) {
            e.preventDefault();
            window.scrollTo({top: 0, behavior: 'smooth'});
        });
    }
    const topBtnElem = document.getElementById('top_btn');
    if (window.scrollY <= 300) {
        if (topBtnElem) topBtnElem.style.display = 'none';
    }
    window.addEventListener('scroll', function() {
        const scrollTop = window.scrollY;
        if (scrollTop > 300) {
            if (topBtnElem) {
                topBtnElem.style.display = 'block';
                setTimeout(() => topBtnElem.style.opacity = '1', 10);
            }
        } else {
            if (topBtnElem) {
                topBtnElem.style.opacity = '0';
                setTimeout(() => topBtnElem.style.display = 'none', 200);
            }
        }
    });
    const style = document.createElement('style');
    style.innerHTML = `#top_btn {transition: opacity 0.2s; opacity: 0;}`;
    document.head.appendChild(style);
});

const loadingSpinner = document.getElementById('loadingSpinner');
const loadingOverlay = document.getElementById('loadingOverlay');
if (loadingSpinner) loadingSpinner.style.display = 'none';
if (loadingOverlay) loadingOverlay.style.display = 'none';

function showLoadingSpinner() {
    if (loadingSpinner) loadingSpinner.style.display = 'block';
    if (loadingOverlay) loadingOverlay.style.display = 'block';
}
function hideLoadingSpinner() {
    if (loadingSpinner) loadingSpinner.style.display = 'none';
    if (loadingOverlay) loadingOverlay.style.display = 'none';
}