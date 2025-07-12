<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가
?>
<?php if(defined('_ADMIN_INDEX_')) {?>
<script>
//통계차트
    document.addEventListener('DOMContentLoaded', function() {
        // 7일간 방문자 통계 차트
        const ctx = document.getElementById('visitChart').getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: <?php echo json_encode($visit_dates);?>,
                datasets: [{
                    label: '방문자 수',
                    data: <?php echo json_encode($visit_counts);?>,
                    borderColor: 'rgb(255, 105, 180)',
                    backgroundColor: 'rgba(255, 105, 180, 0.2)',
                    tension: 0.1,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    title: {
                        display: true,
                        text: '일별 방문자 통계'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });

        // 시간대별 방문자 통계 차트
        const hourlyCtx = document.getElementById('hourlyChart').getContext('2d');
        const rainbowColors = [
            { bg: 'rgba(255, 0, 0, 0.7)', border: 'rgb(255, 0, 0)' },    // 빨강
            { bg: 'rgba(255, 165, 0, 0.7)', border: 'rgb(255, 165, 0)' }, // 주황
            { bg: 'rgba(255, 255, 0, 0.7)', border: 'rgb(255, 255, 0)' }, // 노랑
            { bg: 'rgba(0, 255, 0, 0.7)', border: 'rgb(0, 255, 0)' },     // 초록
            { bg: 'rgba(0, 0, 255, 0.7)', border: 'rgb(0, 0, 255)' },     // 파랑
            { bg: 'rgba(0, 0, 128, 0.7)', border: 'rgb(0, 0, 128)' },     // 남색
            { bg: 'rgba(128, 0, 128, 0.7)', border: 'rgb(128, 0, 128)' }  // 보라
        ];

        const hourlyDatasets = <?php echo json_encode($dates); ?>.map((date, index) => {
            const dateKey = Object.keys(<?php echo json_encode($hourly_data); ?>)[index];
            return {
                label: date,
                data: <?php echo json_encode($hourly_data); ?>[dateKey],
                backgroundColor: rainbowColors[index].bg,
                borderColor: rainbowColors[index].border,
                borderWidth: 1
            };
        });

        new Chart(hourlyCtx, {
            type: 'bar',
            data: {
                labels: Array.from({length: 24}, (_, i) => `${i}시`),
                datasets: hourlyDatasets
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    title: {
                        display: true,
                        text: '시간대별 방문자 통계'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        },
                        stacked: false
                    },
                    x: {
                        ticks: {
                            maxRotation: 45,
                            minRotation: 45
                        },
                        stacked: false
                    }
                }
            }
        });
    });
</script>
<?php } ?>
<script>
//사이드바
const sidebar = document.getElementById('sidebar');
const mainContent = document.getElementById('mainContent');
const toggleButton = document.getElementById('toggleSidebar');
const closeButton = document.getElementById('closeSidebar');

function toggleSidebar() {
    sidebar.classList.toggle('hidden');
    mainContent.classList.toggle('shifted');
}

toggleButton.addEventListener('click', toggleSidebar);
closeButton.addEventListener('click', toggleSidebar);

//사이드바 토글메뉴
document.addEventListener('DOMContentLoaded', function () {
    const sidebar = document.getElementById('sidebar');

    // 모든 collapse 토글 아이콘 처리
    document.querySelectorAll('.toggle-icon').forEach(function (icon) {
        const targetId = icon.getAttribute('data-target');
        const submenu = document.getElementById(targetId);

        if (submenu) {
            submenu.addEventListener('show.bs.collapse', function () {
                // 1. 다른 열린 collapse 요소들을 닫는다
                const openMenus = sidebar.querySelectorAll('.collapse.show');
                openMenus.forEach(function (menu) {
                    if (menu !== submenu) {
                        const collapseInstance = bootstrap.Collapse.getInstance(menu);
                        if (collapseInstance) {
                            collapseInstance.hide();
                        } else {
                            new bootstrap.Collapse(menu, { toggle: false }).hide();
                        }
                    }
                });

                // 2. 아이콘 변경: 열림
                icon.classList.remove('bi-chevron-down');
                icon.classList.add('bi-chevron-up');
            });

            submenu.addEventListener('hide.bs.collapse', function () {
                // 아이콘 변경: 닫힘
                icon.classList.remove('bi-chevron-up');
                icon.classList.add('bi-chevron-down');
            });
        }
    });
});
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>