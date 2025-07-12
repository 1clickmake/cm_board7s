<?php
include_once './_common.php';
define('_ADMIN_INDEX_', true);
include_once CM_ADMIN_PATH.'/admin.head.php';
?>


    <!-- Main Content -->
    <div class="main-content shifted" id="mainContent">
        <div class="container-fluid">
            <h1 class="page-title">DASHBOARD</h1>
            
            <!-- 통계 카드 -->
            <div class="row mb-5">
                <div class="col-lg-3 col-md-6 mb-4">
                    <div class="card stats-card card-visits text-white">
                        <div class="card-body">
                            <i class="fas fa-users card-icon"></i>
                            <h5 class="card-title">총 방문자</h5>
                            <h2 class="card-number"><?php echo number_format($total_visits);?></h2>
                            <p class="card-subtitle mb-0">누적 방문자 수</p>
                        </div>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6 mb-4">
                    <div class="card stats-card card-today text-white">
                        <div class="card-body">
                            <i class="fas fa-calendar-day card-icon"></i>
                            <h5 class="card-title">오늘 방문자</h5>
                            <h2 class="card-number"><?php echo number_format($today_visits);?></h2>
                            <p class="card-subtitle mb-0">오늘 방문한 사용자</p>
                        </div>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6 mb-4">
                    <div class="card stats-card card-yesterday text-white">
                        <div class="card-body">
                            <i class="fas fa-chart-line card-icon"></i>
                            <h5 class="card-title">어제 방문자</h5>
                            <h2 class="card-number"><?php echo number_format($yesterday_visits);?></h2>
                            <p class="card-subtitle mb-0">전일 대비 방문자</p>
                        </div>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6 mb-4">
                    <div class="card stats-card card-posts text-white">
                        <div class="card-body">
                            <i class="fas fa-edit card-icon"></i>
                            <h5 class="card-title">어제 게시물</h5>
                            <h2 class="card-number"><?php echo number_format($yesterday_posts);?></h2>
                            <p class="card-subtitle mb-0">전일 작성된 게시물</p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row">
                <!-- 좌측 섹션 -->
                <div class="col-lg-6">
                    <!-- 최근 7일간 방문자 통계 그래프 -->
                    <div class="card chart-card mb-4">
                        <div class="card-header">
                            <h5 class="card-title mb-0">
                                <i class="fas fa-chart-area me-2"></i>
                                최근 7일간 방문자 통계
                            </h5>
                        </div>
                        <div class="card-body">
                            <canvas id="visitChart" style="height: 300px;"></canvas>
                        </div>
                    </div>

                    <!-- 최근 가입 회원 -->
                    <div class="card table-card">
                        <div class="card-header">
                            <h5 class="card-title mb-0">
                                <i class="fas fa-user-plus me-2"></i>
                                최근 가입 회원
                            </h5>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-sm table-hover">
                                    <thead>
                                        <tr>
                                            <th><i class="fas fa-id-card me-1"></i>아이디</th>
                                            <th><i class="fas fa-user me-1"></i>이름</th>
                                            <th><i class="fas fa-envelope me-1"></i>이메일</th>
                                            <th><i class="fas fa-clock me-1"></i>가입일</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php
                                        // 최근 가입 회원 10명 조회
                                        $sql = "SELECT user_id, user_name, user_email, created_at 
                                               FROM cm_users 
                                               ORDER BY created_at DESC 
                                               LIMIT 10";
                                        $latest_members = sql_all_list($sql);

                                        if ($latest_members) {
                                            foreach ($latest_members as $member) {
                                                ?>
                                                <tr>
                                                    <td><strong><?php echo htmlspecialchars($member['user_id']); ?></strong></td>
                                                    <td><?php echo htmlspecialchars($member['user_name']); ?></td>
                                                    <td class="text-truncate" style="max-width: 200px;">
                                                        <?php echo htmlspecialchars($member['user_email']); ?>
                                                    </td>
                                                    <td><small class="text-muted"><?php echo date('Y-m-d H:i', strtotime($member['created_at'])); ?></small></td>
                                                </tr>
                                                <?php
                                            }
                                        } else {
                                            echo '<tr><td colspan="4" class="text-center text-muted py-4">
                                                    <i class="fas fa-users fa-2x mb-2 d-block"></i>
                                                    가입된 회원이 없습니다.
                                                  </td></tr>';
                                        }
                                        ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- 우측 섹션 -->
                <div class="col-lg-6">
                    <!-- 최근 7일간 시간대별 방문자 통계 -->
                    <div class="card chart-card mb-4">
                        <div class="card-header">
                            <h5 class="card-title mb-0">
                                <i class="fas fa-clock me-2"></i>
                                최근 7일간 시간대별 방문자 통계
                            </h5>
                        </div>
                        <div class="card-body">
                            <canvas id="hourlyChart" style="height: 300px;"></canvas>
                        </div>
                    </div>

                    <!-- 최신 게시글 -->
                    <div class="card table-card">
                        <div class="card-header">
                            <h5 class="card-title mb-0">
                                <i class="fas fa-newspaper me-2"></i>
                                최신 게시글
                            </h5>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-sm table-hover">
                                    <thead>
                                        <tr>
                                            <th><i class="fas fa-clipboard-list me-1"></i>게시판</th>
                                            <th><i class="fas fa-user me-1"></i>작성자</th>
                                            <th><i class="fas fa-file-alt me-1"></i>제목</th>
                                            <th><i class="fas fa-clock me-1"></i>작성일</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php
                                        // 최신 게시글 10개 조회
                                        $sql = "SELECT board_num, board_id, name, title, reg_date 
                                               FROM cm_board WHERE reply_depth = '0'
                                               ORDER BY reg_date DESC 
                                               LIMIT 10";
                                        $latest_posts = sql_all_list($sql);

                                        if ($latest_posts) {
                                            foreach ($latest_posts as $post) {
                                                ?>
                                                <tr>
                                                    <td><span class="badge bg-primary"><?php echo htmlspecialchars($post['board_id']); ?></span></td>
                                                    <td><?php echo htmlspecialchars($post['name']); ?></td>
                                                    <td class="text-truncate" style="max-width: 200px;">
                                                        <a href="<?php echo get_board_url('view', $post['board_id'], $post['board_num']); ?>" 
                                                           class="text-decoration-none text-dark fw-medium">
                                                            <?php echo htmlspecialchars($post['title']); ?>
                                                        </a>
                                                    </td>
                                                    <td><small class="text-muted"><?php echo date('Y-m-d H:i', strtotime($post['reg_date'])); ?></small></td>
                                                </tr>
                                                <?php
                                            }
                                        } else {
                                            echo '<tr><td colspan="4" class="text-center text-muted py-4">
                                                    <i class="fas fa-newspaper fa-2x mb-2 d-block"></i>
                                                    등록된 게시글이 없습니다.
                                                  </td></tr>';
                                        }
                                        ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    
    
<?php
include_once CM_ADMIN_PATH.'/admin.tail.php';
?>