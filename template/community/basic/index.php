<?php
if (!defined('_CMBOARD_'))
    exit;  // 개별 페이지 접근 불가 
?>
<main>
  <!-- 메인 히어로 섹션 -->
  <section class="pt-5 pb-3 mt-0 align-items-bottom d-flex bg-primary" style="min-height: 100vh; background-size: cover; background-image: url('https://cdn.pixabay.com/photo/2018/05/23/13/29/network-3424070_1280.jpg');">
    <div class="container">
      <div class="row justify-content-start align-items-end d-flex h-100">
        <div class="col-12 col-md-8 h-50">
          <h3 class="text-uppercase text-light mb-0 text-left">프로페셔널 솔루션</h3>
          <h1 class="display-5 text-uppercase text-light text-left mb-2 mt-0">
            <strong>비즈니스 성장을 위한<br>완벽한 웹 솔루션</strong>
          </h1>
          <p class="lead text-light mb-4">10년간 검증된 기술력으로 고객의 매출 증대를 실현합니다</p>
          <div class="d-flex gap-3">
            <a href="#contact" class="btn btn-light btn-lg">무료 견적받기</a>
            <a href="#services" class="btn btn-outline-light btn-lg">서비스 보기</a>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- 알림 배너 섹션 -->
  <section class="border py-3">
    <div class="container text-center">
      <p class="mb-0">
        <strong>🎯 500+ 고객사가 선택한 검증된 솔루션</strong> | 
        <span class="text-primary">평균 매출 증대 47%</span> | 
        <a href="#contact" class="text-decoration-none fw-bold">지금 무료 상담받기 →</a>
      </p>
    </div>
  </section>

  <!-- 서비스 소개 섹션 -->
  <section class="pt-5 pb-5">
    <div class="container">
      <div class="row text-center mb-5">
        <div class="col-12">
          <h2 class="fw-bold">핵심 비즈니스 서비스</h2>
          <p class="lead">실제 매출 증대를 위한 검증된 웹 솔루션을 제공합니다</p>
        </div>
      </div>
      <hr>
      <div class="row text-left align-items-start">
        <div class="col-12 col-md-6 col-lg-4">
          <div class="p-4 h-100">
            <h3 class="h4 mb-3">🛒 전자상거래 솔루션</h3>
            <p class="text-h3">월 매출 1억원 달성 고객사 다수 보유! 온라인 쇼핑몰 구축부터 마케팅 자동화까지. 평균 3개월 내 매출 증대 효과를 경험하세요.</p>
            <p class="text-h3 mt-3">
              <a href="<?php echo CM_URL?>/bbs/board.php?bo_table=service&sca=website" class="btn btn-outline-secondary">성공사례 보기</a>
            </p>
          </div>
        </div>
        <div class="col-12 col-md-6 col-lg-4 pt-4 pt-md-0">
          <div class="p-4 h-100">
            <h3 class="h4 mb-3">📈 마케팅 자동화</h3>
            <p class="text-h3">고객 유입부터 매출까지 자동화! 이메일 마케팅, SMS 발송, 고객 관리 시스템 구축. 평균 40% 고객 재방문율 향상을 실현합니다.</p>
            <p class="text-h3 mt-3">
              <a href="<?php echo CM_URL?>/bbs/board.php?bo_table=service&sca=design" class="btn btn-outline-secondary">ROI 확인하기</a>
            </p>
          </div>
        </div>
        <div class="col-12 col-md-8 m-auto m-lg-0 col-lg-4 pt-5 pt-lg-0">
          <div class="p-4 h-100">
            <h3 class="h4 mb-3">💼 기업 관리 시스템</h3>
            <p class="text-h3">업무 효율성 60% 향상! 인사관리, 재고관리, 회계시스템 통합 구축. 월 운영비 30% 절감 효과를 경험하세요.</p>
            <div class="mt-3">
              <p class="text-h3">
                <a href="<?php echo CM_URL?>/bbs/board.php?bo_table=service&sca=solution" class="btn btn-outline-secondary">비용 절감 확인</a>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- 갤러리 섹션 -->
  <section class="pt-5 pb-5 bg-dark">
    <div class="container">
      <h2 class="mb-5 fw-bold text-center"><a href="<?php echo get_board_url('list', 'gallery');?>" class="text-white">갤러리 최신글</a></h2>
      <div class="row">
        <?php echo get_new_post('gallery', 2, 'basic_new_gallery'); ?>
      </div>
    </div>
  </section>

  <!-- 공지사항 섹션 -->
  <section class="pt-5 pb-5">
    <div class="container">
      <h2 class="mb-5 fw-bold text-center"><a href="<?php echo get_board_url('list', 'notice');?>" class="text-dark">공지사항 최신글</a></h2>
      <div class="row">
        <?php echo get_new_post('notice', 4, 'basic_new_post'); ?>
      </div>
    </div>
  </section>

  <!-- 콜투액션 섹션 -->
  <section class="py-5 bg-light">
    <div class="container">
      <div class="row d-flex">
        <div class="col-12 text-center">
          <h4 class="pb-2 h3 mb-1 mt-1 fw-bold">지금 시작하면 3개월 후 매출이 달라집니다!</h4>
          <p class="lead">500+ 기업이 이미 성공을 경험했습니다. 무료 상담 후 맞춤 견적을 받아보세요.</p>
          <div class="my-3">
            <a href="#contact" class="btn btn-secondary btn-lg btn-round">무료 상담 신청 (1시간 소요)</a>
          </div>
          <p class="small text-muted mt-2">※ 상담 후 구매 의무 없음 | 24시간 내 견적서 발송</p>
        </div>
      </div>
    </div>
  </section>

  <!-- 기능 소개 섹션 -->
  <section class="pt-5 pb-5 mt-0 align-items-center text-white d-flex bg-dark" style="min-height: 100vh; background-size: cover; background-image: url('https://cdn.pixabay.com/photo/2018/05/23/13/29/network-3424070_1280.jpg');">
    <div class="container text-white">
      <div class="row">
        <div class="col-12">
          <h2 class="fw-bold mb-5 mt-5 text-center">검증된 성과로 입증된 솔루션</h2>
        </div>
        <div class="mt-2 mb-4 col-md-4 col-6">
          <div class="card bg-transparent border-light">
            <div class="card-body">
              <i class="mt-2 fa fa-chart-line mb-3 fa-2x text-white"></i>
              <h4 class="h5 mb-4 text-white">매출 증대 47%</h4>
              <p class="font-weight-light text-white">평균 3개월 내 고객사 매출 47% 증대 실현. 검증된 마케팅 전략으로 성과를 보장합니다.</p>
            </div>
          </div>
        </div>
        <div class="mt-2 mb-4 col-md-4 col-6">
          <div class="card bg-transparent border-light">
            <div class="card-body">
              <i class="mt-2 fa fa-users mb-3 fa-2x text-white"></i>
              <h4 class="h5 mb-4 text-white">고객 만족도 98%</h4>
              <p class="font-weight-light text-white">500+ 기업 고객의 98% 만족도 달성. 지속적인 업데이트와 기술 지원으로 신뢰를 구축합니다.</p>
            </div>
          </div>
        </div>
        <div class="mt-2 mb-4 col-md-4 col-6">
          <div class="card bg-transparent border-light">
            <div class="card-body">
              <i class="mt-2 fa fa-rocket mb-3 fa-2x text-white"></i>
              <h4 class="h5 mb-4 text-white">빠른 구축 2주</h4>
              <p class="font-weight-light text-white">평균 2주 내 시스템 구축 완료. 빠른 시장 진입으로 경쟁 우위를 확보하세요.</p>
            </div>
          </div>
        </div>
        <div class="mt-2 mb-4 col-md-4 col-6">
          <div class="card bg-transparent border-light">
            <div class="card-body">
              <i class="mt-2 fa fa-shield-alt mb-3 fa-2x text-white"></i>
              <h4 class="h5 mb-4 text-white">보안 인증 완료</h4>
              <p class="font-weight-light text-white">ISO 27001 보안 인증 완료. 고객 데이터 보호와 시스템 안정성을 최우선으로 합니다.</p>
            </div>
          </div>
        </div>
        <div class="mt-2 mb-4 col-md-4 col-6">
          <div class="card bg-transparent border-light">
            <div class="card-body">
              <i class="mt-2 fa fa-headset mb-3 fa-2x text-white"></i>
              <h4 class="h5 mb-4 text-white">24시간 기술지원</h4>
              <p class="font-weight-light text-white">365일 24시간 기술 지원 서비스. 언제든 문제 해결과 업무 연속성을 보장합니다.</p>
            </div>
          </div>
        </div>
        <div class="mt-2 mb-4 col-md-4 col-6">
          <div class="card bg-transparent border-light">
            <div class="card-body">
              <i class="mt-2 fa fa-coins mb-3 fa-2x text-white"></i>
              <h4 class="h5 mb-4 text-white">투자 대비 300% ROI</h4>
              <p class="font-weight-light text-white">평균 투자 대비 300% 수익률 달성. 명확한 성과 측정으로 투자 가치를 입증합니다.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- 연락처 섹션 -->
  <section class="pt-5 pb-5">
    <div class="container">
      <div class="row align-items-center justify-content-between">
        <div class="col-12 col-md-5">
          <h2>문의하기</h2>
          <p class="text-h3">고객 여러분의 소중한 문의에 성심성의껏 답변드리겠습니다.<br>아래 연락처로 연락주시거나, 오른쪽 문의 양식을 작성해주세요.</p>
          <div class="row align-items-center">
            <!-- 고객센터 전화번호 -->
            <div class="col-10 col-sm-6 mx-auto">
              <div class="my-3">
                <div class="d-inline mr-2">
                  <i class="p-2 bi bi-telephone"></i>
                </div>
                <h4 class="d-inline small"><?php echo !empty($config['contact_number']) ? htmlspecialchars($config['contact_number']) : ''; ?></h4>
              </div>
            </div>

            <!-- 팩스번호 -->
            <div class="col-10 col-sm-6 mx-auto">
              <div class="my-3">
                <div class="d-inline mr-2">
                  <i class="p-2 bi bi-printer"></i>
                </div>
                <h4 class="d-inline small"><?php echo !empty($config['fax_number']) ? htmlspecialchars($config['fax_number']) : ''; ?></h4>
              </div>
            </div>

            <!-- 이메일 -->
            <div class="col-10 col-sm-6 mx-auto">
              <div class="my-3">
                <div class="d-inline mr-2">
                  <i class="p-2 bi bi-envelope"></i>
                </div>
                <h4 class="d-inline small"><?php echo !empty($config['admin_email']) ? htmlspecialchars($config['admin_email']) : ''; ?></h4>
              </div>
            </div>

            <!-- 주소 -->
            <div class="col-10 col-sm-6 mx-auto">
              <div class="my-3">
                <div class="d-inline mr-2">
                  <i class="p-2 bi bi-geo-alt"></i>
                </div>
                <h4 class="d-inline small"><?php echo !empty($config['business_address']) ? htmlspecialchars($config['business_address']) : ''; ?></h4>
              </div>
            </div>

            <!-- 운영시간 (전체 너비) -->
            <div class="col-12 text-start">
              <div class="my-3">
                <div class="d-inline mr-2">
                  <i class="p-2 bi bi-clock"></i>
                </div>
                <h4 class="d-inline small"><?php echo !empty($config['operating_hours']) ? nl2br(htmlspecialchars($config['operating_hours'])) : ''; ?></h4>
              </div>
            </div>
          </div>
        </div>
        <div class="col-12 col-md-6 mt-4 mt-md-0">
          <!-- 문의 폼 -->
          <div id="Contact-Form">
            <div class="card">
              <div class="card-header bg-dark text-white">
                <h5 class="mb-0 text-center">문의하기</h5>
              </div>
              <div class="card-body">
                <form class="contact-form" id="contact-form">
                  <div class="mb-1">
                    <label for="manager" class="form-label d-none">담당자</label>
                    <input type="text" class="form-control" id="manager" name="name" placeholder="*담당자명" required>
                  </div>
                  <div class="mb-1">
                    <label for="email" class="form-label d-none">이메일</label>
                    <input type="email" class="form-control" id="email" name="email" placeholder="*이메일:example@email.com" required>
                  </div>
                  <div class="mb-1">
                    <label for="contactName" class="form-label d-none">연락처</label>
                    <input type="tel" class="form-control" id="contactName" name="phone" placeholder="*연락처:010-0000-0000" required>
                  </div>
                  <div class="mb-1">
                    <label for="contactSubject" class="form-label d-none">제목</label>
                    <input type="text" class="form-control" id="contactSubject" name="subject" placeholder="*제목을 입력해주세요" required>
                  </div>
                  <div class="mb-1">
                    <label for="content" class="form-label d-none">내용</label>
                    <textarea class="form-control" id="content" rows="3" name="message" placeholder="*문의 내용을 입력해주세요" required></textarea>
                  </div>
                  <button type="submit" class="btn btn-dark w-100">문의 보내기</button>
                </form>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
</main>