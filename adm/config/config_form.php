<?php
include_once './_common.php';
$cm_title = "기본 환경설정";
include_once CM_ADMIN_PATH.'/admin.head.php';
?>

<!-- Main Content -->
<div class="main-content shifted" id="mainContent">
	<div class="container-fluid">
		<!-- 헤더 카드 -->
            <div class="card shadow-sm mb-4 border-0 card-move">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h2 class="card-title mb-1 text-primary">
                                <i class="bi bi-gear me-2"></i><?php echo $cm_title;?>
                            </h2>
                            <p class="card-text text-muted mb-0">홈페이지 기본 환경설정</p>
                        </div>
                    </div>
                </div>
            </div>
		
		<div class="row justify-content-center">
			<div class="col">
				<div class="card chart-card shadow-lg">
					<div class="card-header">
						<h5 class="card-title mb-0">
							<i class="fas fa-wrench me-2"></i>
							홈페이지 기본 설정
						</h5>
					</div>
					<div class="card-body p-4">
						<form action="./config_form_update.php" method="post">
							<!-- CSRF 토큰 (예시) -->
							<!-- <input type="hidden" name="csrf_token" value="<?php // echo htmlspecialchars($_SESSION['csrf_token']); ?>"> -->
							<!-- 홈페이지 정보 섹션 -->
							<div class="mb-5 site-info-section">
								<h6 class="text-muted fw-bold mb-3">
									<i class="fas fa-globe me-2"></i>
									홈페이지 정보
								</h6>
								
								<div class="mb-4">
									<label for="siteTitle" class="form-label fw-semibold">
										<i class="fas fa-heading me-2 text-primary"></i>
										홈페이지 제목
									</label>
									<div class="input-group">
										<span class="input-group-text bg-light">
											<i class="fas fa-home"></i>
										</span>
										<input type="text" class="form-control" id="siteTitle" name="site_title" 
											   placeholder="홈페이지 제목을 입력하세요" 
											   value="<?php echo htmlspecialchars($config['site_title'] ?? '');?>" required>
									</div>
								</div>
								
								<div class="mb-4">
									<label for="adminEmail" class="form-label fw-semibold">
										<i class="fas fa-envelope me-2 text-success"></i>
										관리자 이메일
									</label>
									<div class="input-group">
										<span class="input-group-text bg-light">
											<i class="fas fa-at"></i>
										</span>
										<input type="email" class="form-control" id="adminEmail" name="admin_email" 
											   placeholder="관리자 이메일을 입력하세요" 
											   value="<?php echo htmlspecialchars($config['admin_email'] ?? '');?>" required>
									</div>
								</div>
								
								<div class="mb-4">
									<label for="contactNumber" class="form-label fw-semibold">
										<i class="fas fa-phone me-2 text-info"></i>
										고객센터
									</label>
									<div class="input-group">
										<span class="input-group-text bg-light">
											<i class="fas fa-mobile-alt"></i>
										</span>
										<input type="tel" class="form-control" id="contactNumber" name="contact_number" 
											   value="<?php echo htmlspecialchars($config['contact_number'] ?? '');?>" 
											   placeholder="연락처를 입력하세요 (예: 010-1234-5678)">
									</div>
								</div>
								
								<div class="mb-4">
									<label for="contactNumber" class="form-label fw-semibold">
										<i class="fas fa-fax me-2 text-info"></i>
										팩스번호
									</label>
									<div class="input-group">
										<span class="input-group-text bg-light">
											<i class="fas fa-fax"></i>
										</span>
										<input type="tel" class="form-control" id="faxtNumber" name="fax_number" 
											   value="<?php echo htmlspecialchars($config['fax_number'] ?? '');?>" 
											   placeholder="팩스번호를 입력하세요 (예: 010-1234-5678)">
									</div>
								</div>
								
								<div class="mb-4">
									<label for="representativeName" class="form-label fw-semibold">
										<i class="fas fa-user me-2 text-primary"></i>
										대표자명
									</label>
									<div class="input-group">
										<span class="input-group-text bg-light">
											<i class="fas fa-user-tie"></i>
										</span>
										<input type="text" class="form-control" id="representativeName" name="representative_name" 
											value="<?php echo htmlspecialchars($config['representative_name'] ?? '');?>" 
											placeholder="대표자명을 입력하세요">
									</div>
								</div>

								<div class="mb-4">
									<label for="privacyManager" class="form-label fw-semibold">
										<i class="fas fa-user-shield me-2 text-warning"></i>
										개인정보보호 책임자
									</label>
									<div class="input-group">
										<span class="input-group-text bg-light">
											<i class="fas fa-user-secret"></i>
										</span>
										<input type="text" class="form-control" id="privacyManager" name="privacy_manager" 
											   value="<?php echo htmlspecialchars($config['privacy_manager'] ?? '');?>" 
											   placeholder="개인정보보호 책임자명을 입력하세요">
									</div>
								</div>

								<!-- 사업자 정보 -->
								<h6 class="text-muted fw-bold mb-3 mt-5">
									<i class="fas fa-building me-2"></i>
									사업자 정보 (br 태그 입력 가능)
								</h6>
								<div class="row">
									<div class="col-md-6 mb-4">
										<label for="businessRegNo" class="form-label fw-semibold">
											<i class="fas fa-id-card me-2 text-secondary"></i>
											사업자번호
										</label>
										<div class="input-group">
											<span class="input-group-text bg-light">
												<i class="fas fa-building"></i>
											</span>
											<input type="text" class="form-control" id="businessRegNo" name="business_reg_no" 
												   value="<?php echo htmlspecialchars($config['business_reg_no'] ?? '');?>" 
												   placeholder="사업자번호를 입력하세요">
										</div>
									</div>
									<div class="col-md-6 mb-4">
										<label for="onlineSalesNo" class="form-label fw-semibold">
											<i class="fas fa-store me-2 text-warning"></i>
											통신판매신고번호
										</label>
										<div class="input-group">
											<span class="input-group-text bg-light">
												<i class="fas fa-shopping-cart"></i>
											</span>
											<input type="text" class="form-control" id="onlineSalesNo" name="online_sales_no" 
												   value="<?php echo htmlspecialchars($config['online_sales_no'] ?? '');?>" 
												   placeholder="통신판매신고번호를 입력하세요">
										</div>
									</div>
									
									<div class="col-md-6 mb-4">
										<label for="businessType" class="form-label fw-semibold">
											<i class="fas fa-briefcase me-2 text-info"></i>
											업태
										</label>
										<div class="input-group">
											<span class="input-group-text bg-light">
												<i class="fas fa-industry"></i>
											</span>
											<input type="text" class="form-control" id="businessType" name="business_type" 
												   value="<?php echo htmlspecialchars($config['business_type'] ?? '');?>" 
												   placeholder="업태를 입력하세요">
										</div>
									</div>
									
									<div class="col-md-6 mb-4">
										<label for="businessCategory" class="form-label fw-semibold">
											<i class="fas fa-tags me-2 text-success"></i>
											종목
										</label>
										<div class="input-group">
											<span class="input-group-text bg-light">
												<i class="fas fa-list-alt"></i>
											</span>
											<input type="text" class="form-control" id="businessCategory" name="business_category" 
												   value="<?php echo htmlspecialchars($config['business_category'] ?? '');?>" 
												   placeholder="종목을 입력하세요">
										</div>
									</div>	

									<div class="col-12 mb-4">
										<label for="businessAddress" class="form-label fw-semibold">
											<i class="fas fa-map-marker-alt me-2 text-danger"></i>
											사업장 주소
										</label>
										<div class="input-group">
											<span class="input-group-text bg-light">
												<i class="fas fa-address-card"></i>
											</span>
											<textarea class="form-control" id="businessAddress" name="business_address" rows="2" placeholder="사업장 주소를 입력하세요"><?php echo $config['business_address'] ?? '';?></textarea>
										</div>
									</div>
								</div>
								
								<div class="row">
									
									<div class="col-md-12 mb-4">
										<label for="operatingHours" class="form-label fw-semibold">
											<i class="fas fa-clock me-2 text-warning"></i>
											운영시간
										</label>
										<div class="input-group">
											<span class="input-group-text bg-light">
												<i class="fas fa-business-time"></i>
											</span>
											<textarea class="form-control" id="operatingHours" name="operating_hours" rows="2" placeholder="예: 평일 09:00 - 18:00&#10;주말 및 공휴일 휴무"><?php echo $config['operating_hours'] ?? '';?></textarea>
										</div>
									</div>
								</div>

								<!-- 입금 계좌 정보 -->
								<h6 class="text-muted fw-bold mb-3 mt-5">
									<i class="fas fa-credit-card me-2"></i>
									입금 계좌 정보
								</h6>
								<div class="row">
									<div class="col-md-4 mb-4">
										<label for="bankName" class="form-label fw-semibold">
											<i class="fas fa-university me-2 text-primary"></i>
											은행명
										</label>
										<div class="input-group">
											<span class="input-group-text bg-light">
												<i class="fas fa-building"></i>
											</span>
											<input type="text" class="form-control" id="bankName" name="bank_name" 
												   value="<?php echo htmlspecialchars($config['bank_name'] ?? '');?>" 
												   placeholder="은행명을 입력하세요">
										</div>
									</div>
									<div class="col-md-4 mb-4">
										<label for="accountHolder" class="form-label fw-semibold">
											<i class="fas fa-user-circle me-2 text-success"></i>
											예금주
										</label>
										<div class="input-group">
											<span class="input-group-text bg-light">
												<i class="fas fa-user"></i>
											</span>
											<input type="text" class="form-control" id="accountHolder" name="account_holder" 
												   value="<?php echo htmlspecialchars($config['account_holder'] ?? '');?>" 
												   placeholder="예금주를 입력하세요">
										</div>
									</div>

									<div class="col-md-4 mb-4">
										<label for="accountNumber" class="form-label fw-semibold">
											<i class="fas fa-money-check-alt me-2 text-warning"></i>
											계좌번호 
										</label>
										<div class="input-group">
											<span class="input-group-text bg-light"><i class="fas fa-credit-card"></i></span>
											<input type="text" class="form-control" id="accountNumber" name="account_number" value="<?php echo htmlspecialchars($config['account_number'] ?? '');?>" placeholder="계좌번호를 입력하세요">
										</div>
									</div>
								</div>
							</div>

							<!--추가 메타, js -->
									<div class="mb-5">
										<h6 class="text-muted fw-bold mb-3">
											<i class="fas fa-code me-2"></i>
											추가 메타 태그 및 스크립트
										</h6>
										<div class="row">
											<div class="col-md-6 mb-4">
												<label for="add_meta" class="form-label fw-semibold">
													<i class="fas fa-tags me-2 text-primary"></i>
													추가 메타 태그
												</label>
												<textarea class="form-control font-monospace" id="add_meta" name="add_meta" 
													  rows="5" placeholder="<meta> 태그를 입력하세요 (예: <meta name='description' content='사이트 설명'>)"><?php echo htmlspecialchars($config['add_meta'] ?? ''); ?></textarea>
												<div class="form-text">
													<head> 태그 내에 추가할 메타 태그를 입력하세요.
												</div>
											</div>
											<div class="col-md-6 mb-4">
												<label for="add_js" class="form-label fw-semibold">
													<i class="fab fa-js me-2 text-warning"></i>
													추가 JavaScript 코드
												</label>
												<textarea class="form-control font-monospace" id="add_js" name="add_js" 
													  rows="5" placeholder="<script> 태그를 제외한 JavaScript 코드를 입력하세요"><?php echo htmlspecialchars($config['add_js'] ?? ''); ?></textarea>
												<div class="form-text">
													페이지 하단에 추가할 JavaScript 코드를 입력하세요. &lt;script&gt; 태그는 자동으로 추가됩니다.
												</div>
											</div>
										</div>
									</div>
									

							<!-- 보안 설정 섹션 -->
							<div class="mb-5">
								<h6 class="text-muted fw-bold mb-3">
									<i class="fas fa-shield-alt me-2"></i>
									보안 설정
								</h6>
								<div class="mb-4">
									<label for="ip_access" class="form-label fw-semibold">
										<i class="fas fa-check-circle me-2 text-success"></i>
										접근가능 IP
									</label>
									<div class="alert alert-info py-2 mb-2" role="alert">
										<i class="fas fa-info-circle me-2"></i>
										<small>입력된 IP의 컴퓨터만 접근가능합니다. 123.123.+ 형식도 가능하며, 엔터로 구분해주세요.</small>
									</div>
									<div class="input-group">
										<span class="input-group-text bg-light">
											<i class="fas fa-unlock"></i>
										</span>
										<textarea class="form-control" id="ip_access" name="ip_access" rows="4" 
												  placeholder="예:&#10;192.168.1.1&#10;123.123.+&#10;10.0.0.1"><?php echo htmlspecialchars($config['ip_access'] ?? '');?></textarea>
									</div>
								</div>
								
								<div class="mb-4">
									<label for="ip_block" class="form-label fw-semibold">
										<i class="fas fa-times-circle me-2 text-danger"></i>
										접근차단 IP
									</label>
									<div class="alert alert-warning py-2 mb-2" role="alert">
										<i class="fas fa-exclamation-triangle me-2"></i>
										<small>입력된 IP의 컴퓨터는 접근이 차단됩니다. 123.123.+ 형식도 가능하며, 엔터로 구분해주세요.</small>
									</div>
									<div class="input-group">
										<span class="input-group-text bg-light">
											<i class="fas fa-ban"></i>
										</span>
										<textarea class="form-control" id="ip_block" name="ip_block" rows="4" 
												  placeholder="예:&#10;192.168.1.100&#10;123.123.+&#10;10.0.0.100"><?php echo htmlspecialchars($config['ip_block'] ?? '');?></textarea>
									</div>
								</div>
							</div>

							<!-- SNS 링크 설정 섹션 -->
							<div class="mb-5">
								<h6 class="text-muted fw-bold mb-3">
									<i class="fas fa-share-alt me-2"></i>
									SNS 링크 설정
								</h6>
								<div class="row">
									<div class="col-md-6 mb-3">
										<label for="sns_facebook" class="form-label">
											<i class="fab fa-facebook me-2 text-primary"></i>Facebook URL
										</label>
										<input type="url" class="form-control" id="sns_facebook" name="sns_facebook" 
											   value="<?php echo htmlspecialchars($config['sns_facebook'] ?? ''); ?>" 
											   placeholder="https://facebook.com/yourpage">
									</div>
									<div class="col-md-6 mb-3">
										<label for="sns_x" class="form-label">
											<i class="fab fa-twitter me-2 text-info"></i>X (Twitter) URL
										</label>
										<input type="url" class="form-control" id="sns_x" name="sns_x" 
											   value="<?php echo htmlspecialchars($config['sns_x'] ?? ''); ?>" 
											   placeholder="https://x.com/yourprofile">
									</div>
									<div class="col-md-6 mb-3">
										<label for="sns_kakao" class="form-label">
											<i class="fas fa-comment me-2 text-warning"></i>Kakao URL
										</label>
										<input type="url" class="form-control" id="sns_kakao" name="sns_kakao" 
											   value="<?php echo htmlspecialchars($config['sns_kakao'] ?? ''); ?>" 
											   placeholder="https://pf.kakao.com/yourpage">
									</div>
									<div class="col-md-6 mb-3">
										<label for="sns_naver" class="form-label">
											<i class="fas fa-blog me-2 text-success"></i>Naver Blog URL
										</label>
										<input type="url" class="form-control" id="sns_naver" name="sns_naver" 
											   value="<?php echo htmlspecialchars($config['sns_naver'] ?? ''); ?>" 
											   placeholder="https://blog.naver.com/yourblog">
									</div>
									<div class="col-md-6 mb-3">
										<label for="sns_line" class="form-label">
											<i class="fab fa-line me-2 text-success"></i>LINE URL
										</label>
										<input type="url" class="form-control" id="sns_line" name="sns_line" 
											   value="<?php echo htmlspecialchars($config['sns_line'] ?? ''); ?>" 
											   placeholder="https://line.me/ti/p/yourlineid">
									</div>
									<div class="col-md-6 mb-3">
										<label for="sns_pinterest" class="form-label">
											<i class="fab fa-pinterest me-2 text-danger"></i>Pinterest URL
										</label>
										<input type="url" class="form-control" id="sns_pinterest" name="sns_pinterest" 
											   value="<?php echo htmlspecialchars($config['sns_pinterest'] ?? ''); ?>" 
											   placeholder="https://pinterest.com/yourprofile">
									</div>
									<div class="col-md-6 mb-3">
										<label for="sns_linkedin" class="form-label">
											<i class="fab fa-linkedin me-2 text-primary"></i>LinkedIn URL
										</label>
										<input type="url" class="form-control" id="sns_linkedin" name="sns_linkedin" 
											   value="<?php echo htmlspecialchars($config['sns_linkedin'] ?? ''); ?>" 
											   placeholder="https://linkedin.com/in/yourprofile">
									</div>
								</div>
							</div>

							<!-- reCAPTCHA 설정 섹션 -->
							<div class="mb-5">
								<h6 class="text-muted fw-bold mb-3">
									<i class="fab fa-google me-2"></i>
									Google  설정
								</h6>
								<div class="alert alert-secondary py-2 mb-3" role="alert">
									<i class="bi bi-envelope-at-fill me-2"></i>
									<small>Google gmail을 사용하여 email을 발송합니다.</small>
								</div>
								
								<div class="mb-4">
									<label for="google_email" class="form-label fw-semibold">
										<i class="bi bi-envelope text-warning"></i>
										구글계정 이메일
									</label>
									<div class="input-group">
										<span class="input-group-text bg-light">
											<i class="bi bi-envelope"></i>
										</span>
										<input type="text" class="form-control" id="google_email" name="google_email" 
											   value="<?php echo htmlspecialchars($config['google_email'] ?? '');?>" 
											   placeholder="google_email을 입력하세요. ex) gmail@gmail.com">
									</div>
								</div>
								
								<div class="mb-4">
									<label for="google_appkey" class="form-label fw-semibold">
										<i class="fas fa-key me-2 text-warning"></i>
										Gmail App Key
									</label>
									<div class="input-group">
										<span class="input-group-text bg-light">
											<i class="bi bi-shield-lock"></i>
										</span>
										<input type="text" class="form-control" id="google_appkey" name="google_appkey" 
											   value="<?php echo htmlspecialchars($config['google_appkey'] ?? '');?>" 
											   placeholder="Gmail App Key를 입력하세요">
									</div>
								</div>
								
								<div class="alert alert-secondary py-2 mb-3" role="alert">
									<i class="fas fa-robot me-2"></i>
									<small>Google reCAPTCHA v3을 사용하여 스팸을 방지할 수 있습니다.</small>
								</div>
								
								<div class="mb-4">
									<label for="recaptcha_site_key" class="form-label fw-semibold">
										<i class="fas fa-key me-2 text-warning"></i>
										reCAPTCHA v3 Site Key
									</label>
									<div class="input-group">
										<span class="input-group-text bg-light">
											<i class="fas fa-globe"></i>
										</span>
										<input type="text" class="form-control" id="recaptcha_site_key" name="recaptcha_site_key" 
											   value="<?php echo htmlspecialchars($config['recaptcha_site_key'] ?? '');?>" 
											   placeholder="Google reCAPTCHA Site Key를 입력하세요">
									</div>
								</div>
								
								<div class="mb-4">
									<label for="recaptcha_secret_key" class="form-label fw-semibold">
										<i class="fas fa-lock me-2 text-danger"></i>
										reCAPTCHA v3 Secret Key
									</label>
									<div class="input-group">
										<span class="input-group-text bg-light">
											<i class="fas fa-shield-alt"></i>
										</span>
										<input type="password" class="form-control" id="recaptcha_secret_key" name="recaptcha_secret_key" 
											   value="<?php echo htmlspecialchars($config['recaptcha_secret_key'] ?? '');?>" 
											   placeholder="Google reCAPTCHA Secret Key를 입력하세요">
										<button class="btn btn-outline-secondary" type="button" id="togglePassword" onclick="togglePasswordVisibility('recaptcha_secret_key', this)">
											<i class="fas fa-eye"></i>
										</button>
									</div>
								</div>
								
								<div id="google_map" class="mb-4">
									<label for="google_map_iframe_src" class="form-label fw-semibold">
										<i class="fas fa-map-marked-alt me-2 text-success"></i>
										구글 지도 iframe src
									</label>
									<div class="alert alert-info py-2 mb-2" role="alert">
										<i class="fas fa-info-circle me-2"></i>
										<small>구글 지도에서 '공유' > '지도 퍼가기'를 통해 얻은 HTML 코드 중 <code>src="..."</code> 부분의 URL을 입력하세요.</small>
									</div>
									<div class="input-group">
										<span class="input-group-text bg-light">
											<i class="fas fa-code"></i>
										</span>
										<textarea class="form-control" id="google_map_iframe_src" name="google_map_iframe_src" rows="3" placeholder="https://www.google.com/maps/embed?pb=..."><?php echo htmlspecialchars($config['google_map_iframe_src'] ?? '');?></textarea>
									</div>
								</div>
							</div>
							
							<!-- 번역 관리 -->
							<div class="mb-5">
								<h6 class="text-muted fw-bold mb-3 mt-5">
									<i class="bi bi-globe2 me-2"></i>
									deepl.com 번역설정
								</h6>
								<div class="alert alert-secondary py-2 mb-3" role="alert">
									<i class="fas fa-robot me-2"></i>
									<small>deepl API 를 이용해 홈페이지를 번역할 수 있습니다.</small>
								</div>
								
								<div class="row">
									<div class="mb-4">
										<label class="form-label fw-semibold">
											<i class="fas fa-server me-2 text-info"></i>
											DeepL 번역
										</label>
										
										
										<div>
											<div class="form-check form-check-inline">
												<input class="form-check-input" type="radio" name="deepl_api_use" id="deepl_use1" value="1"
													<?php echo (($config['deepl_api_use'] ?? '0') == '1') ? 'checked' : ''; ?>>
												<label class="form-check-label" for="deepl_use1">
													<i class="bi bi-check-lg me-1 text-danger"></i> 사용함
												</label>
											</div>
											<div class="form-check form-check-inline">
												<input class="form-check-input" type="radio" name="deepl_api_use" id="deepl_use0" value="0"
													<?php echo (($config['deepl_api_use'] ?? '0') == '0') ? 'checked' : ''; ?>>
												<label class="form-check-label" for="deepl_use0">
													<i class="bi bi-x-lg me-1"></i> 사용안함
												</label>
											</div>
										</div>
									</div>
									
									<div class="mb-4">
										<label for="cfOriginalLang" class="form-label fw-semibold">
											<i class="fas fa-language me-2 text-info"></i>
											사이트 원본 언어
										</label>
										<div class="input-group">
											<span class="input-group-text bg-light">
												<i class="fas fa-flag"></i>
											</span>
											<select class="form-select" id="cfOriginalLang" name="cf_original_lang">
												<option value="KO" <?php echo (($config['cf_original_lang'] ?? 'KO') === 'KO') ? 'selected' : ''; ?>>한국어 (Korean)</option>
												<option value="EN" <?php echo (($config['cf_original_lang'] ?? '') === 'EN') ? 'selected' : ''; ?>>영어 (English)</option>
												<option value="JA" <?php echo (($config['cf_original_lang'] ?? '') === 'JA') ? 'selected' : ''; ?>>일본어 (Japanese)</option>
											</select>
										</div>
										<div class="form-text">
											<i class="fas fa-info-circle text-muted me-1"></i>
											사이트의 기본 언어를 설정합니다. DeepL 번역 시 원본 언어로 사용됩니다.
										</div>
									</div>
								
									<div class="mb-4">
										<label for="deepl_api_key" class="form-label fw-semibold">
											<i class="fas fa-key me-2 text-primary"></i>
											DeepL API Key
										</label>
										<div class="input-group">
											<span class="input-group-text bg-light">
												<i class="fas fa-language"></i>
											</span>
											<input type="password" class="form-control" id="deepl_api_key" name="deepl_api_key"
												   value="<?php echo htmlspecialchars($config['deepl_api_key'] ?? '');?>"
												   placeholder="DeepL API Key를 입력하세요 (예: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx:fx)">
											<button class="btn btn-outline-secondary" type="button" id="toggleDeepLKey" onclick="togglePasswordVisibility('deepl_api_key', this)">
												<i class="fa fa-eye"></i>
											</button>
										</div>
									</div>
									
									<div class="mb-4">
										<label class="form-label fw-semibold">
											<i class="fas fa-server me-2 text-info"></i>
											DeepL API 플랜
										</label>
										<div class="alert alert-info py-2 mb-2" role="alert">
											<i class="fas fa-info-circle text-muted me-1"></i>사용 중인 DeepL API 플랜을 선택하세요. API 호출 URL이 결정됩니다.
										</div>
										<div>
											<div class="form-check form-check-inline">
												<input class="form-check-input" type="radio" name="deepl_api_plan" id="deepl_free_plan" value="free"
													<?php echo (empty($config['deepl_api_plan']) || ($config['deepl_api_plan'] ?? '') === 'free') ? 'checked' : ''; ?>>
												<label class="form-check-label" for="deepl_free_plan">
													<i class="fab fa-creative-commons-share me-1"></i>Free (api-free.deepl.com)
												</label>
											</div>
											<div class="form-check form-check-inline">
												<input class="form-check-input" type="radio" name="deepl_api_plan" id="deepl_pro_plan" value="pro"
													<?php echo (($config['deepl_api_plan'] ?? '') === 'pro') ? 'checked' : ''; ?>>
												<label class="form-check-label" for="deepl_pro_plan">
													<i class="fas fa-crown me-1 text-warning"></i>Pro (api.deepl.com)
												</label>
											</div>
										</div>
									</div>
								
								</div>
							</div>

							<!-- PWA 설정 카드 -->
							<div class="card mb-4 border-0 shadow-sm d-none">
								<div class="card-header bg-white py-3">
									<h5 class="mb-0">
										<i class="fas fa-mobile-alt me-2 text-primary"></i>
										PWA(프로그레시브 웹 앱) 설정
									</h5>
								</div>
								<div class="card-body">
									<!-- PWA 사용 여부 -->
									<div class="mb-4">
										<div>
											<div class="form-check form-check-inline">
												<input class="form-check-input" type="radio" name="pwa_use" id="pwa_use1" value="1"
													<?php echo (($config['pwa_use'] ?? '0') == '1') ? 'checked' : ''; ?>>
												<label class="form-check-label" for="pwa_use1">
													<i class="bi bi-check-lg me-1 text-danger"></i> 사용함
												</label>
											</div>
											<div class="form-check form-check-inline">
												<input class="form-check-input" type="radio" name="pwa_use" id="pwa_use0" value="0"
													<?php echo (($config['pwa_use'] ?? '0') == '0') ? 'checked' : ''; ?>>
												<label class="form-check-label" for="pwa_use0">
													<i class="bi bi-x-lg me-1"></i> 사용안함
												</label>
											</div>
											
											<small class="form-text text-muted">
												<i class="fas fa-info-circle me-1"></i>
												<a href="#" data-bs-toggle="modal" data-bs-target="#pwaGuideModal" class="text-decoration-none">
													PWA를 활성화하면 사용자가 홈 화면에 앱을 설치할 수 있습니다. (가이드 보기)
												</a>
											</small>

											<!-- PWA 가이드 모달 -->
											<div class="modal fade" id="pwaGuideModal" tabindex="-1" aria-labelledby="pwaGuideModalLabel" aria-hidden="true">
												<div class="modal-dialog modal-lg modal-dialog-scrollable">
													<div class="modal-content">
														<div class="modal-header bg-light">
															<h5 class="modal-title" id="pwaGuideModalLabel">
																<i class="fas fa-mobile-alt me-2"></i>PWA 설치 및 설정 가이드
															</h5>
															<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
														</div>
														<div class="modal-body bg-white">
															<?php
								// 문서 루트를 기준으로 PWA 가이드 파일 경로 구성
								$pwa_guide_file = rtrim($_SERVER['DOCUMENT_ROOT'], '/') . '/PWA_SETUP_GUIDE.md';
								
								// 파일 존재 및 읽기 권한 확인
								if (file_exists($pwa_guide_file) && is_readable($pwa_guide_file)) {
									echo '<div class="p-3 bg-light rounded">';
									echo '<pre class="mb-0" style="white-space: pre-wrap; max-height: 60vh; overflow-y: auto;">';
									echo htmlspecialchars(file_get_contents($pwa_guide_file), ENT_QUOTES, 'UTF-8');
									echo '</pre>';
									echo '</div>';
								} else {
									echo '<div class="alert alert-warning">';
									echo '<i class="fas fa-exclamation-triangle me-2"></i>';
									echo 'PWA 설정 가이드 파일을 찾을 수 없거나 읽을 수 없습니다. 파일 경로: ' . htmlspecialchars($pwa_guide_file);
									echo '</div>';
											}
															?>
														</div>
														<div class="modal-footer bg-light">
															<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
																<i class="fas fa-times me-1"></i>닫기
															</button>
														</div>
													</div>
												</div>
											</div>
										</div>
										
										
									</div>

									<!-- PWA 기본 설정 -->
									<div class="row g-3">
										<!-- VAPID 공개 키 -->
										<div class="col-12">
											<label for="pwa_vapid_public_key" class="form-label fw-semibold">
												<i class="fas fa-key me-2"></i>
												VAPID 공개 키 (Public Key)
											</label>
											<div class="input-group">
												<span class="input-group-text bg-light">
													<i class="fas fa-lock"></i>
												</span>
												<input type="text" class="form-control" id="pwa_vapid_public_key" 
													   name="pwa_vapid_public_key"
													   value="<?php echo htmlspecialchars($config['pwa_vapid_public_key'] ?? '');?>"
													   placeholder="VAPID 공개 키를 입력하세요">
											</div>
											<small class="form-text text-muted">
												웹 푸시 알림을 위한 VAPID 공개 키입니다.
											</small>
										</div>

										<!-- VAPID 비공개 키 -->
										<div class="col-12">
											<label for="pwa_vapid_private_key" class="form-label fw-semibold">
												<i class="fas fa-key me-2"></i>
												VAPID 비공개 키 (Private Key)
											</label>
											<div class="input-group">
												<span class="input-group-text bg-light">
													<i class="fas fa-lock"></i>
												</span>
												<input type="password" class="form-control" id="pwa_vapid_private_key" 
													   name="pwa_vapid_private_key"
													   value="<?php echo htmlspecialchars($config['pwa_vapid_private_key'] ?? '');?>"
													   placeholder="VAPID 비공개 키를 입력하세요">
												<button class="btn btn-outline-secondary" type="button" onclick="togglePasswordVisibility('pwa_vapid_private_key', this)">
													<i class="fas fa-eye"></i>
												</button>
											</div>
											<small class="form-text text-muted">
												보안을 위해 반드시 안전하게 보관하세요.
											</small>
										</div>

									</div>
								</div>
								<div class="card-footer bg-light">
									<small class="text-muted">
										<i class="fas fa-info-circle me-1"></i>
										PWA 설정을 변경한 후에는 반드시 설정을 저장하세요.
									</small>
								</div>
							</div>
							
							<hr>
							<!-- 여분필드 -->
							<div class="mb-5">
								<h6 class="text-muted fw-bold mb-3 mt-5">
									<i class="fas fa-plus-circle me-2"></i>
									여분필드
								</h6>
								<?php
								for ($i=1 ; $i <= 5; $i++){
								?>
								<div class="row">
									<div class="col-md-4 mb-4">
										<label for="cf_add_sub_<?php echo $i?>" class="form-label fw-semibold d-none">
											<i class="fas fa-tag me-2 text-primary"></i>
											여분필드<?php echo $i?> 제목
										</label>
										<div class="input-group">
											<span class="input-group-text bg-light">
												<i class="fas fa-tag"></i>
											</span>
											<input type="text" class="form-control" id="cf_add_sub_<?php echo $i?>" name="cf_add_sub_<?php echo $i?>" 
												   value="<?php echo htmlspecialchars($config['cf_add_sub_'.$i] ?? '');?>" 
												   placeholder="여분필드<?php echo $i?> 제목">
										</div>
									</div>
									<div class="col-md-8 mb-4">
										<label for="cf_add_con_<?php echo $i?>" class="form-label fw-semibold d-none">
											<i class="fas fa-edit me-2 text-success"></i>
											여분필드<?php echo $i?> 내용
										</label>
										<div class="input-group">
											<span class="input-group-text bg-light">
												<i class="fas fa-edit"></i>
											</span>
											<input type="text" class="form-control" id="cf_add_con_<?php echo $i?>" name="cf_add_con_<?php echo $i?>" 
												   value="<?php echo htmlspecialchars($config['cf_add_con_'.$i] ?? '');?>" 
												   placeholder="여분필드<?php echo $i?> 내용">
										</div>
									</div>
								</div>
								<?php } ?>
							</div>

							
							<!-- 저장 버튼 -->
							<div class="d-grid gap-2 d-md-flex justify-content-md-end">
								<button type="submit" class="btn btn-primary btn-lg px-5">
									<i class="fas fa-save me-2"></i>
									설정 저장
								</button>
							</div>
						</form>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>

<script>
/**
 * 비밀번호 보기/숨기기 토글 함수
 * @param {string} fieldId - 토글할 입력 필드의 ID
 * @param {HTMLElement} button - 클릭된 버튼 요소
 */
function togglePasswordVisibility(fieldId, button) {
    const field = document.getElementById(fieldId);
    const icon = button.querySelector('i');
    
    if (!field) return;
    
    if (field.type === 'password') {
        field.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        field.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}

// HTML에 있는 토글 버튼에 이벤트 연결
document.addEventListener('DOMContentLoaded', function() {
    // 모든 토글 버튼에 클릭 이벤트 연결
    document.querySelectorAll('.toggle-password').forEach(button => {
        // 가장 가까운 부모 요소에서 input[type="password"] 또는 input[type="text"] 찾기
        const input = button.closest('.input-group').querySelector('input');
        if (input) {
            button.onclick = function() {
                togglePasswordVisibility(input.id, this);
            };
        }
    });
});

// 폼 유효성 검사 시각적 피드백
document.querySelector('form').addEventListener('submit', function(e) {
    const requiredFields = this.querySelectorAll('[required]');
    let isValid = true;
    
    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            field.classList.add('is-invalid');
            isValid = false;
        } else {
            field.classList.remove('is-invalid');
            field.classList.add('is-valid');
        }
    });
    
    if (!isValid) {
        e.preventDefault();
        alert('필수 입력 항목을 모두 입력해주세요.');
    }
});

// 실시간 유효성 검사
document.querySelectorAll('input[required]').forEach(input => {
    input.addEventListener('blur', function() {
        if (this.value.trim()) {
            this.classList.remove('is-invalid');
            this.classList.add('is-valid');
        } else {
            this.classList.remove('is-valid');
            this.classList.add('is-invalid');
        }
    });
});
</script>

<?php
include_once CM_ADMIN_PATH.'/admin.tail.php';
?>