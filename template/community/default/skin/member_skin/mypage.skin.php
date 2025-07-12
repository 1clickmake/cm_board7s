<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가 
?>
<!-- Main Content -->
    <div class="container my-5 pt-5">
		<div class="row">   
			<div class="col-12 col-md-3 mb-3">
				<!-- Sidebar -->
				<aside class="sidebar border rounded p-3">
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item text-center"><h4 class="fw-bold">MY PAGE</h4></li>
                        <li class="list-group-item">👤 <?php echo $member['user_name'];?></li>
                        <li class="list-group-item">LV.<?php echo $member['user_lv'];?></li>
                        <li class="list-group-item"><a href="<?php echo CM_MB_URL?>/mypage.php">개인정보</a></li>
					</ul>
				</aside>
			</div>
			
			<div class="col-12 col-md-9">
				<!-- Content Area -->
				<div class="content-area">
					<div class="alert alert-light" role="alert">
						<h5 class="content-title">개인정보</h5>
						
						<div class="d-flex text-body-secondary pt-3"> 
							<div class="pb-3 mb-0 small lh-sm border-bottom w-100"> 
								<div class="d-flex justify-content-between"> 
									<strong class="text-gray-dark">ID</strong> 
									<a href="#"></a> 
								</div> 
								<span class="d-block"><?php echo $member['user_id'];?></span> 
							</div> 
						</div>
						
						<div class="d-flex text-body-secondary pt-3"> 
							<div class="pb-3 mb-0 small lh-sm border-bottom w-100"> 
								<div class="d-flex justify-content-between"> 
									<strong class="text-gray-dark">Level</strong> 
									<a href="#"></a> 
								</div> 
								<span class="d-block">Lv.<?php echo $member['user_lv'];?></span> 
							</div> 
						</div>
						
						<div class="d-flex text-body-secondary pt-3"> 
							<div class="pb-3 mb-0 small lh-sm border-bottom w-100"> 
								<div class="d-flex justify-content-between"> 
									<strong class="text-gray-dark">Name</strong> 
									<a href="#"></a> 
								</div> 
								<span class="d-block"><?php echo $member['user_name'];?></span> 
							</div> 
						</div>
						
						<div class="d-flex text-body-secondary pt-3"> 
							<div class="pb-3 mb-0 small lh-sm border-bottom w-100"> 
								<div class="d-flex justify-content-between"> 
									<strong class="text-gray-dark">Email</strong> 
									<a href="#"></a> 
								</div> 
								<span class="d-block"><?php echo $member['user_email'];?></span> 
							</div> 
						</div>
						
						<div class="d-flex text-body-secondary pt-3"> 
							<div class="pb-3 mb-0 small lh-sm border-bottom w-100"> 
								<div class="d-flex justify-content-between"> 
									<strong class="text-gray-dark">HP</strong> 
									<a href="#"></a> 
								</div> 
								<span class="d-block"><?php echo $member['user_hp'];?></span> 
							</div> 
						</div>
					</div>

					<div class="row">
						<!-- 정보 수정 -->
						<div class="col-12 col-md-6">
							<div class="alert alert-info" role="alert">
								<h5 class="content-title">정보 수정</h5>
								<p style="font-size:14px;">
								이름, 이메일, 연락처, 비밀번호를<br>
								변경하실 수 있습니다.
								</p>
								<button type="button" class="btn btn-info text-white" value="update" onclick="redirectToPass(this);">
									<i class="fas fa-user-edit me-2"></i> 정보 수정
								</button>
							</div>
						</div>
						

						<!-- 회원 탈퇴 -->
						<div class="col-12 col-md-6">
							<div class="alert alert-danger" role="alert">
							<h5 class="content-title">회원 탈퇴</h5>
							<p style="font-size:14px;">
								회원탈퇴 시 모든 개인정보내역이 삭제되며, 복구할 수 없습니다.<br>
								탈퇴 후 동일한 아이디로 재가입이 불가능합니다. 
								</p>
								<button type="button" class="btn btn-danger" value="leave" onclick="redirectToPass(this);">
									<i class="fas fa-user-slash me-2"></i> 회원 탈퇴
								</button>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
