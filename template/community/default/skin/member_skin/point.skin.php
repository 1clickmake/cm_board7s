<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가
?>
<div class="container-fluid py-4" style="background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); min-height: 100vh;">
  <div class="card shadow-lg mx-auto" style="max-width: 1000px; border-radius: 15px;">
    <div class="card-body p-3 p-md-4">
      <h3 class="text-center mb-4" style="color: #333; font-weight: 600; font-size: 1.5rem;">포인트 내역</h3>
      <div class="d-flex justify-content-between align-items-center mb-3">
        <h5 class="mb-0" style="color: #555; font-size: 1.1rem;">토탈 적립금액</h5>
        <span class="fw-bold" style="color: #007bff; font-size: 1.1rem;">1200 포인트</span>
      </div>
      <div class="table-responsive">
        <table class="table table-hover align-middle" style="font-size: 0.9rem;">
          <thead class="table-light">
            <tr>
              <th scope="col" class="py-2">제목</th>
              <th scope="col" class="py-2 text-end">포인트</th>
              <th scope="col" class="py-2 text-center">적립일</th>
              <th scope="col" class="py-2 text-center">사용일</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td class="py-2">회원가입 축하 포인트</td>
              <td class="py-2 text-end">1000</td>
              <td class="py-2 text-center">2025-05-10</td>
              <td class="py-2 text-center">-</td>
            </tr>
            <tr>
              <td class="py-2">구매 적립</td>
              <td class="py-2 text-end">500</td>
              <td class="py-2 text-center">2025-05-12</td>
              <td class="py-2 text-center">-</td>
            </tr>
            <tr>
              <td class="py-2">포인트 사용</td>
              <td class="py-2 text-end">-300</td>
              <td class="py-2 text-center">-</td>
              <td class="py-2 text-center">2025-05-13</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="text-center mt-3">
        <a href="/points/history" class="btn btn-outline-primary btn-sm" style="border-radius: 10px; padding: 8px 16px;">전체 내역 보기</a>
      </div>
    </div>
  </div>
