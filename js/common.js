// 정렬, 검색, 문의 폼

document.addEventListener('DOMContentLoaded', function() {
  const sortableHeaders = document.querySelectorAll('.sortable');
  const sortFieldElement = document.getElementById('sort_field');
  const sortOrderElement = document.getElementById('sort_order');
  const sort_field = sortFieldElement ? sortFieldElement.value : null;
  const sort_order = sortOrderElement ? sortOrderElement.value : null;
  sortableHeaders.forEach(header => {
      if (!header) return;
      if (header.style) header.style.cursor = 'pointer';
      header.addEventListener('click', function() {
          if (sort_field === null || sort_order === null) return;
          const field = this.dataset.field;
          let newOrder = 'ASC';
          if (field === sort_field && sort_order === 'ASC') newOrder = 'DESC';
          const urlParams = new URLSearchParams(window.location.search);
          const startDate = document.getElementById('start_date').value;
          const endDate = document.getElementById('end_date').value;
          const ipAddress = document.getElementById('ip_address').value;
          if (startDate) urlParams.set('start_date', startDate);
          if (endDate) urlParams.set('end_date', endDate);
          if (ipAddress) urlParams.set('ip_address', ipAddress);
          urlParams.set('sort', field);
          urlParams.set('order', newOrder);
          window.location.href = window.location.pathname + '?' + urlParams.toString();
      });
  });
});

function validateSearch() {
  const searchType = document.getElementById('search_type').value;
  const searchKeyword = document.getElementById('search_keyword').value.trim();
  if (!searchType) {
      alert('검색 구분 선택');
      document.getElementById('search_type').focus();
      return false;
  }
  if (!searchKeyword) {
      alert('검색어 입력');
      document.getElementById('search_keyword').focus();
      return false;
  }
  return true;
}

const contactForm = document.getElementById('contact-form');
if (contactForm) {
  contactForm.addEventListener('submit', function(event) {
      event.preventDefault();
      const form = event.target;
      const formData = new FormData(form);
      fetch(CM.BOARD_URL + '/contact_update.php', {
          method: 'POST',
          body: formData
      })
      .then(response => response.json())
      .then(data => {
          if (data.success) {
              alert(data.message);
              form.reset();
          } else {
              alert('Error: ' + data.message);
          }
      })
      .catch(() => {
          alert('문의 전송 오류');
      });
  });
}