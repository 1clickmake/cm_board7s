// 전역 URL 설정

const base_url = typeof window !== 'undefined' ? window.location.protocol + "//" + window.location.host : '';

const CM = {
	URL: base_url,
	ADMIN_URL: base_url+"/adm",
	BOARD_URL: base_url+"/board",
	MB_URL: base_url+"/member",
	LIB_URL: base_url+"/lib",
	IS_ADMIN: "super",
	IS_MOBILE: true
};
