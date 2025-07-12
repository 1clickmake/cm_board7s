$(document).ready(function() {
    // 초기 네트워크 로드
    loadInitialNetwork();

    // 초기 네트워크 로드 함수
    function loadInitialNetwork() {
        const container = $('#network-tree-container');
        container.empty();
        
        // 현재 로그인한 회원의 ID
        const currentUserId = $('#current_user_id').val();
        
        // 1단계 회원들 로드
        loadNetworkLevel(1, currentUserId, function(firstLevelMembers) {
            // 1단계 회원들의 하위 회원들을 순차적으로 로드
            firstLevelMembers.forEach(function(member) {
                loadSubMembers(member.user_id, 2);
            });
        });
    }

    // 특정 레벨의 회원들을 로드하는 함수
    function loadNetworkLevel(level, parentId, callback) {
        const container = $('#network-tree-container');
        const levelContainer = $('<div>').addClass('network-level');
        const loading = $('<div>').addClass('loading').text('로딩중...');
        
        levelContainer.append(loading);
        container.append(levelContainer);

        $.ajax({
            url: cm_url + '/network/ajax/get_network.php',
            type: 'GET',
            data: {
                level: level,
                parent_id: parentId
            },
            dataType: 'json',
            success: function(response) {
                loading.remove();
                
                if (response.error) {
                    levelContainer.append($('<div>').text(response.error));
                    return;
                }

                if (response.success && response.data.length > 0) {
                    const membersContainer = $('<div>').addClass('members-container');
                    
                    response.data.forEach(function(member) {
                        const memberGroup = $('<div>').addClass('member-group');
                        const memberNode = createMemberNode(member, level, parentId);
                        memberGroup.append(memberNode);
                        membersContainer.append(memberGroup);
                    });
                    
                    levelContainer.append(membersContainer);
                    
                    // 콜백 함수가 있다면 실행
                    if (callback) {
                        callback(response.data);
                    }
                } else {
                    levelContainer.append($('<div>').text('하위 회원이 없습니다.'));
                }
            },
            error: function() {
                loading.remove();
                levelContainer.append($('<div>').text('데이터를 불러오는데 실패했습니다.'));
            }
        });
    }

    // 하위 회원들을 재귀적으로 로드하는 함수
    function loadSubMembers(parentId, level) {
        if (level > 10) return; // 10단계까지만 로드

        loadNetworkLevel(level, parentId, function(members) {
            // 각 하위 회원에 대해 다음 레벨 로드
            members.forEach(function(member) {
                loadSubMembers(member.user_id, level + 1);
            });
        });
    }

    // 회원 노드 생성 함수
    function createMemberNode(member, level, parentId) {
        const node = $('<div>').addClass('member-node');
        const info = $('<div>').addClass('member-info');
        
        // 추천인 정보 표시
        if (parentId) {
            const recommenderLine = $('<div>').addClass('recommender-line')
                .text('추천인: ' + parentId);
            node.append(recommenderLine);
        }
        
        info.append($('<div>').addClass('member-name').text(member.user_name));
        info.append($('<div>').addClass('member-details').text('ID: ' + member.user_id));
        info.append($('<div>').addClass('member-details').text('레벨: ' + member.user_lv));
        info.append($('<div>').addClass('member-details').text('포인트: ' + member.user_point));
        
        node.append(info);
        
        // 클릭 이벤트 처리
        node.click(function() {
            // 클릭한 회원의 하위 회원들만 새로 로드
            const container = $('#network-tree-container');
            $('.network-level').each(function(index) {
                if (index >= level) {
                    $(this).remove();
                }
            });
            
            // 클릭한 회원의 하위 회원들 로드
            loadSubMembers(member.user_id, level + 1);
        });
        
        return node;
    }
}); 