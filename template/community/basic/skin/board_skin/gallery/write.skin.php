<?php
if (!defined('_CMBOARD_')) exit; // 개별 페이지 접근 불가
?>

<div class="container my-5">
    <h2 class="mb-4"><?php echo $bo_title;?></h2>
    
    <form action="<?php echo $formAction;?>" method="post" enctype="multipart/form-data" id="writeForm">
        <!-- Hidden Fields -->
        <input type="hidden" name="board_id" value="<?php echo $boardId;?>">
        <input type="hidden" name="board_num" value="<?php echo $boardNum ?? '';?>">
        <input type="hidden" name="parent_num" value="<?php echo $_GET['parent'] ?? '';?>">
        <input type="hidden" name="g-recaptcha-response" id="g-recaptcha-response">
        <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($member['user_id'] ?? ''); ?>">
        
        <!-- 회원/비회원 정보 입력 -->
        <?php if ($is_member): // 회원인 경우 ?>
            <input type="hidden" name="email" value="<?php echo htmlspecialchars($member['user_email'] ?? ''); ?>">
            <input type="hidden" name="name" value="<?php echo htmlspecialchars($member['user_name'] ?? ''); ?>">
            <input type="hidden" name="password" value="<?php echo $member['user_password'] ?? ''; ?>">
        <?php else: // 비회원인 경우 ?>
            <div class="mb-3">
                <label for="email" class="form-label">이메일</label>
                <input type="email" class="form-control" id="email" name="email" 
                       value="<?php echo htmlspecialchars($write['email'] ?? ''); ?>" required>
            </div>
            
            <div class="mb-3">
                <label for="name" class="form-label">이름</label>
                <input type="text" class="form-control" id="name" name="name" 
                       value="<?php echo htmlspecialchars($write['name'] ?? ''); ?>" required>
            </div>
            
            <div class="mb-3">
                <label for="password" class="form-label">
                    <?php echo isset($write) ? '비밀번호 (변경시에만 입력)' : '비밀번호'; ?>
                </label>
                <input type="password" class="form-control" id="password" name="password" 
                       <?php echo isset($write) ? '' : 'required'; ?>>
                <?php if (isset($write)): ?>
                    <small class="text-muted">비밀번호를 변경하지 않으려면 비워두세요.</small>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        
        <!-- 카테고리 -->
        <?php if(isset($bo['board_category']) && $bo['board_category']): ?>
            <div class="mb-3">
                <div class="form-group">
                    <label class="form-label">카테고리 <span class="required">*</span></label>
                    <select name="category" class="form-select" required>
                        <option value="">카테고리 선택</option>
                        <?php
                        $category_lines = explode("\n", str_replace("\r\n", "\n", $bo['board_category']));
                        foreach ($category_lines as $line) {
                            $trimmed_line = trim($line);
                            if (!empty($trimmed_line)) {
                                $selected = (isset($write['category']) && $write['category'] === $trimmed_line) ? 'selected' : '';
                                echo sprintf(
                                    '<option value="%s" %s>%s</option>',
                                    htmlspecialchars($trimmed_line),
                                    $selected,
                                    htmlspecialchars($trimmed_line)
                                );
                            }
                        }
                        ?>
                    </select>
                </div>
            </div>
        <?php endif; ?>
        
        <!-- 제목 -->
        <div class="mb-3">
            <label for="title" class="form-label">제목</label>
            <input type="text" class="form-control" id="title" name="title" 
                   value="<?php echo htmlspecialchars($write['title'] ?? ''); ?>" required>
        </div>
        
        <!-- 내용 -->
        <div class="mb-3">
            <label for="content" class="form-label">내용</label>
            <div id="editor" style="height: 300px;"><?php echo $write['content'] ?? ''; ?></div>
            <input type="hidden" name="content" id="content">
        </div>
        
        <!-- 기존 첨부파일 목록 -->
        <?php if ($currentFilename == "edit" && !empty($files)): ?>
            <div class="mb-4">
                <label class="form-label">📎 기존 첨부파일</label>
                <div class="row">
                    <?php foreach ($files as $file): 
                        $is_image = is_image_file($file['original_filename']);
                        $icon_class = get_file_icon_class($file['original_filename']);
                    ?>
                        <div class="col-md-6 col-lg-4 mb-3">
                            <div class="card shadow-sm border">
                                <div class="card-body d-flex justify-content-between align-items-center">
                                    <div class="d-flex align-items-center">
                                        <?php if ($is_image): ?>
                                            <img src="download.php?board=<?php echo $boardId;?>&file_id=<?= $file['file_id'] ?>" 
                                                 class="me-2" style="width: 30px; height: 30px; object-fit: cover;">
                                        <?php else: ?>
                                            <i class="fas <?= $icon_class ?> me-2" style="font-size: 1.2rem;"></i>
                                        <?php endif; ?>
                                        <div>
                                            <span class="text-muted"><?php echo htmlspecialchars($file['original_filename']); ?></span>
                                            <small class="d-block text-muted">
                                                <?php echo number_format($file['file_size'] / 1024, 2); ?> KB
                                            </small>
                                        </div>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" 
                                               id="delete_<?php echo $file['file_id']; ?>" 
                                               name="delete_files[]" 
                                               value="<?php echo $file['file_id']; ?>">
                                        <label class="form-check-label text-danger small" 
                                               for="delete_<?php echo $file['file_id']; ?>">삭제</label>
                                    </div>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

        <!-- 새 첨부파일 -->
        <div class="mb-4">
            <label class="form-label">첨부파일</label>
            <div class="file-upload" onclick="document.getElementById('fileInput').click()">
                <div class="file-upload-icon">📁</div>
                <div class="file-upload-text">파일을 선택하거나 여기로 드래그하세요</div>
                <div class="file-upload-hint">최대 10MB, jpg, png, gif, pdf, doc, hwp 파일만 업로드 가능</div>
                <small class="text-muted">
                    여러 파일을 선택하려면 Ctrl(Windows) 또는 Command(Mac) 키를 누른 상태에서 파일을 선택하세요.
                </small>
            </div>
            <input type="file" id="fileInput" class="file-input d-none" 
                   name="files[]" multiple 
                   accept=".jpg,.jpeg,.png,.gif,.pdf,.doc,.docx,.hwp">
            <div id="filePreview">
                <!-- 파일 미리보기가 여기에 표시됩니다 -->
            </div>
        </div>
        
        <!-- 게시글 옵션 {-->
		<?php if($is_member){?>
        <div class="alert alert-light my-4">
            <h6 class="mb-3">게시글 옵션</h6>
            <div class="d-flex flex-wrap gap-4">
                <?php if($is_admin): ?>
                    <div class="form-check">
                        <input type="checkbox" name="notice_chk" id="noticePost" 
                               class="form-check-input" 
                               <?php echo (isset($write['notice_chk']) && $write['notice_chk'] == 1) ? 'checked' : ''; ?>>
                        <label for="noticePost" class="form-check-label">공지글</label>
                    </div>
                <?php endif; ?>
                
                <div class="form-check">
                    <input type="checkbox" name="secret_chk" id="secretPost" 
                           class="form-check-input" 
                           <?php echo (isset($write['secret_chk']) && $write['secret_chk'] == 1) ? 'checked' : ''; ?>>
                    <label for="secretPost" class="form-check-label">비밀글</label>
                </div>
                
                <div class="form-check">
                    <input type="checkbox" name="reply_chk" id="replyPost" 
                           class="form-check-input" 
                           <?php echo (isset($write['reply_chk']) && $write['reply_chk'] == 1) ? 'checked' : ''; ?>>
                    <label for="replyPost" class="form-check-label">답변글 허용</label>
                </div>
                
                <div class="form-check">
                    <input type="checkbox" name="comment_chk" id="commentPost" 
                           class="form-check-input" 
                           <?php echo (isset($write['comment_chk']) && $write['comment_chk'] == 1) ? 'checked' : ''; ?>>
                    <label for="commentPost" class="form-check-label">댓글(코멘트) 허용</label>
                </div>
            </div>
        </div>
		<?php } ?>
		<!-- } 게시글 옵션 끝-->
        
        <!-- 버튼 영역 -->
        <div class="d-grid gap-2 d-md-flex justify-content-md-end">
            <button type="submit" class="btn btn-success px-4"><?php echo $writeBtn;?></button>
            <a href="<?php echo get_board_url('list', $boardId);?>" class="btn btn-secondary px-4">취소</a>
        </div>
    </form>
</div>