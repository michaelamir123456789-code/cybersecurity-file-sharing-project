 const fileInput = document.getElementById('fileInput');
        const fileName = document.getElementById('fileName');
        const dropArea = document.getElementById('fileDropArea');

        fileInput.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                fileName.textContent = this.files[0].name;
            } else {
                fileName.textContent = 'No file chosen';
            }
        });

        dropArea.addEventListener('dragover', function(e) {
            e.preventDefault();
            this.style.borderColor = '#3b82f6';
            this.style.background = 'rgba(59, 130, 246, 0.1)';
        });

        dropArea.addEventListener('dragleave', function(e) {
            e.preventDefault();
            this.style.borderColor = 'rgba(59, 130, 246, 0.3)';
            this.style.background = 'rgba(15, 23, 42, 0.6)';
        });

        dropArea.addEventListener('drop', function(e) {
            e.preventDefault();
            this.style.borderColor = 'rgba(59, 130, 246, 0.3)';
            this.style.background = 'rgba(15, 23, 42, 0.6)';
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                fileName.textContent = files[0].name;
            }
        });
