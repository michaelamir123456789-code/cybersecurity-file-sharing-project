 // Password visibility toggle
        function togglePassword() {
            const input = document.getElementById('password');
            const btn = event.target;
            if (input.type === 'password') {
                input.type = 'text';
                btn.textContent = '🙈';
            } else {
                input.type = 'password';
                btn.textContent = '👁️';
            }
        }

        function toggleConfirmPassword() {
            const input = document.getElementById('confirmPassword');
            const btn = event.target;
            if (input.type === 'password') {
                input.type = 'text';
                btn.textContent = '🙈';
            } else {
                input.type = 'password';
                btn.textContent = '👁️';
            }
        }

        // Password strength checker
        const password = document.getElementById('password');
        const confirm = document.getElementById('confirmPassword');
        const strengthFill = document.getElementById('strengthFill');
        const strengthText = document.getElementById('strengthText');

        const reqLength = document.getElementById('req-length');
        const reqUpper = document.getElementById('req-upper');
        const reqLower = document.getElementById('req-lower');
        const reqNumber = document.getElementById('req-number');

        function checkStrength() {
            const val = password.value;
            const hasLength = val.length >= 8;
            const hasUpper = /[A-Z]/.test(val);
            const hasLower = /[a-z]/.test(val);
            const hasNumber = /[0-9]/.test(val);

            updateRequirement(reqLength, hasLength);
            updateRequirement(reqUpper, hasUpper);
            updateRequirement(reqLower, hasLower);
            updateRequirement(reqNumber, hasNumber);

            let strength = 0;
            if (hasLength) strength++;
            if (hasUpper) strength++;
            if (hasLower) strength++;
            if (hasNumber) strength++;

            const percent = (strength / 4) * 100;
            strengthFill.style.width = percent + '%';

            if (val.length === 0) {
                strengthFill.style.background = '#e0e0e0';
                strengthText.textContent = 'Enter a password';
                strengthText.style.color = '#666';
            } else if (strength <= 2) {
                strengthFill.style.background = '#dc3545';
                strengthText.textContent = 'Weak password';
                strengthText.style.color = '#dc3545';
            } else if (strength === 3) {
                strengthFill.style.background = '#ffc107';
                strengthText.textContent = 'Medium password';
                strengthText.style.color = '#ffc107';
            } else {
                strengthFill.style.background = '#28a745';
                strengthText.textContent = 'Strong password';
                strengthText.style.color = '#28a745';
            }

            checkMatch();
        }

        function updateRequirement(element, isValid) {
            if (isValid) {
                element.classList.remove('invalid');
                element.classList.add('valid');
                if (element.innerHTML.includes('8 or more')) {
                    element.innerHTML = '✓ 8 or more characters';
                } else if (element.innerHTML.includes('uppercase')) {
                    element.innerHTML = '✓ One uppercase letter (A-Z)';
                } else if (element.innerHTML.includes('lowercase')) {
                    element.innerHTML = '✓ One lowercase letter (a-z)';
                } else if (element.innerHTML.includes('number')) {
                    element.innerHTML = '✓ One number (0-9)';
                }
            } else {
                element.classList.remove('valid');
                element.classList.add('invalid');
                if (element.innerHTML.includes('✓')) {
                    element.innerHTML = element.innerHTML.replace('✓ ', '');
                }
            }
        }

        function checkMatch() {
            const matchMsg = document.getElementById('matchMessage');
            if (confirm.value.length === 0) {
                matchMsg.textContent = '';
            } else if (password.value === confirm.value) {
                matchMsg.textContent = '✓ Passwords match';
                matchMsg.style.color = '#28a745';
            } else {
                matchMsg.textContent = '✗ Passwords do not match';
                matchMsg.style.color = '#dc3545';
            }
        }

        password.addEventListener('input', checkStrength);
        confirm.addEventListener('input', checkMatch);

        // Form validation
        document.getElementById('registerForm').addEventListener('submit', function(e) {
            const val = password.value;
            const hasLength = val.length >= 8;
            const hasUpper = /[A-Z]/.test(val);
            const hasLower = /[a-z]/.test(val);
            const hasNumber = /[0-9]/.test(val);

            if (!hasLength || !hasUpper || !hasLower || !hasNumber) {
                e.preventDefault();
                alert('Please create a stronger password that meets all requirements.');
                return false;
            }

            if (password.value !== confirm.value) {
                e.preventDefault();
                alert('Passwords do not match.');
                return false;
            }

            if (!document.getElementById('terms').checked) {
                e.preventDefault();
                alert('Please agree to the Terms of Service and Privacy Policy.');
                return false;
            }
        });
