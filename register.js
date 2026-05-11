 // Password visibility toggle for the main password field
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
    
    // ========== ADD THIS SPACE CHECK FIRST ==========
    if (val.includes(' ')) {
        // Update requirement display
        updateRequirement(reqLength, false);
        updateRequirement(reqUpper, false);
        updateRequirement(reqLower, false);
        updateRequirement(reqNumber, false);
        
        // Show error
        strengthFill.style.width = '0%';
        strengthFill.style.background = '#dc3545';
        strengthText.textContent = 'Password cannot contain spaces!';
        strengthText.style.color = '#dc3545';
        
        // Update requirement text for length
        reqLength.innerHTML = '✗ 8 or more characters (no spaces allowed)';
        reqLength.classList.remove('valid');
        reqLength.classList.add('invalid');
        
        checkMatch();
        return;  // Stop here
    }
    // =============================================
    
    const hasLength = val.length >= 8;
    const hasUpper = /[A-Z]/.test(val);
    const hasLower = /[a-z]/.test(val);
    const hasNumber = /[0-9]/.test(val);

    // ba7seb el score based 3la el requirements eli etlabo (length, upper, lower, number)
    // w ba update el UI (strength bar w requirements list) based 3la el score
    const score = [hasLength, hasUpper, hasLower, hasNumber].filter(Boolean).length;

    // ba update el requirements list (valid wala invalid) based 3la el checks
    updateRequirement(reqLength, hasLength);
    updateRequirement(reqUpper, hasUpper);
    updateRequirement(reqLower, hasLower);
    updateRequirement(reqNumber, hasNumber);

    // ba update el strength bar width w color w text based 3la el score
    const percent = (score / 4) * 100;
    strengthFill.style.width = percent + '%';

    // ba determine el strength label w color based 3la el score
    if (score === 4) {
        strengthFill.style.background = '#28a745';
        strengthText.textContent = 'Strong';
        strengthText.style.color = '#28a745';
    } else if (score === 3) {
        strengthFill.style.background = '#ffc107';
        strengthText.textContent = 'Medium';
        strengthText.style.color = '#ffc107';
    } else if (score === 2) {
        strengthFill.style.background = '#fd7e14';
        strengthText.textContent = 'Weak';
        strengthText.style.color = '#fd7e14';
    } else {
        strengthFill.style.background = '#dc3545';
        strengthText.textContent = 'Very Weak';
        strengthText.style.color = '#dc3545';
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

        // Form validation: ba ta2aked en el password meets all requirements abl ma yrsal el form
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

            // Note: terms checkbox check removed because there is no terms checkbox in register.html
        });
