  // Password visibility toggle
        function togglePassword() {
            const input = document.getElementById('loginPassword');
            const btn = event.target;
            
            if (input.type === 'password') {
                input.type = 'text';
                btn.textContent = '🙈';
            } else {
                input.type = 'password';
                btn.textContent = '👁️';
            }
        }

        // Add loading animation on form submit
        // loginBtn: el button el bey submit el form (Sign In)
        document.getElementById('loginBtn').addEventListener('click', function() {
            this.classList.add('loading');
            this.textContent = 'Signing in...';
        });
