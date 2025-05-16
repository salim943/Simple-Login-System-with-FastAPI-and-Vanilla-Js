'use strict';

        const menuBtn = document.getElementById('menuBtn');
        const overlay = document.getElementById('overlay');
        const signupForm = document.getElementById('signupForm');
        const closeBtn = document.getElementById('closeBtn');

        menuBtn.onclick = () => showModal();
        closeBtn.onclick = () => closeModal();
        overlay.onclick = () => closeModal();

        function showModal() {
            overlay.classList.add('opacity-1', 'z-50');
            overlay.classList.remove('opacity-0', '-z-50');
            signupForm.classList.add('top-0');
            signupForm.classList.remove('-top-150');
            document.body.style.overflowY = 'hidden';
        }

        function closeModal() {
            overlay.classList.add('opacity-0', '-z-50');
            overlay.classList.remove('opacity-1', 'z-50');
            signupForm.classList.add('-top-150');
            signupForm.classList.remove('top-0');
            document.body.style.overflowY = 'scroll';
        }