/* ============================================
   TOHON FOURIER — CYBERSECURITY PORTFOLIO
   ============================================ */

document.addEventListener('DOMContentLoaded', () => {

    // ========================================
    // 1. MATRIX RAIN BACKGROUND
    // ========================================
    const canvas = document.getElementById('matrixCanvas');
    const ctx = canvas.getContext('2d');

    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    const matrixChars = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEF{}[]<>/\\|;:=+-*&^%$#@!~`CYBIS';
    const fontSize = 14;
    let columns = Math.floor(canvas.width / fontSize);
    let drops = Array(columns).fill(1);

    function drawMatrix() {
        ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.font = `${fontSize}px monospace`;

        for (let i = 0; i < drops.length; i++) {
            const text = matrixChars[Math.floor(Math.random() * matrixChars.length)];
            const x = i * fontSize;
            const y = drops[i] * fontSize;

            const brightness = Math.random();
            if (brightness > 0.95) {
                ctx.fillStyle = '#ffffff';
            } else if (brightness > 0.8) {
                ctx.fillStyle = '#39ff14';
            } else {
                ctx.fillStyle = '#00ff41';
            }

            ctx.fillText(text, x, y);

            if (y > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }

    setInterval(drawMatrix, 50);

    window.addEventListener('resize', () => {
        columns = Math.floor(canvas.width / fontSize);
        drops = Array(columns).fill(1);
    });

    // ========================================
    // 2. BOOT SEQUENCE
    // ========================================
    const bootMessages = [
        { text: 'BIOS v4.2.0 — CyberSec Module Initialized', type: 'normal' },
        { text: 'Checking memory... 16384 MB OK', type: 'success' },
        { text: 'Loading kernel modules...', type: 'normal' },
        { text: '[OK] Loaded crypto/aes256-gcm', type: 'success' },
        { text: '[OK] Loaded net/firewall (Fortinet NGFW)', type: 'success' },
        { text: '[OK] Loaded security/wazuh-agent', type: 'success' },
        { text: '[OK] Loaded security/intrusion_detection', type: 'success' },
        { text: '[WARNING] Scan non autorisé détecté sur le port 443', type: 'warning' },
        { text: '[OK] Menace neutralisée — Règle pare-feu appliquée', type: 'success' },
        { text: 'Initialisation du canal chiffré...', type: 'normal' },
        { text: 'Empreinte SSH : SHA256:t0h0n_f0ur13r_s3cur3', type: 'normal' },
        { text: '[OK] Canal sécurisé établi', type: 'success' },
        { text: 'Chargement de l\'interface du portfolio...', type: 'normal' },
        { text: '[OK] Tous les systèmes sont opérationnels', type: 'success' },
        { text: '', type: 'normal' },
        { text: '> Lancement du Portfolio TOHON FOURIER v1.0...', type: 'success' },
    ];

    const bootContainer = document.getElementById('bootLines');
    let bootIndex = 0;

    function showBootLine() {
        if (bootIndex >= bootMessages.length) {
            setTimeout(() => {
                const loadingScreen = document.getElementById('loadingScreen');
                loadingScreen.classList.add('fade-out');
                setTimeout(() => {
                    loadingScreen.classList.add('hidden');
                    showLaptopScene();
                }, 800);
            }, 500);
            return;
        }

        const msg = bootMessages[bootIndex];
        const p = document.createElement('p');
        p.textContent = msg.text;
        p.classList.add(msg.type);
        p.style.animationDelay = '0s';
        bootContainer.appendChild(p);
        bootIndex++;

        bootContainer.scrollTop = bootContainer.scrollHeight;

        const delay = msg.text === '' ? 200 : (50 + Math.random() * 120);
        setTimeout(showBootLine, delay);
    }

    setTimeout(showBootLine, 500);

    // ========================================
    // 3. LAPTOP SCENE
    // ========================================
    function showLaptopScene() {
        const laptopScene = document.getElementById('laptopScene');
        laptopScene.classList.remove('hidden');
        setTimeout(typeURL, 800);
    }

    function typeURL() {
        const urlText = document.getElementById('urlText');
        const url = 'https://tohon-fourier.sec';
        let i = 8;
        urlText.textContent = 'https://';

        function typeChar() {
            if (i <= url.length) {
                urlText.textContent = url.substring(0, i);
                i++;
                setTimeout(typeChar, 30 + Math.random() * 50);
            } else {
                setTimeout(startSearchTyping, 600);
            }
        }
        typeChar();
    }

    // Type "Fourier" in search bar
    function startSearchTyping() {
        const searchInput = document.getElementById('searchInput');
        const searchBox = searchInput.closest('.search-box');
        searchBox.classList.add('active');

        const searchText = 'Tohon Fourier';
        let i = 0;

        function typeSearch() {
            if (i <= searchText.length) {
                searchInput.value = searchText.substring(0, i);
                i++;

                if (i === 4) {
                    showSuggestions();
                }

                setTimeout(typeSearch, 80 + Math.random() * 120);
            } else {
                setTimeout(() => {
                    hideSuggestions();
                    setTimeout(startHackSequence, 400);
                }, 800);
            }
        }

        setTimeout(typeSearch, 300);
    }

    function showSuggestions() {
        const container = document.getElementById('searchSuggestions');
        const suggestions = [
            { icon: 'fas fa-user-secret', text: 'Tohon Fourier — Cybersécurité & DevSecOps' },
            { icon: 'fas fa-shield-halved', text: 'Tohon Fourier — Analyste SOC, Wazuh' },
            { icon: 'fas fa-bug', text: 'Tohon Fourier — CYBIS, plateforme SaaS' },
            { icon: 'fab fa-github', text: 'CalderaFourier-code (GitHub)' },
        ];

        suggestions.forEach((s, idx) => {
            const div = document.createElement('div');
            div.classList.add('suggestion-item');
            div.style.animationDelay = `${idx * 0.1}s`;
            div.innerHTML = `<i class="${s.icon}"></i> ${s.text}`;
            container.appendChild(div);
        });

        container.classList.add('show');
    }

    function hideSuggestions() {
        const container = document.getElementById('searchSuggestions');
        container.classList.remove('show');
    }

    // ========================================
    // 4. HACK / DECRYPTION SEQUENCE
    // ========================================
    function startHackSequence() {
        const searchPage = document.getElementById('searchPage');
        const hackScreen = document.getElementById('hackScreen');

        searchPage.style.opacity = '0';
        setTimeout(() => {
            searchPage.style.display = 'none';
            hackScreen.classList.remove('hidden');
            runHackLines();
        }, 500);
    }

    function runHackLines() {
        const hackContainer = document.getElementById('hackLines');
        const progressFill = document.getElementById('progressFill');
        const progressPercent = document.getElementById('progressPercent');

        const hackMessages = [
            '<span class="success-text">[CONNEXION]</span> Établissement du canal sécurisé...',
            'Résolution DNS : <span class="ip">tohon-fourier.sec → 192.168.10.42</span>',
            '<span class="data">Négociation TLS 1.3 — Chiffrement : AES-256-GCM</span>',
            'Vérification de l\'identité... <span class="success-text">CONFIRMÉE</span>',
            'Profil identifié : <span class="ip">TOHON FOURIER</span>',
            '<span class="data">Vérification des certificats... SHA256 : valide</span>',
            'Analyse des ports ouverts... <span class="success-text">22/SSH 443/HTTPS — Sécurisé</span>',
            '<span class="warning-text">[WAZUH]</span> Contrôle d\'intégrité en cours...',
            'Niveau d\'accès accordé : <span class="success-text">AUTORISÉ</span>',
            'Extraction des données du portfolio...',
            '<span class="data">█▓▒░ Déchiffrement des modules ░▒▓█</span>',
            'Module [PROFIL] ............. <span class="success-text">DÉCHIFFRÉ</span>',
            'Module [COMPÉTENCES] ........ <span class="success-text">DÉCHIFFRÉ</span>',
            'Module [EXPÉRIENCE] ......... <span class="success-text">DÉCHIFFRÉ</span>',
            'Module [PROJETS] ............ <span class="success-text">DÉCHIFFRÉ</span>',
            'Module [FORMATION] .......... <span class="success-text">DÉCHIFFRÉ</span>',
            'Module [CONTACT] ............ <span class="success-text">DÉCHIFFRÉ</span>',
            '<span class="success-text">[TERMINÉ]</span> Tous les modules sont chargés.',
            '',
            '<span class="success-text">>>> BIENVENUE DANS LE PORTFOLIO DE TOHON FOURIER <<<</span>',
        ];

        let lineIndex = 0;

        function addHackLine() {
            if (lineIndex >= hackMessages.length) {
                setTimeout(transitionToPortfolio, 800);
                return;
            }

            const p = document.createElement('p');
            p.innerHTML = hackMessages[lineIndex];
            hackContainer.appendChild(p);
            hackContainer.scrollTop = hackContainer.scrollHeight;

            const progress = Math.min(100, Math.round(((lineIndex + 1) / hackMessages.length) * 100));
            progressFill.style.width = progress + '%';
            progressPercent.textContent = progress + '%';

            lineIndex++;
            const delay = 100 + Math.random() * 200;
            setTimeout(addHackLine, delay);
        }

        addHackLine();
    }

    // ========================================
    // 5. TRANSITION TO PORTFOLIO
    // ========================================
    function transitionToPortfolio() {
        const laptopScene = document.getElementById('laptopScene');
        const portfolioContent = document.getElementById('portfolioContent');

        laptopScene.classList.add('dissolve');

        setTimeout(() => {
            laptopScene.classList.add('hidden');
            portfolioContent.classList.remove('hidden');
            portfolioContent.classList.add('visible');

            canvas.style.opacity = '0.08';

            setTimeout(() => {
                startHeroAnimations();
                initScrollReveal();
                initNavigation();
                generateFooterMatrix();
            }, 300);
        }, 1500);
    }

    // ========================================
    // 6. HERO ANIMATIONS
    // ========================================
    function startHeroAnimations() {
        const heroTyping = document.getElementById('heroTyping');
        const titles = [
            'Analyste SOC & Supervision SIEM',
            'Sécurité Offensive & Défensive',
            'Créateur de CYBIS — SaaS Security',
            'DevSecOps & Automatisation',
            'Réseaux, Mobilité & Sécurité'
        ];
        let titleIndex = 0;
        let charIndex = 0;
        let isDeleting = false;

        function typeHero() {
            const current = titles[titleIndex];

            if (!isDeleting) {
                heroTyping.textContent = current.substring(0, charIndex + 1);
                charIndex++;

                if (charIndex === current.length) {
                    isDeleting = true;
                    setTimeout(typeHero, 2200);
                    return;
                }
            } else {
                heroTyping.textContent = current.substring(0, charIndex - 1);
                charIndex--;

                if (charIndex === 0) {
                    isDeleting = false;
                    titleIndex = (titleIndex + 1) % titles.length;
                }
            }

            const speed = isDeleting ? 35 : 70;
            setTimeout(typeHero, speed);
        }

        typeHero();

        // Animate stat numbers
        const statNumbers = document.querySelectorAll('.stat-number');
        statNumbers.forEach(stat => {
            const target = parseInt(stat.dataset.count);
            const suffix = stat.dataset.suffix || '';
            animateCount(stat, 0, target, 1500, suffix);
        });
    }

    function animateCount(element, start, end, duration, suffix) {
        const startTime = performance.now();

        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);

            const eased = 1 - Math.pow(1 - progress, 3);
            const current = Math.round(start + (end - start) * eased);

            element.textContent = current + suffix;

            if (progress < 1) {
                requestAnimationFrame(update);
            }
        }

        requestAnimationFrame(update);
    }

    // ========================================
    // 7. SCROLL REVEAL & SKILL BARS
    // ========================================
    function initScrollReveal() {
        const revealSelectors = [
            '.info-card', '.skill-category', '.project-card',
            '.timeline-item', '.contact-terminal', '.contact-form-container',
            '.certifications', '.languages-section', '.lang-item'
        ];

        revealSelectors.forEach(selector => {
            document.querySelectorAll(selector).forEach(el => {
                el.classList.add('reveal-element');
            });
        });

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('revealed');

                    if (entry.target.classList.contains('timeline-item')) {
                        entry.target.classList.add('visible');
                    }

                    if (entry.target.classList.contains('skill-category')) {
                        const bars = entry.target.querySelectorAll('.bar-fill');
                        bars.forEach((bar, idx) => {
                            setTimeout(() => {
                                bar.style.width = bar.dataset.width + '%';
                            }, idx * 150);
                        });
                    }

                    observer.unobserve(entry.target);
                }
            });
        }, {
            threshold: 0.15,
            rootMargin: '0px 0px -50px 0px'
        });

        document.querySelectorAll('.reveal-element').forEach(el => {
            observer.observe(el);
        });

        document.querySelectorAll('.timeline-item').forEach(el => {
            observer.observe(el);
        });
    }

    // ========================================
    // 8. NAVIGATION
    // ========================================
    function initNavigation() {
        const hamburger = document.getElementById('navHamburger');
        const mobileNav = document.getElementById('mobileNav');

        if (hamburger) {
            hamburger.addEventListener('click', () => {
                mobileNav.classList.toggle('hidden');
            });
        }

        document.querySelectorAll('.mobile-link').forEach(link => {
            link.addEventListener('click', () => {
                mobileNav.classList.add('hidden');
            });
        });

        document.querySelectorAll('a[href^="#"]').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const target = document.querySelector(link.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        });

        const sections = document.querySelectorAll('.section, .hero-section');
        const navLinks = document.querySelectorAll('.nav-link');

        window.addEventListener('scroll', () => {
            let current = '';
            sections.forEach(section => {
                const top = section.offsetTop - 100;
                if (window.scrollY >= top) {
                    current = section.getAttribute('id');
                }
            });

            navLinks.forEach(link => {
                link.style.color = '';
                if (link.getAttribute('href') === `#${current}`) {
                    link.style.color = '#00ff41';
                }
            });
        });

        const contactForm = document.getElementById('contactForm');
        if (contactForm) {
            contactForm.addEventListener('submit', (e) => {
                e.preventDefault();

                const btn = contactForm.querySelector('.submit-btn span');
                const nameInput = contactForm.querySelector('input[type="text"]');
                const emailInput = contactForm.querySelector('input[type="email"]');
                const messageInput = contactForm.querySelector('textarea');

                const name = nameInput ? nameInput.value.trim() : '';
                const email = emailInput ? emailInput.value.trim() : '';
                const message = messageInput ? messageInput.value.trim() : '';

                if (!name || !email || !message) {
                    btn.textContent = '⚠ CHAMPS_REQUIS()';
                    btn.style.color = '#ffaa00';
                    setTimeout(() => {
                        btn.textContent = 'TRANSMETTRE_MESSAGE()';
                        btn.style.color = '';
                    }, 2500);
                    return;
                }

                // Désactiver le bouton pendant l'envoi
                const submitBtn = contactForm.querySelector('.submit-btn');
                submitBtn.disabled = true;
                btn.textContent = 'TRANSMISSION_EN_COURS...';

                // Envoi via Formspree (service gratuit, sans backend)
                fetch('https://formspree.io/f/fouriertohon@gmail.com', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                    body: JSON.stringify({
                        name: name,
                        _replyto: email,
                        message: message,
                        _subject: `[Portfolio] Nouveau message de ${name}`
                    })
                })
                .then(response => {
                    if (response.ok) {
                        btn.textContent = '✓ MESSAGE_TRANSMIS()';
                        btn.style.color = '#39ff14';
                        contactForm.reset();
                    } else {
                        // Fallback : ouvrir le client mail
                        const mailtoLink = `mailto:fouriertohon@gmail.com?subject=${encodeURIComponent('[Portfolio] Message de ' + name)}&body=${encodeURIComponent('De: ' + name + '\nEmail: ' + email + '\n\n' + message)}`;
                        window.open(mailtoLink, '_blank');
                        btn.textContent = '✓ CLIENT_MAIL_OUVERT()';
                        btn.style.color = '#39ff14';
                        contactForm.reset();
                    }
                    setTimeout(() => {
                        btn.textContent = 'TRANSMETTRE_MESSAGE()';
                        btn.style.color = '';
                        submitBtn.disabled = false;
                    }, 4000);
                })
                .catch(() => {
                    // Fallback direct : mailto
                    const mailtoLink = `mailto:fouriertohon@gmail.com?subject=${encodeURIComponent('[Portfolio] Message de ' + name)}&body=${encodeURIComponent('De: ' + name + '\nEmail: ' + email + '\n\n' + message)}`;
                    window.open(mailtoLink, '_blank');
                    btn.textContent = '✓ CLIENT_MAIL_OUVERT()';
                    btn.style.color = '#39ff14';
                    contactForm.reset();
                    setTimeout(() => {
                        btn.textContent = 'TRANSMETTRE_MESSAGE()';
                        btn.style.color = '';
                        submitBtn.disabled = false;
                    }, 4000);
                });
            });
        }
    }

    // ========================================
    // 9. FOOTER MATRIX LINE
    // ========================================
    function generateFooterMatrix() {
        const footerMatrix = document.getElementById('footerMatrix');
        if (!footerMatrix) return;

        function updateFooter() {
            let line = '';
            const chars = '01アウカキクケコ{}[]<>|;:+-*/=CYBIS';
            for (let i = 0; i < 120; i++) {
                line += chars[Math.floor(Math.random() * chars.length)];
            }
            footerMatrix.textContent = line;
        }

        setInterval(updateFooter, 150);
        updateFooter();
    }

});
