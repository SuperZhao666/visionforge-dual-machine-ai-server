/* ═══════════════════════════════════════════════════════════════
   VisionForge FX runtime (v3)
   渐进增强：所有动效均为可选增强，任何环节失败都不影响页面功能。
   - 页面转场幕布（进入由 CSS 动画自治完成，退出由 JS 拦截）
   - Lenis 平滑滚动 + GSAP ScrollTrigger 集成（按官方文档接线）
   - IntersectionObserver 驱动 reveal 动画（纯 CSS 过渡，60fps）
   - 按钮涟漪 / 磁性 hover / 数字滚动 / Hero 视差
   - 粒子主视觉懒加载（particles.js 动态注入）
   prefers-reduced-motion / Save-Data 时全面降级。
   ═══════════════════════════════════════════════════════════════ */
(function () {
    'use strict';

    var doc = document;
    var root = doc.documentElement;
    var reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var finePointer = window.matchMedia('(pointer: fine)').matches;
    var saveData = !!(navigator.connection && navigator.connection.saveData);

    /* 标记 FX 就绪（base.html 内联守卫依赖此标记做失败回退） */
    window.__fxReady = true;

    /* ── bfcache 恢复：后退/前进回来时清除退出态 ── */
    window.addEventListener('pageshow', function (e) {
        if (e.persisted) root.classList.remove('fx-leaving', 'fx-veil-in');
    });

    /* ── 退出转场：仅拦截普通站内 GET 导航，绝不碰表单/外链/新标签 ── */
    var veil = doc.querySelector('.page-veil');
    /* 入场幕布由 CSS 动画自治完成；此处为合成器冻结环境的硬兜底：
       1.6s 后无论如何移除幕布，保证内容永远可达（定时器不受 rAF 冻结影响） */
    if (veil && !reduced) {
        setTimeout(function () { veil.classList.add('veil-done'); }, 1600);
        /* 交互兜底：极端环境下用户首次交互立即撤幕 */
        var dismiss = function () {
            veil.classList.add('veil-done');
            doc.removeEventListener('pointerdown', dismiss);
            doc.removeEventListener('keydown', dismiss);
        };
        doc.addEventListener('pointerdown', dismiss);
        doc.addEventListener('keydown', dismiss);
    }
    if (!reduced) {
        doc.addEventListener('click', function (e) {
            if (e.defaultPrevented || e.button !== 0) return;
            if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
            var a = e.target && e.target.closest ? e.target.closest('a') : null;
            if (!a) return;
            if (a.target && a.target !== '_self') return;
            if (a.hasAttribute('download')) return;
            var href = a.getAttribute('href');
            if (!href || href.charAt(0) === '#') return;
            var url;
            try { url = new URL(href, location.href); } catch (err) { return; }
            if (url.origin !== location.origin) return;
            if (url.pathname === location.pathname && url.search === location.search && url.hash) return;
            e.preventDefault();
            if (veil) veil.classList.remove('veil-done');
            root.classList.add('fx-leaving');
            requestAnimationFrame(function () { root.classList.add('fx-veil-in'); });
            setTimeout(function () { location.href = url.href; }, 360);
        }, true);
    }

    /* ── 导航栏滚动态 ── */
    var nav = doc.querySelector('.navbar');
    if (nav) {
        var onScroll = function () {
            nav.classList.toggle('scrolled', window.scrollY > 8);
        };
        window.addEventListener('scroll', onScroll, { passive: true });
        onScroll();
    }

    /* ── Lenis 平滑滚动（官方推荐与 GSAP 同帧驱动） ── */
    var hasGsap = !reduced && typeof window.gsap !== 'undefined';
    if (hasGsap && typeof window.ScrollTrigger !== 'undefined') {
        window.gsap.registerPlugin(window.ScrollTrigger);
    }
    if (!reduced && typeof window.Lenis === 'function') {
        var lenis = new window.Lenis({ lerp: 0.11, anchors: true });
        if (hasGsap) {
            lenis.on('scroll', function () {
                if (window.ScrollTrigger) window.ScrollTrigger.update();
            });
            window.gsap.ticker.add(function (time) { lenis.raf(time * 1000); });
            window.gsap.ticker.lagSmoothing(0);
        } else {
            var rafLoop = function (time) { lenis.raf(time); requestAnimationFrame(rafLoop); };
            requestAnimationFrame(rafLoop);
        }
    }

    /* ── Reveal：先展开分组，再统一观察 ── */
    Array.prototype.forEach.call(doc.querySelectorAll('[data-reveal-group]'), function (group) {
        var step = parseInt(group.getAttribute('data-reveal-group') || '80', 10);
        Array.prototype.forEach.call(group.children, function (child, i) {
            if (!child.hasAttribute('data-reveal')) child.setAttribute('data-reveal', '');
            child.style.setProperty('--reveal-delay', Math.min(i * step, 560) + 'ms');
        });
    });
    var revealEls = doc.querySelectorAll('[data-reveal]');
    if (revealEls.length) {
        if (reduced || !('IntersectionObserver' in window)) {
            Array.prototype.forEach.call(revealEls, function (el) { el.classList.add('reveal-in'); });
        } else {
            var io = new IntersectionObserver(function (entries) {
                entries.forEach(function (en) {
                    if (en.isIntersecting) {
                        en.target.classList.add('reveal-in');
                        io.unobserve(en.target);
                    }
                });
            /* Bug #AdminV2-1：阈值 0.12 时，超高元素（如 200 行使用记录表，可视占比永远 <12%）
               回调永不触发，data-reveal 永远停在 opacity:0 导致整块内容不可见。
               改为 0：任一像素进入视口即触发，与元素高度无关。 */
            }, { threshold: 0, rootMargin: '0px 0px -6% 0px' });
            Array.prototype.forEach.call(revealEls, function (el) { io.observe(el); });
        }
    }

    /* ── 按钮涟漪 ── */
    if (!reduced) {
        doc.addEventListener('pointerdown', function (e) {
            var btn = e.target && e.target.closest ? e.target.closest('.btn') : null;
            if (!btn) return;
            var rect = btn.getBoundingClientRect();
            var size = Math.max(rect.width, rect.height);
            var span = doc.createElement('span');
            span.className = 'ripple';
            span.style.width = span.style.height = size + 'px';
            span.style.left = (e.clientX - rect.left - size / 2) + 'px';
            span.style.top = (e.clientY - rect.top - size / 2) + 'px';
            btn.appendChild(span);
            span.addEventListener('animationend', function () { span.remove(); });
        }, { passive: true });
    }

    /* ── 磁性 hover（桌面端 + GSAP quickTo，GPU 友好） ── */
    if (!reduced && finePointer && hasGsap) {
        Array.prototype.forEach.call(doc.querySelectorAll('[data-magnetic]'), function (el) {
            var xTo = window.gsap.quickTo(el, 'x', { duration: 0.4, ease: 'power3' });
            var yTo = window.gsap.quickTo(el, 'y', { duration: 0.4, ease: 'power3' });
            el.addEventListener('pointermove', function (e) {
                var r = el.getBoundingClientRect();
                xTo((e.clientX - (r.left + r.width / 2)) * 0.28);
                yTo((e.clientY - (r.top + r.height / 2)) * 0.28);
            });
            el.addEventListener('pointerleave', function () { xTo(0); yTo(0); });
        });
    }

    /* ── 数字滚动（data-countup="123.4" data-prefix data-suffix data-decimals） ── */
    var countEls = doc.querySelectorAll('[data-countup]');
    if (countEls.length && !reduced && 'IntersectionObserver' in window) {
        var cio = new IntersectionObserver(function (entries) {
            entries.forEach(function (en) {
                if (!en.isIntersecting) return;
                cio.unobserve(en.target);
                var el = en.target;
                var target = parseFloat(el.getAttribute('data-countup'));
                if (isNaN(target)) return;
                var prefix = el.getAttribute('data-prefix') || '';
                var suffix = el.getAttribute('data-suffix') || '';
                var decimals = parseInt(el.getAttribute('data-decimals') || '0', 10);
                var t0 = null, dur = 1100;
                var tick = function (ts) {
                    if (!t0) t0 = ts;
                    var p = Math.min((ts - t0) / dur, 1);
                    var eased = 1 - Math.pow(1 - p, 3);
                    /* 千分位格式化：大数字（如总收入）更易读 */
                    var val = Number((target * eased).toFixed(decimals));
                    el.textContent = prefix + val.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals }) + suffix;
                    if (p < 1) requestAnimationFrame(tick);
                };
                requestAnimationFrame(tick);
            });
        }, { threshold: 0.4 });
        Array.prototype.forEach.call(countEls, function (el) { cio.observe(el); });
    }

    /* ── Hero：入场编排 + 滚动视差（GSAP ScrollTrigger，scrub 驱动） ── */
    if (hasGsap) {
        var heroLines = doc.querySelectorAll('[data-hero-line]');
        if (heroLines.length) {
            window.gsap.fromTo(heroLines,
                { y: 46, opacity: 0 },
                { y: 0, opacity: 1, duration: 1.05, ease: 'power3.out', stagger: 0.12, delay: 0.15, clearProps: 'transform' });
        }
        var heroFade = doc.querySelectorAll('[data-hero-fade]');
        if (heroFade.length) {
            window.gsap.fromTo(heroFade,
                { y: 22, opacity: 0 },
                { y: 0, opacity: 1, duration: 0.9, ease: 'power3.out', stagger: 0.1, delay: 0.55, clearProps: 'transform' });
        }
        /* rAF 冻结环境兜底：2.4s 后清除入场内联态，确保 Hero 内容最终可见 */
        if (heroLines.length || heroFade.length) {
            setTimeout(function () {
                window.gsap.set('[data-hero-line], [data-hero-fade]', { clearProps: 'all' });
            }, 2400);
        }
        if (typeof window.ScrollTrigger !== 'undefined' && doc.querySelector('[data-hero-parallax]')) {
            window.gsap.to('.hero-inner', {
                yPercent: -14, opacity: 0.15, ease: 'none',
                scrollTrigger: { trigger: '.hero', start: 'top top', end: 'bottom 35%', scrub: true }
            });
            window.gsap.to('.scroll-cue', {
                opacity: 0, ease: 'none',
                scrollTrigger: { trigger: '.hero', start: 'top top', end: '18% top', scrub: true }
            });
        }
    }

    /* ── 光标环境光影：径向光晕跟随指针（仅 transform/opacity，GPU 友好） ── */
    if (!reduced && finePointer && !saveData) {
        var glow = doc.createElement('div');
        glow.className = 'cursor-glow';
        glow.setAttribute('aria-hidden', 'true');
        doc.body.appendChild(glow);
        var gx = window.innerWidth / 2, gy = window.innerHeight * 0.35, tx = gx, ty = gy, glowOn = false;
        doc.addEventListener('pointermove', function (e) {
            tx = e.clientX; ty = e.clientY;
            if (!glowOn) { glowOn = true; glow.style.opacity = '1'; }
        }, { passive: true });
        doc.addEventListener('pointerleave', function () { glowOn = false; glow.style.opacity = '0'; });
        var glowLoop = function () {
            gx += (tx - gx) * 0.08; gy += (ty - gy) * 0.08;
            glow.style.transform = 'translate3d(' + (gx - 260) + 'px,' + (gy - 260) + 'px,0)';
            requestAnimationFrame(glowLoop);
        };
        requestAnimationFrame(glowLoop);
    }

    /* ── 粒子主视觉：可见时才注入脚本（懒加载），reduced/save-data 跳过 ── */
    var canvas = doc.getElementById('hero-particles');
    if (canvas && !reduced && !saveData) {
        var loadParticles = function () {
            var s = doc.createElement('script');
            s.src = '/static/js/particles.js?v=3';
            s.async = true;
            s.onload = function () {
                if (window.VFParticles && window.VFParticles.mount) {
                    window.VFParticles.mount(canvas);
                }
            };
            doc.body.appendChild(s);
        };
        if ('IntersectionObserver' in window) {
            var pio = new IntersectionObserver(function (entries) {
                if (entries[0].isIntersecting) { pio.disconnect(); loadParticles(); }
            }, { rootMargin: '240px' });
            pio.observe(canvas);
        } else {
            loadParticles();
        }
    }
})();
