/* ═══════════════════════════════════════════════════════════════
   VisionForge Hero 粒子场（Canvas 2D，零依赖，程序化生成）
   星座式漂移粒子 + 邻近连线 + 指针排斥。
   性能契约：
   - 粒子数按面积自适应（36~110），DPR 上限 2
   - 离屏 / 页面隐藏时自动暂停，回到前台恢复
   - 只写 Canvas，不触发布局；单 rAF 循环
   由 fx.js 在画布可见时懒加载注入并调用 VFParticles.mount(canvas)。
   ═══════════════════════════════════════════════════════════════ */
window.VFParticles = (function () {
    'use strict';

    function mount(canvas) {
        if (!canvas || canvas.__vfMounted) return;
        canvas.__vfMounted = true;

        var ctx = canvas.getContext('2d');
        if (!ctx) return;

        var dpr = Math.min(window.devicePixelRatio || 1, 2);
        var w = 0, h = 0;
        var particles = [];
        var running = false;
        var visible = true;
        var rafId = null;
        var mouse = { x: -9999, y: -9999 };
        var isCompact = window.matchMedia('(max-width: 640px)').matches;
        var LINK_DIST = isCompact ? 92 : 124;
        var MOUSE_RADIUS = 150;

        function targetCount() {
            var base = (w * h) / (isCompact ? 22000 : 15000);
            return Math.round(Math.min(isCompact ? 64 : 110, Math.max(34, base)));
        }

        function spawn() {
            var cyan = Math.random() < 0.22;
            return {
                x: Math.random() * w,
                y: Math.random() * h,
                vx: (Math.random() - 0.5) * 0.24,
                vy: (Math.random() - 0.5) * 0.24,
                r: Math.random() * 1.5 + 0.7,
                cyan: cyan
            };
        }

        function resize() {
            var rect = canvas.getBoundingClientRect();
            w = Math.max(1, rect.width);
            h = Math.max(1, rect.height);
            canvas.width = Math.round(w * dpr);
            canvas.height = Math.round(h * dpr);
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            var count = targetCount();
            while (particles.length < count) particles.push(spawn());
            if (particles.length > count) particles.length = count;
        }

        function step() {
            if (!running) return;
            ctx.clearRect(0, 0, w, h);

            var i, j, p, q, dx, dy, d2;
            var link2 = LINK_DIST * LINK_DIST;
            var mr2 = MOUSE_RADIUS * MOUSE_RADIUS;

            /* 连线（平方距离预筛，命中才开方） */
            ctx.lineWidth = 1;
            for (i = 0; i < particles.length; i++) {
                p = particles[i];
                for (j = i + 1; j < particles.length; j++) {
                    q = particles[j];
                    dx = p.x - q.x;
                    dy = p.y - q.y;
                    d2 = dx * dx + dy * dy;
                    if (d2 < link2) {
                        var alpha = (1 - Math.sqrt(d2) / LINK_DIST) * 0.26;
                        ctx.strokeStyle = 'rgba(124,111,240,' + alpha.toFixed(3) + ')';
                        ctx.beginPath();
                        ctx.moveTo(p.x, p.y);
                        ctx.lineTo(q.x, q.y);
                        ctx.stroke();
                    }
                }
            }

            /* 粒子 */
            for (i = 0; i < particles.length; i++) {
                p = particles[i];
                /* 指针排斥 */
                dx = p.x - mouse.x;
                dy = p.y - mouse.y;
                d2 = dx * dx + dy * dy;
                if (d2 < mr2 && d2 > 0.01) {
                    var d = Math.sqrt(d2);
                    var force = (1 - d / MOUSE_RADIUS) * 0.55;
                    p.vx += (dx / d) * force;
                    p.vy += (dy / d) * force;
                }
                /* 速度阻尼回稳 */
                p.vx *= 0.985;
                p.vy *= 0.985;
                if (Math.abs(p.vx) < 0.05) p.vx += (Math.random() - 0.5) * 0.012;
                if (Math.abs(p.vy) < 0.05) p.vy += (Math.random() - 0.5) * 0.012;

                p.x += p.vx;
                p.y += p.vy;

                /* 边缘回绕 */
                if (p.x < -8) p.x = w + 8; else if (p.x > w + 8) p.x = -8;
                if (p.y < -8) p.y = h + 8; else if (p.y > h + 8) p.y = -8;

                ctx.beginPath();
                ctx.arc(p.x, p.y, p.r, 0, 6.2832);
                ctx.fillStyle = p.cyan ? 'rgba(103,232,249,0.75)' : 'rgba(167,139,250,0.7)';
                ctx.fill();
            }

            rafId = requestAnimationFrame(step);
        }

        function start() {
            if (running || !visible || document.hidden) return;
            running = true;
            rafId = requestAnimationFrame(step);
        }
        function stop() {
            running = false;
            if (rafId !== null) cancelAnimationFrame(rafId);
            rafId = null;
        }

        resize();
        if (typeof ResizeObserver !== 'undefined') {
            new ResizeObserver(function () { resize(); }).observe(canvas);
        } else {
            window.addEventListener('resize', resize);
        }

        var host = canvas.parentElement || canvas;
        host.addEventListener('pointermove', function (e) {
            var rect = canvas.getBoundingClientRect();
            mouse.x = e.clientX - rect.left;
            mouse.y = e.clientY - rect.top;
        }, { passive: true });
        host.addEventListener('pointerleave', function () {
            mouse.x = -9999;
            mouse.y = -9999;
        });

        document.addEventListener('visibilitychange', function () {
            if (document.hidden) stop(); else start();
        });
        if ('IntersectionObserver' in window) {
            new IntersectionObserver(function (entries) {
                visible = entries[0].isIntersecting;
                if (visible) start(); else stop();
            }, { threshold: 0.02 }).observe(canvas);
        }

        start();
    }

    return { mount: mount };
})();
