/* ═══════════════════════════════════════════════════════════════
   VisionForge 时长商店 FX（零依赖，程序化生成，无外部素材）
   - 星尘宇宙画布（粒子漂移/闪烁/流星，指针引力，等效动态视频背景）
   - 套餐卡 3D 倾斜 + 镜面流光（CSS 变量驱动）
   - 支付方式切换 / 订单号复制
   - 支付台：状态轮询、到账成功覆盖层、礼花爆发、匹配窗口倒计时
   prefers-reduced-motion / Save-Data 时全面降级。
   ═══════════════════════════════════════════════════════════════ */
(function () {
    'use strict';

    var doc = document;
    var reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var finePointer = window.matchMedia('(pointer: fine)').matches;
    var saveData = !!(navigator.connection && navigator.connection.saveData);

    /* ── 星尘宇宙（Hero 动态背景） ──────────────────────────── */
    var cosmos = doc.getElementById('shop-cosmos');
    if (cosmos && !reduced && !saveData) {
        var ctx = cosmos.getContext('2d');
        var W = 0, H = 0, dpr = Math.min(window.devicePixelRatio || 1, 2);
        var stars = [], meteors = [], running = true, visible = true;
        var pointer = { x: -9999, y: -9999 };

        function resize() {
            var rect = cosmos.parentElement.getBoundingClientRect();
            W = rect.width; H = rect.height;
            cosmos.width = Math.round(W * dpr); cosmos.height = Math.round(H * dpr);
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            var count = Math.min(150, Math.round((W * H) / 12000));
            stars = [];
            for (var i = 0; i < count; i++) {
                stars.push({
                    x: Math.random() * W, y: Math.random() * H,
                    r: 0.6 + Math.random() * 1.7,
                    vx: (Math.random() - 0.5) * 0.08, vy: -0.05 - Math.random() * 0.22,
                    tw: Math.random() * Math.PI * 2, ts: 0.008 + Math.random() * 0.02,
                    hue: Math.random() < 0.72 ? '124,111,240' : '103,232,249'
                });
            }
        }
        function spawnMeteor() {
            if (meteors.length > 1 || Math.random() > 0.006) return;
            var fromLeft = Math.random() < 0.5;
            meteors.push({
                x: fromLeft ? -40 : Math.random() * W * 0.7 + W * 0.3,
                y: Math.random() * H * 0.35,
                vx: fromLeft ? 5.5 + Math.random() * 2.5 : -(5.5 + Math.random() * 2.5),
                vy: 2.2 + Math.random() * 1.2, life: 1
            });
        }
        function frame() {
            if (!running || !visible) return;
            ctx.clearRect(0, 0, W, H);
            spawnMeteor();
            for (var i = 0; i < stars.length; i++) {
                var s = stars[i];
                s.x += s.vx; s.y += s.vy; s.tw += s.ts;
                var dx = s.x - pointer.x, dy = s.y - pointer.y;
                var d2 = dx * dx + dy * dy;
                if (d2 < 9000) { var f = 1 - d2 / 9000; s.x += dx * f * 0.012; s.y += dy * f * 0.012; }
                if (s.y < -6) { s.y = H + 6; s.x = Math.random() * W; }
                if (s.x < -6) s.x = W + 6; else if (s.x > W + 6) s.x = -6;
                var a = 0.35 + Math.sin(s.tw) * 0.3;
                ctx.beginPath(); ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
                ctx.fillStyle = 'rgba(' + s.hue + ',' + Math.max(a, 0.05).toFixed(3) + ')';
                ctx.fill();
            }
            ctx.lineWidth = 1;
            for (var j = 0; j < stars.length; j++) {
                var a2 = stars[j];
                var pdx = a2.x - pointer.x, pdy = a2.y - pointer.y;
                if (pdx * pdx + pdy * pdy > 150 * 150) continue;
                for (var k = j + 1; k < stars.length; k++) {
                    var b = stars[k];
                    var ddx = a2.x - b.x, ddy = a2.y - b.y;
                    var dd = ddx * ddx + ddy * ddy;
                    if (dd < 8500) {
                        ctx.strokeStyle = 'rgba(124,111,240,' + (0.16 * (1 - dd / 8500)).toFixed(3) + ')';
                        ctx.beginPath(); ctx.moveTo(a2.x, a2.y); ctx.lineTo(b.x, b.y); ctx.stroke();
                    }
                }
            }
            for (var m = meteors.length - 1; m >= 0; m--) {
                var mt = meteors[m];
                mt.x += mt.vx; mt.y += mt.vy; mt.life -= 0.014;
                if (mt.life <= 0 || mt.x < -80 || mt.x > W + 80 || mt.y > H + 40) { meteors.splice(m, 1); continue; }
                var grad = ctx.createLinearGradient(mt.x, mt.y, mt.x - mt.vx * 9, mt.y - mt.vy * 9);
                grad.addColorStop(0, 'rgba(200,190,255,' + (0.8 * mt.life).toFixed(3) + ')');
                grad.addColorStop(1, 'rgba(103,232,249,0)');
                ctx.strokeStyle = grad; ctx.lineWidth = 1.6;
                ctx.beginPath(); ctx.moveTo(mt.x, mt.y); ctx.lineTo(mt.x - mt.vx * 9, mt.y - mt.vy * 9); ctx.stroke();
                ctx.lineWidth = 1;
            }
            requestAnimationFrame(frame);
        }
        cosmos.parentElement.addEventListener('pointermove', function (e) {
            var rect = cosmos.getBoundingClientRect();
            pointer.x = e.clientX - rect.left; pointer.y = e.clientY - rect.top;
        });
        cosmos.parentElement.addEventListener('pointerleave', function () { pointer.x = pointer.y = -9999; });
        doc.addEventListener('visibilitychange', function () {
            running = !doc.hidden;
            if (running && visible) requestAnimationFrame(frame);
        });
        if ('IntersectionObserver' in window) {
            new IntersectionObserver(function (entries) {
                visible = entries[0].isIntersecting;
                if (visible && running) requestAnimationFrame(frame);
            }).observe(cosmos);
        }
        window.addEventListener('resize', resize);
        resize();
        requestAnimationFrame(frame);
    }

    /* ── 光标环境光影：径向光晕跟随指针（仅 transform/opacity） ── */
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

    /* ── 套餐卡 3D 倾斜 + 镜面流光 ───────────────────────────── */
    if (!reduced && finePointer) {
        doc.querySelectorAll('[data-tilt]').forEach(function (card) {
            card.addEventListener('pointermove', function (e) {
                var r = card.getBoundingClientRect();
                var px = (e.clientX - r.left) / r.width, py = (e.clientY - r.top) / r.height;
                card.style.setProperty('--ry', ((px - 0.5) * 9).toFixed(2) + 'deg');
                card.style.setProperty('--rx', ((0.5 - py) * 9).toFixed(2) + 'deg');
                card.style.setProperty('--gx', (px * 100).toFixed(1) + '%');
                card.style.setProperty('--gy', (py * 100).toFixed(1) + '%');
            });
            card.addEventListener('pointerleave', function () {
                card.style.setProperty('--rx', '0deg');
                card.style.setProperty('--ry', '0deg');
            });
        });
    }

    /* ── 支付台 ─────────────────────────────────────────────── */
    var payCard = doc.getElementById('pay-card');
    if (payCard) {
        /* 进入页滚到支付台 */
        setTimeout(function () {
            doc.getElementById('pay').scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
        }, 80);

        /* 支付方式切换 */
        var qrImg = doc.getElementById('pay-qr');
        doc.querySelectorAll('.pay-tab').forEach(function (tab) {
            tab.addEventListener('click', function () {
                doc.querySelectorAll('.pay-tab').forEach(function (t) {
                    t.classList.remove('active'); t.setAttribute('aria-selected', 'false');
                });
                tab.classList.add('active'); tab.setAttribute('aria-selected', 'true');
                var method = tab.getAttribute('data-method');
                var src = qrImg.getAttribute('data-' + method);
                if (src && qrImg.getAttribute('src') !== src) {
                    qrImg.style.opacity = '0';
                    setTimeout(function () { qrImg.src = src; qrImg.style.opacity = '1'; }, 140);
                }
            });
        });
        if (qrImg) qrImg.style.transition = 'opacity 0.14s';

        /* 复制订单号 */
        var copyBtn = doc.getElementById('pay-copy');
        if (copyBtn) {
            copyBtn.addEventListener('click', function () {
                var text = doc.getElementById('pay-order-no').textContent.trim();
                var done = function () {
                    copyBtn.textContent = '已复制';
                    setTimeout(function () { copyBtn.textContent = '复制'; }, 1200);
                };
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(text).then(done, done);
                } else {
                    var ta = doc.createElement('textarea');
                    ta.value = text; doc.body.appendChild(ta); ta.select();
                    try { doc.execCommand('copy'); } catch (e) { /* 忽略 */ }
                    ta.remove(); done();
                }
            });
        }

        /* 状态轮询 + 倒计时 + 礼花 */
        var pill = doc.getElementById('pay-pill');
        var pillText = doc.getElementById('pay-pill-text');
        var hint = doc.getElementById('pay-hint');
        var countdownEl = doc.getElementById('pay-countdown');
        var successBox = doc.getElementById('pay-success');
        var statusUrl = payCard.getAttribute('data-status-url');
        var finished = false, fails = 0;

        function confetti() {
            if (reduced) return;
            var canvas = doc.getElementById('pay-confetti');
            if (!canvas) return;
            var cctx = canvas.getContext('2d');
            var cw = canvas.width = window.innerWidth;
            var ch = canvas.height = window.innerHeight;
            var palette = ['#8b7ff5', '#67e8f9', '#34d399', '#fbbf24', '#c4b5fd', '#a5f3fc'];
            var parts = [];
            for (var i = 0; i < 150; i++) {
                var ang = Math.random() * Math.PI * 2;
                var speed = 3 + Math.random() * 7;
                parts.push({
                    x: cw / 2, y: ch * 0.32,
                    vx: Math.cos(ang) * speed, vy: Math.sin(ang) * speed - 3.5,
                    w: 4 + Math.random() * 5, h: 3 + Math.random() * 4,
                    rot: Math.random() * Math.PI, vr: (Math.random() - 0.5) * 0.25,
                    color: palette[i % palette.length], life: 1
                });
            }
            var frames = 0;
            var tick = function () {
                cctx.clearRect(0, 0, cw, ch);
                frames++;
                for (var j = 0; j < parts.length; j++) {
                    var p = parts[j];
                    p.x += p.vx; p.y += p.vy; p.vy += 0.16; p.vx *= 0.985; p.rot += p.vr;
                    p.life = Math.max(0, 1 - frames / 150);
                    cctx.save();
                    cctx.translate(p.x, p.y); cctx.rotate(p.rot);
                    cctx.globalAlpha = p.life;
                    cctx.fillStyle = p.color;
                    cctx.fillRect(-p.w / 2, -p.h / 2, p.w, p.h);
                    cctx.restore();
                }
                if (frames < 170) requestAnimationFrame(tick);
                else cctx.clearRect(0, 0, cw, ch);
            };
            requestAnimationFrame(tick);
        }

        function succeed(status) {
            finished = true;
            pill.classList.add('ok');
            pillText.textContent = status === 'paid' ? '已支付，正在到账…' : '已到账';
            if (countdownEl) countdownEl.textContent = '';
            if (status === 'delivered') {
                if (successBox) successBox.hidden = false;
                confetti();
            } else {
                /* paid：短暂后再轮询一次拿 delivered */
                finished = false;
                setTimeout(poll, 1800);
            }
        }
        function fail(reason) {
            finished = true;
            pill.classList.add('fail');
            pillText.textContent = reason;
            if (countdownEl) countdownEl.textContent = '';
            if (hint) hint.innerHTML = '该订单已失效，请返回商店重新发起。';
        }
        function poll() {
            if (finished) return;
            fetch(statusUrl, { credentials: 'same-origin' })
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (data) {
                    if (finished) return;
                    fails = 0;
                    var st = data && data.status;
                    if (st === 'delivered') succeed('delivered');
                    else if (st === 'paid') succeed('paid');
                    else if (st === 'cancelled') fail('订单已取消');
                    else if (st === 'expired') fail('订单已过期');
                    else if (st === 'failed') fail('支付失败');
                    else setTimeout(poll, 3000);
                })
                .catch(function () {
                    if (finished) return;
                    fails++;
                    if (fails > 20) { fail('网络异常，请刷新查询'); return; }
                    setTimeout(poll, 4000);
                });
        }
        setTimeout(poll, 2200);

        /* 匹配窗口倒计时（展示用途，过期后仍继续轮询兜底） */
        var remain = 15 * 60;
        var timer = setInterval(function () {
            if (finished) { clearInterval(timer); return; }
            remain--;
            if (remain <= 0) {
                clearInterval(timer);
                if (countdownEl) countdownEl.textContent = '匹配窗口已过，如已支付将自动入账或转人工处理';
                return;
            }
            var mm = String(Math.floor(remain / 60));
            var ss = String(remain % 60).padStart(2, '0');
            if (countdownEl) countdownEl.textContent = '自动匹配窗口 ' + mm + ':' + ss;
        }, 1000);
    }
})();
