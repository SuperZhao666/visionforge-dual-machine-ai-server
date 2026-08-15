/* ═══════════════════════════════════════════════════════════════
   VisionForge Admin 驾驶舱图表（零依赖 Canvas 渲染，无外部库）
   数据源：window.__VF_ADMIN_CHARTS__（/admin 路由注入）
   - trend：近 30 天收入 + 订单双折线（面积渐变、hover 十字线 tooltip）
   - users / hours：近 30 天柱状图
   - status：订单状态环形图（HTML 图例）
   - plans：套餐收入横向条形图
   prefers-reduced-motion 时跳过动画直接绘制终态。
   ═══════════════════════════════════════════════════════════════ */
(function () {
    'use strict';

    var DATA = window.__VF_ADMIN_CHARTS__ || {};
    var reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    var COLORS = {
        primary: '#8b7ff5', accent: '#67e8f9', success: '#34d399',
        warning: '#fbbf24', error: '#f87171', muted: '#5d6579',
        grid: 'rgba(255,255,255,0.06)', tick: '#5d6579', text: '#9aa3ba'
    };
    var STATUS_META = {
        delivered: ['已发货', '#34d399'], paid: ['已支付', '#67e8f9'],
        pending: ['待支付', '#fbbf24'], cancelled: ['已取消', '#5d6579'],
        failed: ['已失败', '#f87171'], refund_required: ['待退款', '#fb923c'],
        refunding: ['退款中', '#fb923c'], refunded: ['已退款', '#94a3b8']
    };

    function fmtInt(v) { return Number(v || 0).toLocaleString('zh-CN'); }
    function fmtMoney(v) {
        v = Number(v || 0);
        if (Math.abs(v) >= 10000) return '¥' + (v / 10000).toFixed(1) + '万';
        return '¥' + fmtInt(Math.round(v));
    }
    function fmtHours(v) { return Number(v || 0).toFixed(1) + 'h'; }
    function shortDay(label) { return label.slice(5); } /* YYYY-MM-DD → MM-DD */

    function niceCeil(v) {
        if (v <= 0) return 1;
        var mag = Math.pow(10, Math.floor(Math.log10(v)));
        var n = v / mag;
        if (n <= 1) return mag;
        if (n <= 2) return 2 * mag;
        if (n <= 5) return 5 * mag;
        return 10 * mag;
    }

    function setup(canvas) {
        var dpr = Math.min(window.devicePixelRatio || 1, 2);
        var rect = canvas.getBoundingClientRect();
        canvas.width = Math.max(1, Math.round(rect.width * dpr));
        canvas.height = Math.max(1, Math.round(rect.height * dpr));
        var ctx = canvas.getContext('2d');
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        return { ctx: ctx, w: rect.width, h: rect.height };
    }

    function getTip(box) {
        var tip = box.querySelector('.chart-tip');
        if (!tip) {
            tip = document.createElement('div');
            tip.className = 'chart-tip';
            box.appendChild(tip);
        }
        return tip;
    }
    function showTip(box, tip, x, y, html) {
        tip.innerHTML = html;
        tip.classList.add('on');
        var bw = box.clientWidth;
        var tw = tip.offsetWidth;
        var left = Math.min(Math.max(x + 12, 4), Math.max(4, bw - tw - 4));
        tip.style.left = left + 'px';
        tip.style.top = Math.max(y - tip.offsetHeight - 10, 4) + 'px';
    }
    function hideTip(tip) { tip.classList.remove('on'); }

    function drawEmpty(g, text) {
        g.ctx.fillStyle = COLORS.tick;
        g.ctx.font = '12px sans-serif';
        g.ctx.textAlign = 'center';
        g.ctx.fillText(text || '暂无数据', g.w / 2, g.h / 2);
    }

    function xTicks(labels, padL, plotW) {
        var n = labels.length;
        var step = Math.max(1, Math.ceil(n / 6));
        var ticks = [];
        for (var i = 0; i < n; i += step) ticks.push({ x: padL + (n === 1 ? plotW / 2 : (i / (n - 1)) * plotW), label: shortDay(labels[i]) });
        return ticks;
    }

    function catmullPath(ctx, pts) {
        ctx.moveTo(pts[0].x, pts[0].y);
        for (var i = 0; i < pts.length - 1; i++) {
            var p0 = pts[Math.max(0, i - 1)], p1 = pts[i], p2 = pts[i + 1], p3 = pts[Math.min(pts.length - 1, i + 2)];
            ctx.bezierCurveTo(
                p1.x + (p2.x - p0.x) / 6, p1.y + (p2.y - p0.y) / 6,
                p2.x - (p3.x - p1.x) / 6, p2.y - (p3.y - p1.y) / 6,
                p2.x, p2.y
            );
        }
    }

    /* ── 双折线趋势（左轴金额 / 右轴单量） ─────────────────────── */
    function renderTrend(canvas, cfg) {
        var box = canvas.parentElement;
        var tip = getTip(box);
        var hover = -1, progress = reduced ? 1 : 0;
        var labels = cfg.labels || [];
        if (!labels.length) { drawEmpty(setup(canvas)); return; }

        function draw() {
            var g = setup(canvas), ctx = g.ctx;
            var padL = 52, padR = 40, padT = 12, padB = 26;
            var plotW = g.w - padL - padR, plotH = g.h - padT - padB;
            var maxR = niceCeil(Math.max.apply(null, cfg.revenue.concat([1])));
            var maxO = niceCeil(Math.max.apply(null, cfg.orders.concat([1])));
            var n = labels.length;
            function X(i) { return padL + (n === 1 ? plotW / 2 : (i / (n - 1)) * plotW); }
            function YR(v) { return padT + plotH - (v / maxR) * plotH; }
            function YO(v) { return padT + plotH - (v / maxO) * plotH; }

            ctx.font = '10px sans-serif';
            ctx.textAlign = 'right';
            ctx.strokeStyle = COLORS.grid; ctx.fillStyle = COLORS.tick; ctx.lineWidth = 1;
            for (var r = 0; r <= 4; r++) {
                var yy = padT + (plotH * r) / 4;
                ctx.beginPath(); ctx.moveTo(padL, yy); ctx.lineTo(padL + plotW, yy); ctx.stroke();
                ctx.fillText(fmtMoney(maxR * (4 - r) / 4), padL - 6, yy + 3);
                ctx.textAlign = 'left';
                ctx.fillText(fmtInt(maxO * (4 - r) / 4), padL + plotW + 6, yy + 3);
                ctx.textAlign = 'right';
            }
            ctx.textAlign = 'center';
            xTicks(labels, padL, plotW).forEach(function (t) { ctx.fillText(t.label, t.x, g.h - 8); });

            ctx.save();
            ctx.beginPath(); ctx.rect(0, 0, padL + plotW * progress + 2, g.h); ctx.clip();

            var ptsR = cfg.revenue.map(function (v, i) { return { x: X(i), y: YR(v) }; });
            var grad = ctx.createLinearGradient(0, padT, 0, padT + plotH);
            grad.addColorStop(0, 'rgba(124,111,240,0.30)'); grad.addColorStop(1, 'rgba(124,111,240,0)');
            ctx.beginPath();
            catmullPath(ctx, ptsR);
            ctx.lineTo(ptsR[ptsR.length - 1].x, padT + plotH); ctx.lineTo(ptsR[0].x, padT + plotH); ctx.closePath();
            ctx.fillStyle = grad; ctx.fill();

            ctx.beginPath(); catmullPath(ctx, ptsR);
            ctx.strokeStyle = COLORS.primary; ctx.lineWidth = 2; ctx.stroke();

            var ptsO = cfg.orders.map(function (v, i) { return { x: X(i), y: YO(v) }; });
            ctx.beginPath(); catmullPath(ctx, ptsO);
            ctx.strokeStyle = COLORS.accent; ctx.lineWidth = 1.6;
            ctx.setLineDash([5, 4]); ctx.stroke(); ctx.setLineDash([]);
            ctx.restore();

            if (hover >= 0 && hover < n) {
                var hx = X(hover);
                ctx.strokeStyle = 'rgba(255,255,255,0.18)'; ctx.lineWidth = 1;
                ctx.beginPath(); ctx.moveTo(hx, padT); ctx.lineTo(hx, padT + plotH); ctx.stroke();
                [[ptsR[hover], COLORS.primary], [ptsO[hover], COLORS.accent]].forEach(function (p) {
                    ctx.beginPath(); ctx.arc(p[0].x, p[0].y, 3.5, 0, Math.PI * 2);
                    ctx.fillStyle = p[1]; ctx.fill();
                    ctx.strokeStyle = '#0a0c14'; ctx.lineWidth = 1.5; ctx.stroke();
                });
            }
        }

        canvas.addEventListener('mousemove', function (e) {
            var rect = canvas.getBoundingClientRect();
            var padL = 52, padR = 40;
            var plotW = rect.width - padL - padR;
            var ratio = (e.clientX - rect.left - padL) / plotW;
            var idx = Math.round(ratio * (labels.length - 1));
            if (idx < 0 || idx >= labels.length) { hover = -1; hideTip(tip); draw(); return; }
            hover = idx; draw();
            showTip(box, tip, e.clientX - rect.left, e.clientY - rect.top,
                '<b>' + labels[idx] + '</b><br>收入 ' + fmtMoney(cfg.revenue[idx]) + '<br>订单 ' + fmtInt(cfg.orders[idx]) + ' 单');
        });
        canvas.addEventListener('mouseleave', function () { hover = -1; hideTip(tip); draw(); });

        var legend = document.querySelector('[data-legend="trend"]');
        if (legend) {
            legend.innerHTML = '<span class="lg"><span class="dot" style="background:' + COLORS.primary + '"></span>收入（左轴）</span>' +
                '<span class="lg"><span class="dot" style="background:' + COLORS.accent + '"></span>订单量（右轴）</span>';
        }
        return { draw: draw, progress: function () { return progress; }, setProgress: function (p) { progress = p; } };
    }

    /* ── 柱状图 ───────────────────────────────────────────────── */
    function renderBars(canvas, cfg, color, fmt) {
        var box = canvas.parentElement;
        var tip = getTip(box);
        var hover = -1, progress = reduced ? 1 : 0;
        var labels = cfg.labels || [];
        if (!labels.length) { drawEmpty(setup(canvas)); return; }

        function draw() {
            var g = setup(canvas), ctx = g.ctx;
            var padL = 40, padR = 10, padT = 12, padB = 26;
            var plotW = g.w - padL - padR, plotH = g.h - padT - padB;
            var maxV = niceCeil(Math.max.apply(null, cfg.values.concat([1])));
            var n = labels.length;
            var bw = Math.max(2, (plotW / n) * 0.55);

            ctx.font = '10px sans-serif'; ctx.textAlign = 'right';
            ctx.strokeStyle = COLORS.grid; ctx.fillStyle = COLORS.tick; ctx.lineWidth = 1;
            for (var r = 0; r <= 4; r++) {
                var yy = padT + (plotH * r) / 4;
                ctx.beginPath(); ctx.moveTo(padL, yy); ctx.lineTo(padL + plotW, yy); ctx.stroke();
                ctx.fillText(fmtInt(maxV * (4 - r) / 4), padL - 5, yy + 3);
            }
            ctx.textAlign = 'center';
            xTicks(labels, padL, plotW).forEach(function (t) { ctx.fillText(t.label, t.x, g.h - 8); });

            for (var i = 0; i < n; i++) {
                var x = padL + ((i + 0.5) / n) * plotW - bw / 2;
                var hgt = (cfg.values[i] / maxV) * plotH * progress;
                var y = padT + plotH - hgt;
                ctx.fillStyle = i === hover ? color : color + 'b3';
                ctx.beginPath();
                if (ctx.roundRect) ctx.roundRect(x, y, bw, Math.max(hgt, 0.5), [3, 3, 0, 0]);
                else ctx.rect(x, y, bw, Math.max(hgt, 0.5));
                ctx.fill();
            }
        }

        canvas.addEventListener('mousemove', function (e) {
            var rect = canvas.getBoundingClientRect();
            var plotW = rect.width - 40 - 10;
            var idx = Math.floor(((e.clientX - rect.left - 40) / plotW) * labels.length);
            if (idx < 0 || idx >= labels.length) { hover = -1; hideTip(tip); draw(); return; }
            hover = idx; draw();
            showTip(box, tip, e.clientX - rect.left, e.clientY - rect.top,
                '<b>' + labels[idx] + '</b><br>' + fmt(cfg.values[idx]));
        });
        canvas.addEventListener('mouseleave', function () { hover = -1; hideTip(tip); draw(); });

        return { draw: draw, progress: function () { return progress; }, setProgress: function (p) { progress = p; } };
    }

    /* ── 环形图 ───────────────────────────────────────────────── */
    function renderDonut(canvas, items) {
        var box = canvas.parentElement;
        var tip = getTip(box);
        var hover = -1, progress = reduced ? 1 : 0;
        items = (items || []).map(function (it) {
            var meta = STATUS_META[it.status] || [it.status, COLORS.muted];
            return { label: meta[0], color: meta[1], value: it.value };
        }).filter(function (it) { return it.value > 0; });
        var total = items.reduce(function (s, it) { return s + it.value; }, 0);
        if (!total) { drawEmpty(setup(canvas), '暂无订单'); return; }

        function arcs() {
            var list = [], start = -Math.PI / 2;
            items.forEach(function (it) {
                var sweep = (it.value / total) * Math.PI * 2 * progress;
                list.push({ it: it, start: start, end: start + sweep });
                start += (it.value / total) * Math.PI * 2;
            });
            return list;
        }

        function draw() {
            var g = setup(canvas), ctx = g.ctx;
            var cx = g.w / 2, cy = g.h / 2;
            var radius = Math.min(g.w, g.h) / 2 - 14;
            arcs().forEach(function (a, i) {
                ctx.beginPath();
                ctx.arc(cx, cy, radius, a.start + 0.02, Math.max(a.start + 0.02, a.end - 0.02));
                ctx.strokeStyle = a.it.color;
                ctx.lineWidth = i === hover ? 22 : 16;
                ctx.stroke();
            });
            ctx.fillStyle = '#eef1f8';
            ctx.font = '700 20px sans-serif'; ctx.textAlign = 'center';
            ctx.fillText(fmtInt(total), cx, cy + 2);
            ctx.fillStyle = COLORS.tick; ctx.font = '10px sans-serif';
            ctx.fillText('总订单', cx, cy + 18);
        }

        canvas.addEventListener('mousemove', function (e) {
            var rect = canvas.getBoundingClientRect();
            var dx = e.clientX - rect.left - rect.width / 2;
            var dy = e.clientY - rect.top - rect.height / 2;
            var dist = Math.sqrt(dx * dx + dy * dy);
            var radius = Math.min(rect.width, rect.height) / 2 - 14;
            var found = -1;
            if (dist > radius - 12 && dist < radius + 12) {
                var ang = Math.atan2(dy, dx);
                var list = arcs();
                for (var i = 0; i < list.length; i++) {
                    var s = list[i].start, en = list[i].end;
                    if (ang >= s && ang <= en) { found = i; break; }
                }
            }
            if (found !== hover) { hover = found; draw(); }
            if (found >= 0) {
                var it = items[found];
                showTip(box, tip, e.clientX - rect.left, e.clientY - rect.top,
                    it.label + ' ' + fmtInt(it.value) + ' 单（' + Math.round((it.value / total) * 100) + '%）');
            } else hideTip(tip);
        });
        canvas.addEventListener('mouseleave', function () { hover = -1; hideTip(tip); draw(); });

        var legend = document.querySelector('[data-legend="status"]');
        if (legend) {
            legend.innerHTML = items.map(function (it) {
                return '<span class="lg"><span class="dot" style="background:' + it.color + '"></span>' + it.label + ' ' + fmtInt(it.value) + '</span>';
            }).join('');
        }
        return { draw: draw, progress: function () { return progress; }, setProgress: function (p) { progress = p; } };
    }

    /* ── 横向条形图 ───────────────────────────────────────────── */
    function renderHBars(canvas, items) {
        var box = canvas.parentElement;
        var tip = getTip(box);
        var hover = -1, progress = reduced ? 1 : 0;
        items = (items || []).filter(function (it) { return it.label; });
        if (!items.length) { drawEmpty(setup(canvas), '暂无订单'); return; }

        function draw() {
            var g = setup(canvas), ctx = g.ctx;
            var padL = 86, padR = 64, padT = 8;
            var plotW = g.w - padL - padR;
            var maxV = niceCeil(Math.max.apply(null, items.map(function (it) { return it.value; }).concat([1])));
            var rows = items.length;
            var rowH = Math.min(34, (g.h - padT - 6) / rows);
            var bh = Math.min(16, rowH * 0.5);

            ctx.font = '11px sans-serif';
            items.forEach(function (it, i) {
                var y = padT + i * rowH + (rowH - bh) / 2;
                var w = (it.value / maxV) * plotW * progress;
                ctx.fillStyle = COLORS.tick; ctx.textAlign = 'right';
                ctx.fillText(it.label.length > 9 ? it.label.slice(0, 9) + '…' : it.label, padL - 8, y + bh / 2 + 4);
                ctx.fillStyle = 'rgba(255,255,255,0.05)';
                ctx.fillRect(padL, y, plotW, bh);
                var grad = ctx.createLinearGradient(padL, 0, padL + Math.max(w, 1), 0);
                grad.addColorStop(0, '#6d5ce7'); grad.addColorStop(1, '#67e8f9');
                ctx.fillStyle = i === hover ? '#a78bfa' : grad;
                ctx.beginPath();
                if (ctx.roundRect) ctx.roundRect(padL, y, Math.max(w, 1.5), bh, 3);
                else ctx.rect(padL, y, Math.max(w, 1.5), bh);
                ctx.fill();
                ctx.fillStyle = COLORS.text; ctx.textAlign = 'left';
                ctx.fillText(fmtMoney(it.value) + ' · ' + fmtInt(it.count) + ' 单', padL + Math.max(w, 1.5) + 8, y + bh / 2 + 4);
            });
        }

        canvas.addEventListener('mousemove', function (e) {
            var rect = canvas.getBoundingClientRect();
            var rows = items.length;
            var rowH = Math.min(34, (rect.height - 8 - 6) / rows);
            var idx = Math.floor((e.clientY - rect.top - 8) / rowH);
            if (idx < 0 || idx >= rows) { hover = -1; hideTip(tip); draw(); return; }
            hover = idx; draw();
            showTip(box, tip, e.clientX - rect.left, e.clientY - rect.top,
                '<b>' + items[idx].label + '</b><br>收入 ' + fmtMoney(items[idx].value) + '<br>订单 ' + fmtInt(items[idx].count) + ' 单');
        });
        canvas.addEventListener('mouseleave', function () { hover = -1; hideTip(tip); draw(); });

        return { draw: draw, progress: function () { return progress; }, setProgress: function (p) { progress = p; } };
    }

    /* ── 初始化：按 data-chart 分发，入场动画 + 尺寸自适应 ─────── */
    var instances = [];
    document.querySelectorAll('canvas[data-chart]').forEach(function (canvas) {
        var kind = canvas.getAttribute('data-chart');
        var inst = null;
        if (kind === 'trend' && DATA.trend) inst = renderTrend(canvas, DATA.trend);
        else if (kind === 'users' && DATA.users) inst = renderBars(canvas, DATA.users, COLORS.primary, function (v) { return fmtInt(v) + ' 人'; });
        else if (kind === 'hours' && DATA.hours) inst = renderBars(canvas, DATA.hours, COLORS.success, fmtHours);
        else if (kind === 'status') inst = renderDonut(canvas, DATA.status);
        else if (kind === 'plans') inst = renderHBars(canvas, DATA.plans);
        if (inst) instances.push(inst);
    });

    function drawAll() { instances.forEach(function (inst) { inst.draw(); }); }

    function startIntro() {
        if (reduced || !instances.length) {
            drawAll();
            return;
        }
        var t0 = null, DUR = 900;
        var tick = function (ts) {
            if (!t0) t0 = ts;
            var p = Math.min((ts - t0) / DUR, 1);
            var eased = 1 - Math.pow(1 - p, 3);
            instances.forEach(function (inst) { inst.setProgress(eased); inst.draw(); });
            if (p < 1) requestAnimationFrame(tick);
        };
        requestAnimationFrame(tick);
    }

    /* 滚动到位才播入场动画：图表位于首屏下方时不在加载即白播一次 */
    if (!instances.length || reduced || !('IntersectionObserver' in window)) {
        startIntro();
    } else {
        var introStarted = false;
        var introIO = new IntersectionObserver(function (entries) {
            if (entries[0].isIntersecting && !introStarted) {
                introStarted = true;
                introIO.disconnect();
                startIntro();
            }
        }, { rootMargin: '200px' });
        introIO.observe(instances.length ? document.querySelector('canvas[data-chart]').parentElement : document.body);
    }

    if ('ResizeObserver' in window) {
        var rto = null;
        var ro = new ResizeObserver(function () {
            clearTimeout(rto);
            rto = setTimeout(function () {
                instances.forEach(function (inst) { inst.setProgress(1); });
                drawAll();
            }, 120);
        });
        document.querySelectorAll('canvas[data-chart]').forEach(function (c) { ro.observe(c.parentElement); });
    } else {
        window.addEventListener('resize', function () {
            instances.forEach(function (inst) { inst.setProgress(1); });
            drawAll();
        });
    }
})();
