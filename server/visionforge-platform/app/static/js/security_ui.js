(() => {
    'use strict';

    const confirmationText = (element) => {
        const value = element?.dataset?.confirm;
        return typeof value === 'string' ? value.trim() : '';
    };

    document.addEventListener('click', (event) => {
        const target = event.target instanceof Element
            ? event.target.closest('[data-confirm]')
            : null;
        const message = confirmationText(target);
        if (target && message && !window.confirm(message)) {
            event.preventDefault();
            event.stopImmediatePropagation();
        }
    }, true);

    document.addEventListener('submit', (event) => {
        const form = event.target instanceof HTMLFormElement ? event.target : null;
        const message = confirmationText(form);
        if (form && message && !window.confirm(message)) {
            event.preventDefault();
            event.stopImmediatePropagation();
        }
    }, true);

    document.addEventListener('error', (event) => {
        const image = event.target instanceof HTMLImageElement
            ? event.target
            : null;
        if (!image || !image.hasAttribute('data-hide-on-error')) return;
        image.style.display = 'none';

        const fallbackId = (image.dataset.errorTarget || '').trim();
        if (fallbackId) {
            const fallback = document.getElementById(fallbackId);
            if (fallback instanceof HTMLElement) fallback.style.display = 'block';
        }

        const messageTargetId = (image.dataset.errorMessageTarget || '').trim();
        const message = (image.dataset.errorMessage || '').trim();
        if (messageTargetId && message) {
            const messageTarget = document.getElementById(messageTargetId);
            if (messageTarget instanceof HTMLElement) messageTarget.textContent = message;
        }
    }, true);
})();
