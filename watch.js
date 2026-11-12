/* Watch-alert form. Posts to tools.ignixip.com and never claims an inbox exists. */
(function (root) {
    'use strict';

    var ENDPOINT = 'https://tools.ignixip.com/watch/subscribe';
    var MESSAGES = {
        successTitle: 'Check your inbox to confirm',
        successBody: 'If that address can receive mail, a confirmation is on its way. We only email when something changes, and you can unsubscribe from any message.',
        invalid: 'That email or address was not accepted. Check both and try again.',
        unavailable: "Alerts aren't available just now. Please try later.",
        confirmedTitle: "You're confirmed",
        confirmedBody: "We'll email you when something changes for that watch. Nothing is sent while it stays the same, and you can unsubscribe from any message.",
        unsubscribedTitle: "You're unsubscribed",
        unsubscribedBody: "We won't send further alerts for that watch. You can set up a new one below if you want.",
        linkTitle: 'That link is not valid',
        linkBody: 'It may have expired, or it was already used. You can subscribe again with the form.',
        limitTitle: "You're at the limit",
        limitBody: "You're already watching 10 addresses, which is the limit. Unsubscribe from one, then open the confirmation link again.",
        unavailableTitle: 'Try later'
    };

    var MANAGE_ROOT = 'https://tools.ignixip.com/watch/manage/';
    var WATCH_LIMIT = 10;

    function isIPv4(value) {
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return false;
        var parts = value.split('.');
        for (var i = 0; i < parts.length; i++) {
            if (parts[i].length > 1 && parts[i].charAt(0) === '0') return false;
            var n = Number(parts[i]);
            if (n > 255) return false;
        }
        return true;
    }

    function isHexGroup(group) {
        return /^[0-9a-f]{1,4}$/i.test(group);
    }

    function isIPv6(value) {
        if (value.indexOf(':') === -1) return false;
        if (!/^[0-9a-f:]+$/i.test(value)) return false;
        if (value.indexOf(':::') !== -1) return false;
        var halves = value.split('::');
        if (halves.length > 2) return false;
        if (halves.length === 2) {
            var left = halves[0] ? halves[0].split(':') : [];
            var right = halves[1] ? halves[1].split(':') : [];
            if (left.length + right.length > 7) return false;
            var groups = left.concat(right);
            for (var i = 0; i < groups.length; i++) if (!isHexGroup(groups[i])) return false;
            return true;
        }
        var full = value.split(':');
        if (full.length !== 8) return false;
        for (var j = 0; j < full.length; j++) if (!isHexGroup(full[j])) return false;
        return true;
    }

    function isDomain(value) {
        if (!value || value.length > 253) return false;
        if (!/^[a-z0-9.-]+$/i.test(value)) return false;
        if (value.indexOf('..') !== -1) return false;
        if (!/[a-z]/i.test(value)) return false;
        var labels = value.split('.');
        if (labels.length < 2) return false;
        if (labels[labels.length - 1].length < 2) return false;
        for (var i = 0; i < labels.length; i++) {
            var label = labels[i];
            if (!label || label.length > 63) return false;
            if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(label)) return false;
        }
        return true;
    }

    function classifyTarget(raw) {
        var value = String(raw == null ? '' : raw).trim().replace(/\.$/, '');
        if (!value) return { ok: false, reason: 'empty' };
        if (isIPv4(value)) return { ok: true, target: value, type: 'ip' };
        if (isIPv6(value)) return { ok: true, target: value.toLowerCase(), type: 'ip' };
        if (isDomain(value)) return { ok: true, target: value.toLowerCase(), type: 'domain' };
        return { ok: false, reason: 'invalid' };
    }

    function defaultKinds(type) {
        if (type === 'ip') return ['blacklist'];
        if (type === 'domain') return ['dns', 'blacklist'];
        return [];
    }

    function isEmail(value) {
        var email = String(value || '').trim();
        if (email.length < 3 || email.length > 254) return false;
        return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
    }

    function normaliseKinds(list) {
        var wanted = { blacklist: false, dns: false };
        (list || []).forEach(function (kind) {
            if (kind === 'blacklist' || kind === 'dns') wanted[kind] = true;
        });
        var kinds = [];
        if (wanted.blacklist) kinds.push('blacklist');
        if (wanted.dns) kinds.push('dns');
        return kinds;
    }

    function validate(input) {
        var errors = {};
        var email = String(input.email == null ? '' : input.email).trim();
        var parsed = classifyTarget(input.target);
        var kinds = normaliseKinds(input.kinds);
        if (!email) errors.email = 'Enter the email address that should receive the alerts.';
        else if (!isEmail(email)) errors.email = 'That email address does not look valid.';
        if (!parsed.ok) {
            errors.target = parsed.reason === 'empty'
                ? 'Enter an IP address or a domain name.'
                : 'Enter an IP address, such as 8.8.8.8, or a domain, such as example.com.';
        }
        if (!kinds.length) errors.kinds = 'Choose at least one thing to watch.';
        if (errors.email || errors.target || errors.kinds) return { ok: false, errors: errors };
        if (String(input.honeypot || '').trim()) return { ok: true, honeypot: true };
        return {
            ok: true,
            payload: { email: email, target: parsed.target, kinds: kinds }
        };
    }

    function outcomeFrom(status, body) {
        if (status === 400) return { state: 'invalid' };
        if (status === 200 && body && body.ok === true) return { state: 'success' };
        return { state: 'unavailable' };
    }

    function submit(payload, fetchImpl) {
        var doFetch = fetchImpl || root.fetch;
        return doFetch(ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({
                email: payload.email,
                target: payload.target,
                kinds: payload.kinds
            })
        }).then(function (response) {
            return response.json().catch(function () { return null; }).then(function (body) {
                return outcomeFrom(response.status, body);
            });
        }).catch(function () {
            return { state: 'unavailable' };
        });
    }

    function bannerFromSearch(params) {
        if (params.get('error') === 'invalid') {
            return { kind: 'warn', title: MESSAGES.linkTitle, text: MESSAGES.linkBody };
        }
        if (params.get('confirmed') === '1') {
            return { kind: 'ok', title: MESSAGES.confirmedTitle, text: MESSAGES.confirmedBody };
        }
        if (params.get('unsubscribed') === '1') {
            return { kind: 'ok', title: MESSAGES.unsubscribedTitle, text: MESSAGES.unsubscribedBody };
        }
        if (params.get('error') === 'limit') {
            return { kind: 'warn', title: MESSAGES.limitTitle, text: MESSAGES.limitBody };
        }
        return null;
    }

    function manageUrl(token, action) {
        var url = MANAGE_ROOT + encodeURIComponent(String(token || ''));
        if (action === 'remove') return url + '/remove';
        if (action === 'remove-all') return url + '/remove-all';
        return url;
    }

    function manageOutcome(status, body) {
        if (status === 404) return { state: 'invalid' };
        if (status === 200 && body && Array.isArray(body.watches)) {
            return { state: 'ok', doc: body, removed: body.removed };
        }
        return { state: 'unavailable' };
    }

    function describeKinds(kinds) {
        var list = kinds || [];
        var blacklist = list.indexOf('blacklist') !== -1;
        var dns = list.indexOf('dns') !== -1;
        if (blacklist && dns) return 'Blacklist listings and DNS changes';
        if (dns) return 'DNS changes for SPF, DMARC, DKIM and MX';
        if (blacklist) return 'Blacklist listings and delistings';
        return 'Changes';
    }

    function describeStatus(status) {
        if (status === 'confirmed') return 'Confirmed';
        if (status === 'pending') return 'Waiting for confirmation';
        return 'Unknown';
    }

    function describeCreated(iso) {
        var date = new Date(iso);
        if (!iso || isNaN(date.getTime())) return '';
        try {
            return date.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
        } catch (err) {
            return '';
        }
    }

    function readJson(response) {
        return response.json().catch(function () { return null; }).then(function (body) {
            return manageOutcome(response.status, body);
        });
    }

    function fetchManage(token, fetchImpl) {
        var doFetch = fetchImpl || root.fetch;
        return doFetch(manageUrl(token), {
            method: 'GET',
            headers: { 'Accept': 'application/json' }
        }).then(readJson).catch(function () {
            return { state: 'unavailable' };
        });
    }

    function postManage(token, action, payload, fetchImpl) {
        var doFetch = fetchImpl || root.fetch;
        return doFetch(manageUrl(token, action), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify(payload || {})
        }).then(readJson).catch(function () {
            return { state: 'unavailable' };
        });
    }

    function selectedKinds(form) {
        var boxes = form.querySelectorAll('input[name="kinds"]');
        var kinds = [];
        for (var i = 0; i < boxes.length; i++) if (boxes[i].checked) kinds.push(boxes[i].value);
        return kinds;
    }

    function setKinds(form, kinds) {
        var boxes = form.querySelectorAll('input[name="kinds"]');
        for (var i = 0; i < boxes.length; i++) boxes[i].checked = kinds.indexOf(boxes[i].value) !== -1;
    }

    function clearErrors(form) {
        var fields = form.querySelectorAll('[aria-invalid]');
        for (var i = 0; i < fields.length; i++) fields[i].removeAttribute('aria-invalid');
        var errors = form.querySelectorAll('.field-error');
        for (var j = 0; j < errors.length; j++) {
            errors[j].textContent = '';
            errors[j].hidden = true;
        }
    }

    function showFieldErrors(form, errors) {
        var order = ['email', 'target', 'kinds'];
        var first = null;
        order.forEach(function (name) {
            if (!errors[name]) return;
            var input = name === 'kinds' ? form.querySelector('.watch-kinds') : form.querySelector('[name="' + name + '"]');
            var note = form.querySelector('#' + (name === 'email' ? 'watch-email-error' : name === 'target' ? 'watch-target-error' : 'watch-kinds-error'));
            if (input) input.setAttribute('aria-invalid', 'true');
            if (note) {
                note.textContent = errors[name];
                note.hidden = false;
            }
            if (!first) first = input;
        });
        if (first && first.classList && first.classList.contains('watch-kinds')) {
            var box = first.querySelector('input');
            if (box) first = box;
        }
        if (first && first.focus) first.focus();
    }

    function showBanner(banner, notice, withReset) {
        if (!banner) return;
        banner.hidden = false;
        banner.className = 'watch-banner ' + (notice.kind === 'ok' ? 'ok' : 'warn');
        var title = banner.querySelector('h2');
        var text = banner.querySelector('p');
        if (title) title.textContent = notice.title;
        if (text) text.textContent = notice.text;
        var reset = banner.querySelector('[data-watch-reset]');
        if (reset) reset.hidden = !withReset;
        if (banner.focus) banner.focus();
    }

    function mount(doc) {
        var form = doc.getElementById('watch-form');
        var banner = doc.getElementById('watch-banner');
        if (!form || !banner) return;
        var email = doc.getElementById('watch-email');
        var target = doc.getElementById('watch-target');
        var honeypot = doc.getElementById('watch-fax');
        var submitBtn = form.querySelector('[type="submit"]');
        var touched = false;
        var params = new URLSearchParams(doc.defaultView.location.search);

        form.querySelectorAll('input[name="kinds"]').forEach(function (box) {
            box.addEventListener('change', function () { touched = true; });
        });

        function applyDefaults() {
            if (touched) return;
            var parsed = classifyTarget(target.value);
            setKinds(form, parsed.ok ? defaultKinds(parsed.type) : []);
        }

        var presetTarget = params.get('target');
        if (presetTarget) target.value = presetTarget;
        var kindsParam = params.get('kinds');
        if (kindsParam !== null && params.has('kinds')) {
            setKinds(form, normaliseKinds(kindsParam.split(',').map(function (part) { return part.trim(); })));
            touched = true;
        } else {
            applyDefaults();
        }
        target.addEventListener('input', applyDefaults);

        var notice = bannerFromSearch(params);
        if (notice) showBanner(banner, notice, false);

        var manageToken = (params.get('manage') || '').trim();
        var manage = doc.getElementById('watch-manage');
        if (manageToken && manage) mountManage(doc, manage, form, banner, email, manageToken);

        var reset = banner.querySelector('[data-watch-reset]');
        if (reset) {
            reset.addEventListener('click', function () {
                banner.hidden = true;
                form.hidden = false;
                submitBtn.disabled = false;
                submitBtn.textContent = 'Email me when it changes';
                email.focus();
            });
        }

        form.addEventListener('submit', function (event) {
            event.preventDefault();
            var result = validate({
                email: email.value,
                target: target.value,
                kinds: selectedKinds(form),
                honeypot: honeypot ? honeypot.value : ''
            });
            clearErrors(form);
            if (!result.ok) {
                banner.hidden = true;
                showFieldErrors(form, result.errors);
                return;
            }
            if (result.honeypot) {
                form.hidden = true;
                showBanner(banner, { kind: 'ok', title: MESSAGES.successTitle, text: MESSAGES.successBody }, true);
                return;
            }
            submitBtn.disabled = true;
            submitBtn.textContent = 'Sending…';
            form.setAttribute('aria-busy', 'true');
            submit(result.payload).then(function (outcome) {
                form.removeAttribute('aria-busy');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Email me when it changes';
                if (outcome.state === 'success') {
                    form.hidden = true;
                    showBanner(banner, { kind: 'ok', title: MESSAGES.successTitle, text: MESSAGES.successBody }, true);
                    return;
                }
                showBanner(banner, {
                    kind: 'warn',
                    title: outcome.state === 'invalid' ? 'Check the form' : 'Try later',
                    text: outcome.state === 'invalid' ? MESSAGES.invalid : MESSAGES.unavailable
                }, false);
            });
        });
    }

    function mountManage(doc, panel, form, banner, emailField, token) {
        var emailLine = panel.querySelector('[data-manage-email]');
        var loading = panel.querySelector('[data-manage-loading]');
        var list = panel.querySelector('[data-manage-list]');
        var empty = panel.querySelector('[data-manage-empty]');
        var note = panel.querySelector('[data-manage-note]');
        var removeAll = panel.querySelector('[data-manage-remove-all]');
        var add = panel.querySelector('[data-manage-add]');
        var armed = false;
        var limitNotice = new URLSearchParams(doc.defaultView.location.search).get('error') === 'limit';

        form.hidden = true;
        panel.hidden = false;
        loading.hidden = false;
        list.hidden = true;
        empty.hidden = true;
        removeAll.hidden = true;
        add.hidden = true;
        panel.setAttribute('aria-busy', 'true');

        function showInvalid() {
            panel.hidden = true;
            form.hidden = false;
            showBanner(banner, { kind: 'warn', title: MESSAGES.linkTitle, text: MESSAGES.linkBody }, false);
        }

        function showUnavailable() {
            panel.hidden = true;
            form.hidden = false;
            showBanner(banner, { kind: 'warn', title: MESSAGES.unavailableTitle, text: MESSAGES.unavailable }, false);
        }

        function paint(docBody) {
            var watches = docBody.watches || [];
            emailLine.textContent = docBody.email_masked ? ('Alerts for ' + docBody.email_masked) : '';
            list.textContent = '';
            watches.forEach(function (item) {
                var row = doc.createElement('li');
                row.className = 'watch-row';
                var info = doc.createElement('div');
                var target = doc.createElement('div');
                target.className = 'watch-target';
                target.textContent = item.target || '';
                var meta = doc.createElement('div');
                meta.className = 'watch-meta';
                var status = doc.createElement('span');
                status.className = 'watch-status ' + (item.status === 'confirmed' ? 'confirmed' : item.status === 'pending' ? 'pending' : '');
                status.textContent = describeStatus(item.status);
                meta.appendChild(status);
                var when = describeCreated(item.created_at);
                meta.appendChild(doc.createTextNode(' · ' + describeKinds(item.kinds) + (when ? ' · since ' + when : '')));
                info.appendChild(target);
                info.appendChild(meta);
                var button = doc.createElement('button');
                button.type = 'button';
                button.className = 'ix-btn ghost';
                button.textContent = 'Remove';
                button.setAttribute('aria-label', 'Remove ' + (item.target || 'this watch'));
                button.addEventListener('click', function () { removeOne(item.target, button); });
                row.appendChild(info);
                row.appendChild(button);
                list.appendChild(row);
            });
            var has = watches.length > 0;
            list.hidden = !has;
            empty.hidden = has;
            removeAll.hidden = !has;
            removeAll.textContent = 'Remove all';
            armed = false;
            add.hidden = !has || watches.length >= WATCH_LIMIT || limitNotice;
            loading.hidden = true;
            panel.hidden = false;
            form.hidden = has;
            panel.setAttribute('aria-busy', 'false');
        }

        function removeOne(target, button) {
            if (!target) return;
            button.disabled = true;
            note.textContent = '';
            note.hidden = true;
            postManage(token, 'remove', { target: target }).then(function (result) {
                button.disabled = false;
                if (result.state === 'invalid') return showInvalid();
                if (result.state !== 'ok') {
                    note.hidden = false;
                    note.textContent = MESSAGES.unavailable;
                    return;
                }
                paint(result.doc);
                note.hidden = false;
                note.textContent = result.removed === false
                    ? 'That address is no longer on the list.'
                    : ('Removed ' + target + '.');
            });
        }

        removeAll.addEventListener('click', function () {
            if (!armed) {
                armed = true;
                removeAll.textContent = 'Remove all watches?';
                return;
            }
            armed = false;
            removeAll.disabled = true;
            note.textContent = '';
            note.hidden = true;
            postManage(token, 'remove-all', {}).then(function (result) {
                removeAll.disabled = false;
                if (result.state === 'invalid') return showInvalid();
                if (result.state !== 'ok') {
                    note.hidden = false;
                    note.textContent = MESSAGES.unavailable;
                    return;
                }
                var count = typeof result.removed === 'number' ? result.removed : 0;
                paint(result.doc);
                note.hidden = false;
                if (count === 0) note.textContent = 'There was nothing to remove.';
                else if (count === 1) note.textContent = 'Removed 1 watch.';
                else note.textContent = 'Removed ' + count + ' watches.';
            });
        });

        if (add) {
            add.addEventListener('click', function () {
                form.hidden = false;
                if (emailField) emailField.focus();
            });
        }

        fetchManage(token).then(function (result) {
            if (result.state === 'invalid') return showInvalid();
            if (result.state !== 'ok') return showUnavailable();
            paint(result.doc);
            if (!banner.hidden) return;
            var heading = panel.querySelector('h2');
            if (heading) {
                heading.tabIndex = -1;
                heading.focus();
            }
        });
    }

    var api = {
        ENDPOINT: ENDPOINT,
        MESSAGES: MESSAGES,
        classifyTarget: classifyTarget,
        defaultKinds: defaultKinds,
        validate: validate,
        outcomeFrom: outcomeFrom,
        submit: submit,
        bannerFromSearch: bannerFromSearch,
        manageUrl: manageUrl,
        manageOutcome: manageOutcome,
        describeKinds: describeKinds,
        describeStatus: describeStatus,
        fetchManage: fetchManage,
        postManage: postManage,
        mount: mount
    };

    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (root && root.document) {
        if (root.document.readyState === 'loading') root.document.addEventListener('DOMContentLoaded', function () { mount(root.document); });
        else mount(root.document);
    }
})(typeof window !== 'undefined' ? window : null);
