/* Shareable lookup links. Query values are validated before they are written
   into a URL or copied back into a form, so a crafted link cannot be reflected
   as HTML. Headers and bulk lists are never encoded. */
(function (root) {
    'use strict';

    var SLUGS = {
        ip: 'ip-lookup',
        blacklist: 'blacklist-check',
        dns: 'dns-lookup',
        dmarc: 'dmarc-check',
        asn: 'asn-lookup'
    };

    var NOTES = {
        headers: 'There isn\u2019t a share link for pasted headers. The header block can contain private addresses, and putting it in a URL would publish it. Look up one address from the result if you want a link to send.',
        bulk: 'There isn\u2019t a share link for a list of addresses. A link would have to include the whole list. Open one address and share that result.'
    };

    var LINK_SVG = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>';

    function esc(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

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
        if (!value || value.length > 45 || value.indexOf(':') === -1) return false;
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

    function isIP(value) {
        return isIPv4(value) || isIPv6(value);
    }

    function normalizeDomain(raw) {
        var value = String(raw == null ? '' : raw).trim().replace(/\.$/, '').toLowerCase();
        if (!value || value.length > 253) return '';
        if (!/^[a-z0-9._-]+$/.test(value)) return '';
        if (value.indexOf('..') !== -1) return '';
        if (!/[a-z]/.test(value)) return '';
        var labels = value.split('.');
        if (labels.length < 2) return '';
        if (labels[labels.length - 1].length < 2) return '';
        for (var i = 0; i < labels.length; i++) {
            var label = labels[i];
            if (!label || label.length > 63) return '';
            if (!/^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$/.test(label)) return '';
        }
        return value;
    }

    function normalizeIP(raw) {
        var value = String(raw == null ? '' : raw).trim();
        if (isIPv4(value)) return value;
        if (isIPv6(value)) return value.toLowerCase();
        return '';
    }

    function normalizeAsn(raw) {
        var value = String(raw == null ? '' : raw).trim();
        var match = value.match(/^(?:AS)?(\d{1,10})$/i);
        if (!match) return '';
        if (match[1].length > 1 && match[1].charAt(0) === '0') return '';
        var n = Number(match[1]);
        if (!isFinite(n) || n < 1 || n > 4294967295) return '';
        return 'AS' + match[1];
    }

    function normalizeCidr(raw) {
        var value = String(raw == null ? '' : raw).trim();
        var match = value.match(/^(.+)\/(\d{1,3})$/);
        if (!match) return '';
        var bits = Number(match[2]);
        if (!isFinite(bits) || String(bits) !== String(Number(match[2]))) return '';
        var ip = normalizeIP(match[1]);
        if (!ip) return '';
        if (ip.indexOf(':') === -1 && bits >= 0 && bits <= 32) return ip + '/' + bits;
        if (ip.indexOf(':') !== -1 && bits >= 0 && bits <= 128) return ip + '/' + bits;
        return '';
    }

    function normalizeEmail(raw) {
        var value = String(raw == null ? '' : raw).trim();
        if (value.length < 3 || value.length > 254) return '';
        if (!/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) return '';
        return value;
    }

    function normalizeSelector(raw) {
        var value = String(raw == null ? '' : raw).trim();
        if (!value) return '';
        if (value.length > 63) return '';
        if (!/^[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?$/i.test(value)) return '';
        if (value.indexOf('..') !== -1) return '';
        return value;
    }

    function normalizeUrl(raw) {
        var value = String(raw == null ? '' : raw).trim();
        if (!value || value.length > 500) return '';
        if (/[\u0000-\u001f\s<>"'\\]/.test(value)) return '';
        if (/^https?:\/\//i.test(value)) {
            try {
                var parsed = new URL(value);
                if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
                if (parsed.username || parsed.password) return '';
                var host = parsed.hostname.replace(/^\[|\]$/g, '');
                if (!normalizeIP(host) && !normalizeDomain(host)) return '';
                return value;
            } catch (e) {
                return '';
            }
        }
        var slash = value.indexOf('/');
        var hostPart = slash === -1 ? value : value.slice(0, slash);
        var rest = slash === -1 ? '' : value.slice(slash);
        if (rest && !/^[a-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$/i.test(rest)) return '';
        var host = normalizeDomain(hostPart) || normalizeIP(hostPart);
        if (!host) return '';
        return slash === -1 ? host : host + rest;
    }

    function normalizeWhois(raw) {
        return normalizeIP(raw) || normalizeCidr(raw) || normalizeDomain(raw);
    }

    function normalize(tab, raw) {
        if (tab === 'ip') return normalizeIP(raw) || normalizeDomain(raw);
        if (tab === 'bl' || tab === 'tools') return normalizeIP(raw);
        if (tab === 'dns' || tab === 'dmarc') return normalizeDomain(raw);
        if (tab === 'asn') return normalizeAsn(raw);
        if (tab === 'whois') return normalizeWhois(raw);
        if (tab === 'urlcheck') return normalizeUrl(raw);
        if (tab === 'emailcheck') return normalizeEmail(raw) || normalizeDomain(raw);
        return '';
    }

    function normalizeEmbed(kind, raw) {
        if (kind === 'ip' || kind === 'blacklist') return normalizeIP(raw);
        if (kind === 'dns' || kind === 'dmarc') return normalizeDomain(raw);
        if (kind === 'asn') return normalizeAsn(raw);
        return '';
    }

    function normalizeHero(raw) {
        var value = String(raw == null ? '' : raw).trim();
        if (!value || /\s/.test(value)) return '';
        return normalizeIP(value) || normalizeAsn(value) || normalizeCidr(value) || normalizeEmail(value) || normalizeUrl(value) || normalizeDomain(value);
    }

    function homepageQuery(tab, raw) {
        var value = normalize(tab, raw);
        if (!value || !/^(ip|dns|bl|asn|whois|tools|urlcheck|emailcheck)$/.test(tab)) return '';
        var params = new URLSearchParams();
        params.set('tab', tab);
        if (tab === 'ip' || tab === 'bl' || tab === 'tools') params.set('ip', value);
        else if (tab === 'asn') params.set('asn', value);
        else params.set('q', value);
        if (tab === 'ip' || tab === 'asn') params.set('full', '1');
        return '/?' + params.toString();
    }

    function cleanPath(pathname) {
        var path = String(pathname || '/');
        if (path.endsWith('/index.html')) path = path.slice(0, -10);
        if (!path) path = '/';
        if (path.length > 1 && path.charAt(path.length - 1) !== '/') path += '/';
        return path;
    }

    function embedQuery(kind, raw, pathname) {
        var value = normalizeEmbed(kind, raw);
        var slug = SLUGS[kind];
        if (!value || !slug) return '';
        var path = cleanPath(pathname);
        if (kind === 'ip' && path === '/ip/' + value + '/') return path;
        if (kind === 'asn' && path.toLowerCase() === '/asn/' + value.toLowerCase() + '/') return '/asn/' + value + '/';
        return '/tools/' + slug + '/?q=' + encodeURIComponent(value);
    }

    function readTabValue(params, tab) {
        if (!params || !tab) return '';
        if (tab === 'ip' || tab === 'bl' || tab === 'tools') return params.get('ip') || params.get('q') || '';
        if (tab === 'asn') return params.get('asn') || params.get('q') || '';
        if (tab === 'whois') return params.get('q') || params.get('ip') || '';
        if (tab === 'dns' || tab === 'urlcheck' || tab === 'emailcheck') return params.get('q') || '';
        return '';
    }

    function canonicalFor(tab, raw, index) {
        var value = normalize(tab, raw);
        if (!value || !index) return '';
        if (tab === 'ip' && isIP(value) && index.ips && index.ips[value]) return '/ip/' + value + '/';
        if (tab === 'asn' && index.asns && index.asns[value]) return '/asn/' + value + '/';
        return '';
    }

    function embedCanonical(kind, raw, index) {
        var value = normalizeEmbed(kind, raw);
        if (!value || !index) return '';
        if (kind === 'ip' && index.ips && index.ips[value]) return '/ip/' + value + '/';
        if (kind === 'asn' && index.asns && index.asns[value]) return '/asn/' + value + '/';
        return '';
    }

    function absolute(path, origin) {
        if (!path) return '';
        var base = origin;
        if (!base && typeof location !== 'undefined') base = location.origin;
        if (!base) return path;
        return new URL(path, base).href;
    }

    function canWebShare() {
        return typeof navigator !== 'undefined' && typeof navigator.share === 'function';
    }

    function actionButtons(url) {
        if (!url) return '';
        var safe = esc(url);
        var share = canWebShare()
            ? '<button type="button" class="action-btn" data-web-share="' + safe + '">Share</button>'
            : '';
        return '<button type="button" class="action-btn" data-share="' + safe + '">' + LINK_SVG + '<span data-share-label>Copy link</span></button>' + share;
    }

    function barHtml(url) {
        var buttons = actionButtons(url);
        if (!buttons) return '';
        return '<div class="action-bar share-bar fade-in">' + buttons + '</div>';
    }

    function unavailableNote(kind) {
        return NOTES[kind] || '';
    }

    function mailAuthHash(domain, selector, authoritative) {
        var host = normalizeDomain(domain);
        if (!host) return '';
        if (selector && !normalizeSelector(selector)) return '';
        var parts = ['domain=' + encodeURIComponent(host)];
        var sel = normalizeSelector(selector);
        if (sel) parts.push('selector=' + encodeURIComponent(sel));
        if (authoritative) parts.push('authoritative=1');
        return '#' + parts.join('&');
    }

    function readMailAuthHash(hash) {
        var raw = String(hash || '').replace(/^#/, '');
        if (!raw) return null;
        var params;
        try { params = new URLSearchParams(raw); } catch (e) { return null; }
        var domain = normalizeDomain(params.get('domain') || '');
        if (!domain) return null;
        var selRaw = params.get('selector') || '';
        var selector = selRaw ? normalizeSelector(selRaw) : '';
        if (selRaw && !selector) return null;
        return { domain: domain, selector: selector, authoritative: params.get('authoritative') === '1' };
    }

    function ensureNoindex(doc) {
        var documentRef = doc || (typeof document !== 'undefined' ? document : null);
        if (!documentRef || !documentRef.head) return;
        var robots = documentRef.querySelector('meta[name="robots"]');
        if (!robots) {
            robots = documentRef.createElement('meta');
            robots.setAttribute('name', 'robots');
            documentRef.head.appendChild(robots);
        }
        robots.setAttribute('content', 'noindex, follow');
    }

    function clearNoindex(doc) {
        var documentRef = doc || (typeof document !== 'undefined' ? document : null);
        if (!documentRef) return;
        var robots = documentRef.querySelector('meta[name="robots"]');
        if (robots && robots.getAttribute('content') === 'noindex, follow') robots.parentNode.removeChild(robots);
    }

    function setCanonical(path, doc, origin) {
        var documentRef = doc || (typeof document !== 'undefined' ? document : null);
        if (!documentRef || !path) return;
        var abs = absolute(path, origin || (typeof location !== 'undefined' ? location.origin : ''));
        var link = documentRef.querySelector('link[rel="canonical"]');
        if (link) link.setAttribute('href', abs);
        var og = documentRef.querySelector('meta[property="og:url"]');
        if (og) og.setAttribute('content', abs);
    }

    function applyMeta(sharePath, canonicalPath, doc) {
        if (!sharePath || sharePath.indexOf('?') === -1) {
            clearNoindex(doc);
            return;
        }
        ensureNoindex(doc);
        if (canonicalPath) setCanonical(canonicalPath, doc);
    }

    function flash(btn, text) {
        if (!btn) return;
        var label = btn.querySelector('[data-share-label]');
        var target = label || btn;
        if (!btn.getAttribute('data-label')) btn.setAttribute('data-label', target.textContent);
        target.textContent = text;
        btn.classList.add('is-copied');
        setTimeout(function () {
            target.textContent = btn.getAttribute('data-label') || 'Copy link';
            btn.classList.remove('is-copied');
        }, 2000);
    }

    function fallbackCopy(url, done) {
        var ta = document.createElement('textarea');
        ta.value = url;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        try {
            document.execCommand('copy');
            done();
        } catch (e) {}
        document.body.removeChild(ta);
    }

    function copyUrl(url, btn) {
        if (!url) return;
        var done = function () {
            flash(btn, 'Copied');
            if (typeof root.showToast === 'function') root.showToast('Link copied');
        };
        if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(url).then(done).catch(function () { fallbackCopy(url, done); });
            return;
        }
        fallbackCopy(url, done);
    }

    function webShare(url, btn) {
        if (!url) return;
        if (!canWebShare()) {
            copyUrl(url, btn);
            return;
        }
        navigator.share({ title: (typeof document !== 'undefined' && document.title) || 'ignixip', url: url }).then(function () {
            flash(btn, 'Shared');
        }).catch(function (err) {
            if (err && err.name === 'AbortError') return;
            copyUrl(url, btn);
        });
    }

    function bindClicks(doc) {
        var documentRef = doc || (typeof document !== 'undefined' ? document : null);
        if (!documentRef || documentRef.__ignixShareBound) return;
        documentRef.__ignixShareBound = true;
        documentRef.addEventListener('click', function (event) {
            var target = event.target && event.target.closest ? event.target.closest('[data-share], [data-web-share]') : null;
            if (!target) return;
            event.preventDefault();
            if (target.hasAttribute('data-web-share')) webShare(target.getAttribute('data-web-share'), target);
            else copyUrl(target.getAttribute('data-share'), target);
        });
    }

    var api = {
        NOTES: NOTES,
        isIPv4: isIPv4,
        isIPv6: isIPv6,
        normalize: normalize,
        normalizeEmbed: normalizeEmbed,
        normalizeHero: normalizeHero,
        normalizeDomain: normalizeDomain,
        normalizeSelector: normalizeSelector,
        homepageQuery: homepageQuery,
        embedQuery: embedQuery,
        readTabValue: readTabValue,
        canonicalFor: canonicalFor,
        embedCanonical: embedCanonical,
        absolute: absolute,
        actionButtons: actionButtons,
        barHtml: barHtml,
        unavailableNote: unavailableNote,
        mailAuthHash: mailAuthHash,
        readMailAuthHash: readMailAuthHash,
        ensureNoindex: ensureNoindex,
        clearNoindex: clearNoindex,
        applyMeta: applyMeta,
        copyUrl: copyUrl,
        bindClicks: bindClicks
    };

    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (root) {
        root.ignixShare = api;
        if (root.document) bindClicks(root.document);
    }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
