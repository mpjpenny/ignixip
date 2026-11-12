/* "Watch this address" card. Shared by the homepage and domain tools. */
(function (root) {
    'use strict';

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

    function normaliseTarget(raw) {
        var value = String(raw == null ? '' : raw).trim().replace(/\.$/, '');
        if (isIPv4(value)) return value;
        if (isIPv6(value)) return value.toLowerCase();
        if (isDomain(value)) return value.toLowerCase();
        return '';
    }

    function kindsFor(target) {
        var value = normaliseTarget(target);
        if (!value) return [];
        if (isIPv4(value) || isIPv6(value)) return ['blacklist'];
        return ['dns', 'blacklist'];
    }

    function esc(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function cta(target) {
        var value = normaliseTarget(target);
        var kinds = kindsFor(value);
        if (!value || !kinds.length) return '';
        var detail = kinds.indexOf('dns') === -1
            ? 'Free email when ' + esc(value) + ' is listed or delisted on a public blacklist. We only write when something changes, after you confirm.'
            : 'Free email when the SPF, DMARC, DKIM or MX records for ' + esc(value) + ' change, or when it is listed or delisted on a public blacklist. We only write when something changes, after you confirm.';
        var href = '/watch/?target=' + encodeURIComponent(value) + '&kinds=' + encodeURIComponent(kinds.join(','));
        return '<aside class="watch-cta">' +
            '<div>' +
            '<p class="watch-kicker">Free email alert</p>' +
            '<h2>Watch this address</h2>' +
            '<p>' + detail + '</p>' +
            '</div>' +
            '<a class="ix-btn pri" href="' + esc(href) + '">Watch ' + esc(value) + '</a>' +
            '</aside>';
    }

    var api = {
        normaliseTarget: normaliseTarget,
        isWatchable: function (target) { return !!normaliseTarget(target); },
        kindsFor: kindsFor,
        cta: cta
    };

    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (root) root.ignixWatch = api;
})(typeof window !== 'undefined' ? window : null);
