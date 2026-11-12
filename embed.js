/* Small client lookup used by the pre-generated SEO pages. */
(function () {
    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
    function row(k, v) {
        return '<div class="data-row"><span class="data-key">' + esc(k) + '</span><span class="data-val">' + v + '</span></div>';
    }
    function card(title, inner) {
        return '<div class="result-card"><div class="card-title">' + esc(title) + '</div>' + inner + '</div>';
    }
    function fullLink(tab, value) {
        return '/?tab=' + encodeURIComponent(tab) + '&ip=' + encodeURIComponent(value) + '&full=1';
    }

    function renderIp(box, ip, info, abuse) {
        var org = (info && info.org) || 'Unknown';
        var place = [info && info.city, info && info.region, info && info.country].filter(Boolean).join(', ') || '—';
        var abuseScore = abuse && abuse.data ? (abuse.data.abuseConfidenceScore || 0) : null;
        var html = card('Live lookup', 
            row('Address', esc(ip)) +
            row('Organisation', esc(org)) +
            row('Location', esc(place)) +
            row('Hostname', esc((info && info.hostname) || '—')) +
            row('AbuseIPDB', abuseScore == null ? '—' : esc(abuseScore + '%'))
        );
        html += '<p class="seo-note"><a href="' + fullLink('ip', ip) + '">Open the full ignixip report</a></p>';
        box.innerHTML = html;
    }

    function runIp(root, ip) {
        var box = root.querySelector('[data-results]');
        box.innerHTML = '<div class="loading"><span class="loading-dots">Looking up</span></div>';
        Promise.all([
            fetch('https://tools.ignixip.com/ipinfo/' + encodeURIComponent(ip)).then(function (r) { return r.json(); }).catch(function () { return null; }),
            fetch('https://portal.ignix.co.uk/api/abuseipdb/' + encodeURIComponent(ip)).then(function (r) { return r.json(); }).catch(function () { return null; })
        ]).then(function (pair) {
            if (!pair[0] || pair[0].error) {
                box.innerHTML = '<div class="error-card">Could not look up ' + esc(ip) + '.</div>';
                return;
            }
            renderIp(box, ip, pair[0], pair[1]);
        });
    }

    function runAsn(root, raw) {
        var box = root.querySelector('[data-results]');
        var num = String(raw || '').replace(/^AS/i, '');
        if (!/^\d+$/.test(num)) {
            box.innerHTML = '<div class="error-card">Enter an ASN such as AS15169.</div>';
            return;
        }
        box.innerHTML = '<div class="loading"><span class="loading-dots">Looking up AS' + esc(num) + '</span></div>';
        fetch('https://rdap.org/autnum/' + encodeURIComponent(num))
            .then(function (r) { return r.json(); })
            .then(function (d) {
                var name = (d && d.name) || 'Unknown';
                box.innerHTML = card('Live RDAP', row('ASN', 'AS' + esc(num)) + row('Name', esc(name)) + row('Handle', esc((d && d.handle) || '—'))) +
                    '<p class="seo-note"><a href="/?tab=asn&asn=AS' + encodeURIComponent(num) + '&full=1">Open the full ASN lookup</a></p>';
            })
            .catch(function () {
                box.innerHTML = '<div class="error-card">ASN lookup failed.</div>';
            });
    }

    function runDns(root, name) {
        var box = root.querySelector('[data-results]');
        var host = String(name || '').trim();
        if (!host || /^\d+\.\d+\.\d+\.\d+$/.test(host)) {
            box.innerHTML = '<div class="error-card">Enter a domain name.</div>';
            return;
        }
        box.innerHTML = '<div class="loading"><span class="loading-dots">Querying DNS</span></div>';
        var types = ['A', 'AAAA', 'MX', 'NS', 'TXT'];
        Promise.all(types.map(function (type) {
            return fetch('https://dns.google/resolve?name=' + encodeURIComponent(host) + '&type=' + type)
                .then(function (r) { return r.json(); })
                .then(function (d) { return { type: type, data: d }; })
                .catch(function () { return { type: type, data: null }; });
        })).then(function (rows) {
            var html = '';
            rows.forEach(function (rowSet) {
                var answers = rowSet.data && rowSet.data.Answer ? rowSet.data.Answer : [];
                if (!answers.length) return;
                var inner = answers.slice(0, 8).map(function (a) {
                    return row(rowSet.type, esc(a.data));
                }).join('');
                html += card(rowSet.type, inner);
            });
            var watch = (window.ignixWatch && host) ? window.ignixWatch.cta(host) : '';
            box.innerHTML = (html || '<div class="error-card">No records returned.</div>') +
                '<p class="seo-note"><a href="/?tab=dns&q=' + encodeURIComponent(host) + '&full=1">Open the full DNS lookup</a></p>' +
                watch;
        });
    }

    function runBl(root, ip) {
        var box = root.querySelector('[data-results]');
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
            box.innerHTML = '<div class="error-card">Enter an IPv4 address. Spamhaus is not queried here.</div>';
            return;
        }
        box.innerHTML = '<div class="loading"><span class="loading-dots">Checking lists</span></div>';
        var rev = ip.split('.').reverse().join('.');
        var lists = [
            ['SpamCop', 'bl.spamcop.net'],
            ['Barracuda', 'b.barracudacentral.org'],
            ['UCEPROTECT L1', 'dnsbl-1.uceprotect.net']
        ];
        Promise.all(lists.map(function (item) {
            return fetch('https://dns.google/resolve?name=' + encodeURIComponent(rev + '.' + item[1]) + '&type=A')
                .then(function (r) { return r.json(); })
                .then(function (d) {
                    var code = d.Answer && d.Answer[0] ? d.Answer[0].data : '';
                    var blocked = code.indexOf('127.255.255.') === 0;
                    var listed = !!code && !blocked && code.indexOf('127.') === 0;
                    return item[0] + ': ' + (blocked ? 'not checked' : (listed ? 'listed' : 'not listed'));
                })
                .catch(function () { return item[0] + ': not checked'; });
        })).then(function (lines) {
            fetch('https://portal.ignix.co.uk/api/abuseipdb/' + encodeURIComponent(ip))
                .then(function (r) { return r.json(); })
                .catch(function () { return null; })
                .then(function (abuse) {
                    var score = abuse && abuse.data ? (abuse.data.abuseConfidenceScore || 0) : null;
                    var inner = lines.map(function (line) {
                        var bits = line.split(': ');
                        return row(bits[0], esc(bits[1]));
                    }).join('') + row('AbuseIPDB', score == null ? '—' : esc(score + '%'));
                    box.innerHTML = card('Quick blacklist check', inner) +
                        '<p class="seo-note">Spamhaus is not queried on this page. <a href="' + fullLink('bl', ip) + '">Open the full blacklist check</a>.</p>';
                });
        });
    }

    function boot(el) {
        var kind = el.getAttribute('data-embed');
        var input = el.querySelector('[data-query]');
        var button = el.querySelector('button');
        function go(value) {
            if (kind === 'ip' || kind === 'blacklist') runIpOrBl(kind, el, value);
            else if (kind === 'asn') runAsn(el, value);
            else if (kind === 'dns' || kind === 'dmarc') runDns(el, value);
            else if (kind === 'headers') runHeaders(el, value);
            else if (kind === 'bulk') runBulk(el, value);
        }
        function runIpOrBl(which, root, value) {
            if (which === 'blacklist') runBl(root, value);
            else runIp(root, value);
        }
        if (el.querySelector('form')) {
            el.querySelector('form').addEventListener('submit', function (e) {
                e.preventDefault();
                go(input ? input.value.trim() : '');
            });
        }
        if (el.getAttribute('data-auto') === '1' && input && input.value.trim()) go(input.value.trim());
        if (button && !el.querySelector('form')) button.addEventListener('click', function () { go(input ? input.value.trim() : ''); });
    }

    function runHeaders(root, text) {
        var box = root.querySelector('[data-results]');
        var ips = [];
        var re = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
        var m;
        while ((m = re.exec(text || ''))) {
            if (ips.indexOf(m[0]) === -1) ips.push(m[0]);
            if (ips.length >= 8) break;
        }
        if (!ips.length) {
            box.innerHTML = '<div class="error-card">No IPv4 addresses found in those headers.</div>';
            return;
        }
        box.innerHTML = card('Addresses in the headers', ips.map(function (ip) {
            return row('IP', '<a href="/ip/' + esc(ip) + '/">' + esc(ip) + '</a>');
        }).join('')) + '<p class="seo-note"><a href="/?tab=headers&full=1">Open the full header analyser</a></p>';
    }

    function runBulk(root, text) {
        var box = root.querySelector('[data-results]');
        var ips = [];
        String(text || '').split(/[^0-9.]+/).forEach(function (part) {
            if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(part) && ips.indexOf(part) === -1) ips.push(part);
        });
        ips = ips.slice(0, 5);
        if (!ips.length) {
            box.innerHTML = '<div class="error-card">Paste one or more IPv4 addresses.</div>';
            return;
        }
        box.innerHTML = '<div class="loading"><span class="loading-dots">Looking up</span></div>';
        Promise.all(ips.map(function (ip) {
            return fetch('https://tools.ignixip.com/ipinfo/' + encodeURIComponent(ip))
                .then(function (r) { return r.json(); })
                .then(function (d) { return { ip: ip, org: (d && d.org) || '—' }; })
                .catch(function () { return { ip: ip, org: '—' }; });
        })).then(function (rows) {
            box.innerHTML = card('First addresses', rows.map(function (r) {
                return row(r.ip, '<a href="/ip/' + esc(r.ip) + '/">' + esc(r.org) + '</a>');
            }).join('')) + '<p class="seo-note">This preview checks up to five addresses. <a href="/?tab=bulk&full=1">Open bulk check</a> for up to 25.</p>';
        });
    }

    document.querySelectorAll('[data-embed]').forEach(boot);
})();
