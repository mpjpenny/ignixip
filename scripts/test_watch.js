#!/usr/bin/env node
'use strict';

var assert = require('assert');
var fs = require('fs');
var path = require('path');
var watch = require('../watch.js');
var cta = require('../watch-cta.js');

assert.deepStrictEqual(watch.classifyTarget('8.8.8.8'), { ok: true, target: '8.8.8.8', type: 'ip' });
assert.deepStrictEqual(watch.classifyTarget(' 2001:DB8::1 '), { ok: true, target: '2001:db8::1', type: 'ip' });
assert.deepStrictEqual(watch.classifyTarget('Example.COM.'), { ok: true, target: 'example.com', type: 'domain' });
assert.strictEqual(watch.classifyTarget('').ok, false);
assert.strictEqual(watch.classifyTarget('256.1.1.1').ok, false);
assert.strictEqual(watch.classifyTarget('08.8.8.8').ok, false);
assert.strictEqual(watch.classifyTarget('AS15169').ok, false);
assert.strictEqual(watch.classifyTarget('10.0.0.0/24').ok, false);
assert.strictEqual(watch.classifyTarget('https://example.com').ok, false);
assert.strictEqual(watch.classifyTarget('user@example.com').ok, false);

assert.deepStrictEqual(watch.defaultKinds('ip'), ['blacklist']);
assert.deepStrictEqual(watch.defaultKinds('domain'), ['dns', 'blacklist']);

var ip = watch.validate({ email: 'a@b.co', target: '8.8.8.8', kinds: ['blacklist', 'dns'], honeypot: '' });
assert.deepStrictEqual(ip.payload, { email: 'a@b.co', target: '8.8.8.8', kinds: ['blacklist', 'dns'] });

var domain = watch.validate({ email: 'a@b.co', target: 'example.com', kinds: ['dns', 'blacklist'], honeypot: '  ' });
assert.deepStrictEqual(domain.payload.kinds, ['blacklist', 'dns']);

var bot = watch.validate({ email: 'a@b.co', target: 'example.com', kinds: ['dns'], honeypot: 'http://spam.test' });
assert.strictEqual(bot.honeypot, true);
assert.strictEqual(bot.payload, undefined);

var bad = watch.validate({ email: 'not-an-email', target: 'nope', kinds: [], honeypot: '' });
assert.strictEqual(bad.ok, false);
assert.ok(bad.errors.email);
assert.ok(bad.errors.target);
assert.ok(bad.errors.kinds);

assert.deepStrictEqual(watch.outcomeFrom(200, { ok: true, message: 'If that address can receive mail, a confirmation is on its way.' }), { state: 'success' });
assert.deepStrictEqual(watch.outcomeFrom(400, { error: 'bad' }), { state: 'invalid' });
assert.deepStrictEqual(watch.outcomeFrom(404, null), { state: 'unavailable' });
assert.deepStrictEqual(watch.outcomeFrom(500, { error: 'boom' }), { state: 'unavailable' });
assert.deepStrictEqual(watch.outcomeFrom(200, { ok: false }), { state: 'unavailable' });
assert.strictEqual(watch.ENDPOINT, 'https://tools.ignixip.com/watch/subscribe');
assert.strictEqual(watch.MESSAGES.successTitle, 'Check your inbox to confirm');
assert.ok(watch.MESSAGES.unavailable.indexOf("aren't available just now") !== -1);

assert.strictEqual(watch.bannerFromSearch(new URLSearchParams('confirmed=1')).title, watch.MESSAGES.confirmedTitle);
assert.strictEqual(watch.bannerFromSearch(new URLSearchParams('unsubscribed=1')).title, watch.MESSAGES.unsubscribedTitle);
assert.strictEqual(watch.bannerFromSearch(new URLSearchParams('error=invalid')).title, watch.MESSAGES.linkTitle);
assert.strictEqual(watch.bannerFromSearch(new URLSearchParams('confirmed=1&error=invalid')).title, watch.MESSAGES.linkTitle);
assert.strictEqual(watch.bannerFromSearch(new URLSearchParams('')), null);

function mockFetch(status, body, fail) {
    return function (url, options) {
        assert.strictEqual(url, watch.ENDPOINT);
        assert.strictEqual(options.method, 'POST');
        assert.strictEqual(options.headers['Content-Type'], 'application/json');
        var sent = JSON.parse(options.body);
        assert.deepStrictEqual(Object.keys(sent).sort(), ['email', 'kinds', 'target']);
        if (fail) return Promise.reject(new Error('offline'));
        return Promise.resolve({
            status: status,
            json: function () { return Promise.resolve(body); }
        });
    };
}

watch.submit({ email: 'a@b.co', target: '8.8.8.8', kinds: ['blacklist'] }, mockFetch(200, { ok: true }))
    .then(function (outcome) {
        assert.deepStrictEqual(outcome, { state: 'success' });
        return watch.submit({ email: 'a@b.co', target: '8.8.8.8', kinds: ['blacklist'] }, mockFetch(400, { error: 'nope' }));
    })
    .then(function (outcome) {
        assert.deepStrictEqual(outcome, { state: 'invalid' });
        return watch.submit({ email: 'a@b.co', target: '8.8.8.8', kinds: ['blacklist'] }, mockFetch(503, null, true));
    })
    .then(function (outcome) {
        assert.deepStrictEqual(outcome, { state: 'unavailable' });
        return watch.submit({ email: 'a@b.co', target: 'example.com', kinds: ['dns', 'blacklist'] }, mockFetch(404, { detail: 'missing' }));
    })
    .then(function (outcome) {
        assert.deepStrictEqual(outcome, { state: 'unavailable' });
    })
    .then(function () {
        assert.strictEqual(cta.isWatchable('AS15169'), false);
        assert.strictEqual(cta.isWatchable('1.1.1.1'), true);
        assert.deepStrictEqual(cta.kindsFor('Example.COM'), ['dns', 'blacklist']);
        assert.deepStrictEqual(cta.kindsFor('1.1.1.1'), ['blacklist']);
        var html = cta.cta('Example.COM');
        assert.ok(html.indexOf('Watch this address') !== -1);
        assert.ok(html.indexOf('example.com') !== -1);
        assert.ok(html.indexOf('kinds=dns%2Cblacklist') !== -1);
        assert.strictEqual(html.toLowerCase().indexOf('spamhaus'), -1);
        assert.strictEqual(cta.cta('AS13335'), '');

        var root = path.join(__dirname, '..');
        var page = fs.readFileSync(path.join(root, 'watch', 'index.html'), 'utf8');
        assert.ok(fs.existsSync(path.join(root, 'watch', 'index.html')));
        assert.ok(page.indexOf('rel="canonical" href="https://ignixip.com/watch/"') !== -1);
        assert.ok(page.indexOf('name="contact_me_by_fax_only"') !== -1);
        assert.ok(page.indexOf('id="privacy"') !== -1);
        assert.ok(page.indexOf('/privacy/#watch') !== -1);
        assert.strictEqual(page.toLowerCase().indexOf('spamhaus'), -1);
        var privacy = fs.readFileSync(path.join(root, 'privacy', 'index.html'), 'utf8');
        assert.ok(privacy.indexOf('id="watch"') !== -1);
        assert.ok(privacy.indexOf("don't sell") !== -1 || privacy.indexOf('don\'t sell') !== -1);
        var sitemap = fs.readFileSync(path.join(root, 'sitemap.xml'), 'utf8');
        assert.ok(sitemap.indexOf('https://ignixip.com/watch/') !== -1);
        assert.ok(sitemap.indexOf('https://ignixip.com/privacy/') !== -1);
        var ipPage = fs.readFileSync(path.join(root, 'ip', '8.8.8.8', 'index.html'), 'utf8');
        assert.ok(ipPage.indexOf('class="watch-cta"') !== -1);
        assert.ok(ipPage.indexOf('kinds=blacklist') !== -1);
        assert.ok(ipPage.indexOf('href="/watch/"') !== -1);
        var asnPage = fs.readFileSync(path.join(root, 'asn', 'AS15169', 'index.html'), 'utf8');
        assert.strictEqual(asnPage.indexOf('class="watch-cta"'), -1);
        assert.ok(asnPage.indexOf('href="/watch/"') !== -1);
        console.log('watch tests ok');
    })
    .catch(function (err) {
        console.error(err);
        process.exit(1);
    });
