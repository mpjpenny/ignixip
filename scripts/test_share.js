#!/usr/bin/env node
'use strict';

var assert = require('assert');
var share = require('../share.js');

var index = { ips: { '8.8.8.8': true, '127.0.0.2': false }, asns: { AS15169: true } };
delete index.ips['127.0.0.2'];

assert.strictEqual(share.normalize('ip', ' 8.8.8.8 '), '8.8.8.8');
assert.strictEqual(share.normalize('ip', '127.0.0.2'), '127.0.0.2');
assert.strictEqual(share.normalize('ip', '10.1.2.3'), '10.1.2.3');
assert.strictEqual(share.normalize('ip', '192.168.0.1'), '192.168.0.1');
assert.strictEqual(share.normalize('ip', '172.16.0.1'), '172.16.0.1');
assert.strictEqual(share.normalize('ip', '169.254.1.1'), '169.254.1.1');
assert.strictEqual(share.normalize('ip', '0.0.0.0'), '0.0.0.0');
assert.strictEqual(share.normalize('ip', '255.255.255.255'), '255.255.255.255');
assert.strictEqual(share.normalize('ip', '::1'), '::1');
assert.strictEqual(share.normalize('ip', '2001:DB8::1'), '2001:db8::1');
assert.strictEqual(share.normalize('ip', 'FC00::1'), 'fc00::1');
assert.strictEqual(share.normalize('bl', '127.0.0.2'), '127.0.0.2');
assert.strictEqual(share.normalize('ip', '08.8.8.8'), '');
assert.strictEqual(share.normalize('ip', '256.1.1.1'), '');
assert.strictEqual(share.normalize('ip', '8.8.8.8<script>'), '');
assert.strictEqual(share.normalize('ip', '"><img src=x onerror=alert(1)>'), '');

assert.strictEqual(share.normalize('dns', 'Example.COM.'), 'example.com');
assert.strictEqual(share.normalize('dns', '_dmarc.example.com'), '_dmarc.example.com');
assert.strictEqual(share.normalize('dmarc', 'example.com'), 'example.com');
assert.strictEqual(share.normalize('dns', 'example.com/<script>'), '');
assert.strictEqual(share.normalize('dns', 'not a domain'), '');

assert.strictEqual(share.normalize('asn', 'as15169'), 'AS15169');
assert.strictEqual(share.normalize('asn', '15169'), 'AS15169');
assert.strictEqual(share.normalize('asn', 'AS0'), '');
assert.strictEqual(share.normalize('asn', 'AS4294967296'), '');
assert.strictEqual(share.normalize('asn', 'AS<script>'), '');

assert.strictEqual(share.normalize('whois', '10.0.0.0/8'), '10.0.0.0/8');
assert.strictEqual(share.normalize('whois', '2001:db8::/32'), '2001:db8::/32');
assert.strictEqual(share.normalize('whois', 'example.com'), 'example.com');
assert.strictEqual(share.normalize('emailcheck', 'a@example.com'), 'a@example.com');
assert.strictEqual(share.normalize('emailcheck', 'example.com'), 'example.com');
assert.strictEqual(share.normalize('emailcheck', '"><svg onload=alert(1)>@example.com'), '');
assert.strictEqual(share.normalize('urlcheck', 'https://example.com/path'), 'https://example.com/path');
assert.strictEqual(share.normalize('urlcheck', 'javascript:alert(1)'), '');
assert.strictEqual(share.normalizeHero('  <script>alert(1)</script>  '), '');
assert.strictEqual(share.normalizeHero('8.8.8.8'), '8.8.8.8');

assert.strictEqual(share.homepageQuery('ip', '8.8.8.8'), '/?tab=ip&ip=8.8.8.8&full=1');
assert.strictEqual(share.homepageQuery('bl', '127.0.0.2'), '/?tab=bl&ip=127.0.0.2');
assert.strictEqual(share.homepageQuery('dns', 'Example.COM'), '/?tab=dns&q=example.com');
assert.strictEqual(share.homepageQuery('asn', '15169'), '/?tab=asn&asn=AS15169&full=1');
assert.strictEqual(share.homepageQuery('headers', 'secret headers'), '');
assert.strictEqual(share.homepageQuery('bulk', '8.8.8.8\n1.1.1.1'), '');
assert.strictEqual(share.homepageQuery('ip', '<script>'), '');

var ipParams = new URLSearchParams(share.homepageQuery('ip', '10.0.0.1').slice(2));
assert.strictEqual(share.normalize('ip', share.readTabValue(ipParams, 'ip')), '10.0.0.1');
var dnsParams = new URLSearchParams(share.homepageQuery('dns', 'example.com').slice(2));
assert.strictEqual(share.normalize('dns', share.readTabValue(dnsParams, 'dns')), 'example.com');

assert.strictEqual(share.canonicalFor('ip', '8.8.8.8', index), '/ip/8.8.8.8/');
assert.strictEqual(share.canonicalFor('ip', '127.0.0.2', index), '');
assert.strictEqual(share.canonicalFor('bl', '8.8.8.8', index), '');
assert.strictEqual(share.canonicalFor('asn', 'AS15169', index), '/asn/AS15169/');
assert.strictEqual(share.canonicalFor('dns', 'example.com', index), '');
assert.strictEqual(share.embedCanonical('ip', '8.8.8.8', index), '/ip/8.8.8.8/');
assert.strictEqual(share.embedCanonical('blacklist', '8.8.8.8', index), '');

assert.strictEqual(share.embedQuery('ip', '8.8.8.8', '/ip/8.8.8.8/'), '/ip/8.8.8.8/');
assert.strictEqual(share.embedQuery('ip', '1.1.1.1', '/ip/8.8.8.8/'), '/tools/ip-lookup/?q=1.1.1.1');
assert.strictEqual(share.embedQuery('ip', '127.0.0.2', '/tools/ip-lookup/'), '/tools/ip-lookup/?q=127.0.0.2');
assert.strictEqual(share.embedQuery('blacklist', '127.0.0.2', '/tools/blacklist-check/'), '/tools/blacklist-check/?q=127.0.0.2');
assert.strictEqual(share.embedQuery('dns', 'example.com', '/tools/dns-lookup/'), '/tools/dns-lookup/?q=example.com');
assert.strictEqual(share.embedQuery('asn', 'AS15169', '/asn/AS15169/'), '/asn/AS15169/');
assert.strictEqual(share.embedQuery('headers', 'Received: from x', '/tools/header-analyzer/'), '');
assert.strictEqual(share.embedQuery('bulk', '8.8.8.8', '/tools/bulk-check/'), '');

assert.strictEqual(share.mailAuthHash('Example.com', 'selector1', true), '#domain=example.com&selector=selector1&authoritative=1');
assert.strictEqual(share.mailAuthHash('example.com', '<script>', false), '');
assert.deepStrictEqual(share.readMailAuthHash('#domain=example.com&selector=selector1&authoritative=1'), {
    domain: 'example.com',
    selector: 'selector1',
    authoritative: true
});
assert.strictEqual(share.readMailAuthHash('#domain=%3Cscript%3E'), null);
assert.ok(share.barHtml('https://ignixip.com/?tab=ip&ip=8.8.8.8&full=1').indexOf('Copy link') !== -1);
assert.ok(share.barHtml('https://ignixip.com/?tab=ip&ip=8.8.8.8&full=1').indexOf('<script') === -1);
assert.strictEqual(share.barHtml(''), '');
assert.ok(share.unavailableNote('headers').length > 40);
assert.ok(share.unavailableNote('bulk').length > 40);
assert.strictEqual(share.unavailableNote('ip'), '');

var buttons = share.actionButtons('https://ignixip.com/?tab=bl&ip=127.0.0.2');
assert.ok(buttons.indexOf('data-share="https://ignixip.com/?tab=bl&amp;ip=127.0.0.2"') !== -1);

console.log('share tests ok');
