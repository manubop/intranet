const https = require('https');
const url = require('url');
const querystring = require('querystring');
const xml2js = require('xml2js');
const AsyncLock = require('async-lock');
const cookiejar = require('cookiejar');
const zlib = require('zlib');

const debug = require('debug');
const log = debug('intranet');

var getRedirection = function (hostname, location) {

    let parsed = url.parse(location);

    if (parsed.hostname) {

        return {
            hostname: parsed.hostname,
            path: parsed.path
        }
    }

    return {
        hostname: hostname,
        path: location
    }
}

var HttpsSession = function () {

    var _cookieJar = new cookiejar.CookieJar();

    this.post = function (hostname, path, postData, success, failure) {

        log('POST', hostname, path);

        if (typeof postData !== 'string') {
            postData = querystring.stringify(postData);
        }

        log('postData: ' + postData);

        let cookies = _cookieJar.getCookies(new cookiejar.CookieAccessInfo(hostname, path, true, false));

        log('cookies: ' + cookies.toString());

        let options = {
            hostname: hostname,
            path: path,
            method: 'POST',
            headers: {
                'Accept-Encoding': 'gzip, deflate, br',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': postData.length,
                'Cookie': cookies.toValueString()
            }
        };

        let req = https.request(options, (resp) => {

            log('statusCode: ' + resp.statusCode);
            log('headers: ' + JSON.stringify(resp.headers));

            if (resp.headers['set-cookie']) {
                _cookieJar.setCookies(resp.headers['set-cookie'], hostname, path);
            }

            success(resp);
        });

        req.on('error', failure);

        req.write(postData);
        req.end();
    }

    var getResponseStream = function (resp) {

        const encoding = resp.headers['content-encoding'];

        let dec;

        if (encoding === 'gzip') {

            dec = zlib.createGunzip();

        } else if (encoding === 'deflate') {

            dec = zlib.createInflate();
        
        } else if (encoding === 'br') {

            dec = zlib.createBrotliDecompress();
        }

        if (dec) {

            resp.pipe(dec);

            return dec;
        }

        return resp;
    }

    this.get = function (hostname, path, success, failure) {

        log('GET', hostname, path);

        let cookies = _cookieJar.getCookies(new cookiejar.CookieAccessInfo(hostname, path, true, false));

        log('cookies: ' + cookies.toString());

        let options = {
            hostname: hostname,
            path: path,
            headers: {
                'Accept-Encoding': 'gzip, deflate, br',
                'Cookie': cookies.toValueString()
            }
        };

        https.get(options, (resp) => {

            log('statusCode: ' + resp.statusCode);
            log('headers: ' + JSON.stringify(resp.headers));

            if (resp.headers['set-cookie']) {
                _cookieJar.setCookies(resp.headers['set-cookie'], hostname, path);
            }

            let stream = getResponseStream(resp);
            let data = '';

            stream.on('data', (chunk) => {
                data += chunk;
            });

            stream.on('end', () => {
                success(resp, data);
            });

        }).on('error', failure);
    }
};

var IntranetSession = function (addr, username, password) {

    var _lock = new AsyncLock();
    var _httpsSession = new HttpsSession();

    var handleAPM = function (data, done) {

        xml2js.parseString(data, (err, result) => {

            if (!result) {
                done(new Error('could not parse APM payload'));
                return;
            }

            let form = result.html.apm_do_not_touch[0].body[0].form[0];
            let parsed = url.parse(form['$'].action);
            let postData = {};

            form.input.forEach(formInput => {
                postData[formInput['$'].name] = formInput['$'].value;
            });

            _httpsSession.post(parsed.hostname, parsed.path, postData, (resp) => {

                if (resp.statusCode !== 302) {
                    done(new Error(`unexpected status code ${resp.statusCode} fetching ${parsed.path}`));
                    return;
                }

                handleRedirection(parsed.hostname, resp.headers, done, true);

            }, done);
        });
    };

    var handleLogin = function (hostname, path, done) {

        let postData = {
            username,
            password,
            vhost: 'standard'
        };

        // credentials
        _httpsSession.post(hostname, path, postData, (resp) => {

            if (resp.statusCode !== 302) {
                done(new Error('failed login attempt'));
                return;
            }

            handleRedirection(hostname, resp.headers, done);

        }, done);
    };

    var handleRedirection = function (hostname, headers, done, final) {

        if (!headers.location) {
            done(new Error('missing redirect location'));
            return;
        }

        let redirect = getRedirection(hostname, headers.location);

        log('redirecting to: ' + redirect.hostname + redirect.path);

        _httpsSession.get(redirect.hostname, redirect.path, (resp, data) => {
            if (resp.statusCode === 200) {
                if (final) {
                    done(false, { path: redirect.path, statusCode: resp.statusCode, body: data });
                } else if (redirect.path === '/my.policy') {
                    handleLogin(redirect.hostname, redirect.path, done);
                } else {
                    // token refresh or logout
                    handleAPM(data, done);
                }
            } else if (resp.statusCode === 302) {
                handleRedirection(redirect.hostname, resp.headers, done, final);
            } else {
                done(new Error(`unexpected HTTP status ${resp.statusCode} fetching ${redirect.path}`));
            }
        }, done);
    }

    this.setMaxPendingRequests = function (maxPending) {

        _lock.maxPending = maxPending;
    }

    this.get = function (path) {

        return _lock.acquire('cookie', (done) => {

            _httpsSession.get(addr, path, (resp, data) => {

                if (resp.statusCode === 200) {
                    done(false, { path: path, statusCode: resp.statusCode, body: data });
                } else if (resp.statusCode === 302) {
                    handleRedirection(addr, resp.headers, done);
                } else {
                    done(new Error(`unexpected HTTP status ${resp.statusCode} fetching ${path}`));
                }

            }, done);
        });
    }

    this.logout = function () {

        return this.get('/Shibboleth.sso/Logout');
    }
}

exports.IntranetSession = IntranetSession;
