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

            if (resp.headers["set-cookie"]) {
                _cookieJar.setCookies(resp.headers["set-cookie"], hostname, path);
            }

            success(resp);
        });

        req.on('error', (e) => {
            failure(e);
        });

        req.write(postData);
        req.end();
    }

    this.get = function (hostname, path, success, failure) {

        log('GET', hostname, path);

        let cookies = _cookieJar.getCookies(new cookiejar.CookieAccessInfo(hostname, path, true, false));

        log('cookies: ' + cookies.toString());

        let options = {
            hostname: hostname,
            path: path,
            headers: {
                'Accept-Encoding': 'gzip',
                'Cookie': cookies.toValueString()
            }
        };

        https.get(options, (resp) => {

            log('statusCode: ' + resp.statusCode);
            log('headers: ' + JSON.stringify(resp.headers));

            if (resp.headers["set-cookie"]) {
                _cookieJar.setCookies(resp.headers["set-cookie"], hostname, path);
            }

            let data = '';

            if (resp.headers["content-encoding"] === "gzip") {

                let gunzip = zlib.createGunzip();

                gunzip.on('data', (chunk) => {
                    data += chunk;
                });

                gunzip.on('end', () => {
                    success(resp, data)
                });

                resp.pipe(gunzip);

            } else {

                resp.on('data', (chunk) => {
                    data += chunk;
                });

                resp.on('end', () => {
                    success(resp, data)
                });
            }

        }).on('error', (e) => {
            failure(e);
        });;
    }
};

var IntranetSession = function (addr, username, password) {

    var _lock = new AsyncLock();
    var _httpsSession = new HttpsSession();

    var handleAPM = function (data, done) {

        xml2js.parseString(data, (err, result) => {

            if (!result) {
                done(true, "Error parsing APM payload");
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
                    done(true, "Unexpected status code: " + resp.statusCode);
                    return;
                }

                handleRedirection(parsed.hostname, resp.headers, done, true);

            }, (err) => {
                done(true, err);
            });
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
                done(true, "Error: failed login attempt");
                return;
            }

            handleRedirection(hostname, resp.headers, done);

        }, (err) => {
            done(true, err);
        });
    };

    var handleRedirection = function (hostname, headers, done, final) {

        if (!headers.location) {
            done(true, "Missing redirect location");
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
                done(true, "Unexpected HTTP status: " + resp.statusCode);
            }
        }, (err) => {
            done(true, err);
        });
    }

    this.setMaxPendingRequests = function (maxPending) {

        _lock.maxPending = maxPending;
    }

    this.get = function (path) {

        return new Promise((resolve, reject) => {

            _lock.acquire('cookie', (done) => {

                _httpsSession.get(addr, path, (resp, data) => {

                    if (resp.statusCode === 200) {
                        done(false, { path: path, statusCode: resp.statusCode, body: data });
                    } else if (resp.statusCode === 302) {
                        handleRedirection(addr, resp.headers, done);
                    } else {
                        done(true, "Unexpected HTTP status: " + resp.statusCode);
                    }

                }, (err) => {
                    done(true, err);
                });

            }, (err, data) => {

                if (!err) {
                    resolve(data);
                } else {
                    reject(data);
                }

            });
        });
    }

    this.logout = function () {

        return this.get('/Shibboleth.sso/Logout');
    }
}

exports.IntranetSession = IntranetSession;
