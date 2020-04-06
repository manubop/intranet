const https = require('https');
const url = require('url');
const querystring = require('querystring');
const xml2js = require('xml2js'); 
const AsyncLock = require('async-lock');

const debug = require('debug');
const log = debug('intranet');

var getCookieStr = function (cookies) {

    return cookies ? cookies.filter(cookie => !cookie.includes('=deleted')).map(cookie => cookie.split(';')[0]).join('; ') : '';
};

var httpsPost = function (hostname, path, cookies, postData, handler) {

    log('post: ' + hostname + path);
    log('cookies: ' + cookies);

    if (typeof postData !== 'string') {
        postData = querystring.stringify(postData);
    }

    log('postData: ' + postData);

    let options = {
        hostname: hostname,
        path: path,
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': postData.length,
            'Cookie': cookies
        }
    };

    let req = https.request(options, (resp) => {

        log('statusCode: ' + resp.statusCode);
        log(JSON.stringify(resp.headers));

        handler(resp);
    });

    req.on('error', (e) => {
        handler(e);
    });

    req.write(postData);
    req.end();
}

var httpsGet = function (hostname, path, cookies, handler) {

    log('get: ' + hostname + path);
    log('cookies: ' + cookies);

    let options = {
        hostname: hostname,
        path: path,
        headers: { 
            'Cookie': cookies 
        }
    };

    https.get(options, (resp) => {

        log('statusCode: ' + resp.statusCode);
        log(JSON.stringify(resp.headers));

        let data = '';

        resp.on('data', (chunk) => {
            data += chunk;
        });

        resp.on('end', () => {
            if (handler) {
                handler(resp, data)
            }
        });
    });
}

var getRedirection = function (hostname, location) {

    if (location) {

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

    return null;
}

var IntranetSession = function (addr, username, password) {

    var _cookiestr = '';
    var _lock = new AsyncLock();

    var handleLastRedirection = function (hostname, path, postData, done) {

        httpsPost(hostname, path, '', postData, (resp) => {

            if (resp.statusCode !== 302) {
                done(true);
            }

            let redirect = getRedirection(hostname, resp.headers.location);

            if (!redirect) {
                done(true);
            }

            _cookiestr = getCookieStr(resp.headers["set-cookie"]);

            httpsGet(redirect.hostname, redirect.path, _cookiestr, (resp, data) => {
                done(false, { path: redirect.path, statusCode: resp.statusCode, body: data });
            });

        });
    }

    var handleSSO = function (hostname, path, cookiestr, done) {

        httpsGet(hostname, path, cookiestr, (resp, data) => {

            xml2js.parseString(data, (err, result) => {

                if (!result) {
                    done(true);
                }

                let form = result.html.apm_do_not_touch[0].body[0].form[0];
                let parsed = url.parse(form['$'].action);
                let postData = {
                    [form.input[0]['$'].name]: form.input[0]['$'].value,
                    [form.input[1]['$'].name]: form.input[1]['$'].value
                };

                handleLastRedirection(parsed.hostname, parsed.path, postData, done);
            });
        });
    };

    var handleLogin = function (hostname, path, cookiestr, done) {

        let postData = {
            username: username,
            password: password,
            vhost: 'standard'
        };

        httpsPost(hostname, path, cookiestr, postData, (resp) => {          

            if (resp.statusCode !== 200) {
                done(true);
            }           

            let cookiestr = getCookieStr(resp.headers["set-cookie"]);

            httpsPost(hostname, path, cookiestr, postData, (resp) => {

                if (resp.statusCode !== 302) {
                    done(true);
                }

                let redirect = getRedirection(hostname, resp.headers.location);

                if (!redirect) {
                    done(true);
                }

                log('redirecting to: ' + redirect.hostname + redirect.path);

                let cookiestr = getCookieStr(resp.headers["set-cookie"]);

                handleSSO(redirect.hostname, redirect.path, cookiestr, done);
            });
        });
    };

    var handleLogout = function (hostname, path, cookiestr, done) {

        httpsGet(hostname, path, cookiestr, (resp, data) => {
            
            xml2js.parseString(data, (err, result) => {

                if (!result) {
                    done(true);
                }

                let form = result.html.apm_do_not_touch[0].body[0].form[0];
                let postData = {
                    [form.input[0]['$'].name]: form.input[0]['$'].value
                };

                httpsPost(hostname, path, '', postData, (resp) => {
                    done(false, resp);
                });
            });
        });
    }

    var handleGetResponse = function (hostname, headers, done) {

        let redirect = getRedirection(hostname, headers.location);

        if (!redirect) {
            done(true);
        }

        log('redirecting to: ' + redirect.hostname + redirect.path);

        let cookiestr = getCookieStr(headers["set-cookie"]);

        if (redirect.path === '/my.policy') {

            handleLogin(redirect.hostname, redirect.path, cookiestr, done);

        } else if (redirect.path.indexOf('/saml/idp/profile/redirect/sls?SAMLRequest=') === 0) {

            handleLogout(redirect.hostname, redirect.path, cookiestr, done);

        } else {

            httpsGet(redirect.hostname, redirect.path, cookiestr, (resp, data) => {
                handleGetResponse(redirect.hostname, resp.headers, done);
            });
        }
    }

    this.get = function (path) {

        return new Promise((resolve, reject) => {

            _lock.acquire('cookie', (done) => {

                httpsGet(addr, path, _cookiestr, (resp, data) => {

                    if (resp.statusCode === 302) {

                        handleGetResponse(addr, resp.headers, done);

                    } else {

                        done(false, { path: path, statusCode: resp.statusCode, body: data });
                    }
                });
                
            }, (err, data) => {

                if (!err) {
                    resolve(data);
                } else {
                    reject();
                }

            }, {});
        });
    }

    this.logout = function () {

        return this.get('/Shibboleth.sso/Logout');
    }
}

exports.IntranetSession = IntranetSession;
