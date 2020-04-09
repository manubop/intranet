const https = require('https');
const url = require('url');
const querystring = require('querystring');
const xml2js = require('xml2js'); 
const AsyncLock = require('async-lock');
const cookiejar = require('cookiejar');

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
                //'Accept-Encoding': 'gzip, deflate, br',
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
                //'Accept-Encoding': 'gzip, deflate, br',
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
    
            resp.on('data', (chunk) => {
                data += chunk;
            });
    
            resp.on('end', () => {
                success(resp, data)
            });
    
        }).on('error', (e) => {
            failure(e);
        });;
    }    
};

var IntranetSession = function (addr, username, password) {

    var _lock = new AsyncLock();
    var _httpsSession = new HttpsSession();

    var handleFinal = function (hostname, path, done) {

        _httpsSession.get(hostname, path, (resp, data) => {                
            if (resp.statusCode === 302 && resp.headers.location) {
                let redirect = getRedirection(hostname, resp.headers.location);
                return _httpsSession.get(redirect.hostname, redirect.path, (resp, data) => {
                    done(false, { path: redirect.path, statusCode: resp.statusCode, body: data });
                }, (err) => {
                    done(true, err);
                })
            }
            done(false, { path: path, statusCode: resp.statusCode, body: data });
        }, (err) => {
            done(true, err);
        });
    };

    var processAPM = function (data, done) {

        xml2js.parseString(data, (err, result) => {

            if (!result) {
                done(true);
                return;
            }

            let form = result.html.apm_do_not_touch[0].body[0].form[0];
            let parsed = url.parse(form['$'].action);
            let postData = {};

            form.input.forEach(formInput => {
                postData[formInput['$'].name] = formInput['$'].value;
            });

            _httpsSession.post(parsed.hostname, parsed.path, postData, (resp) => {

                if (resp.statusCode !== 302 || !resp.headers.location) {
                    done(true);
                    return;
                }
    
                let redirect = getRedirection(parsed.hostname, resp.headers.location);
    
                log('redirecting to: ' + redirect.hostname + redirect.path);
    
                handleFinal(redirect.hostname, redirect.path, done);
    
            }, (err) => {
                done(true, err);
            });
        });
    };

    var handleLogin = function (hostname, path, done) {

        let postData = {
            username: username,
            password: password,
            vhost: 'standard'
        };

        // credentials
        _httpsSession.post(hostname, path, postData, (resp) => {

            if (resp.statusCode !== 302 || !resp.headers.location) {
                done(true, "Error: failed login attempt");
                return;
            }

            handleGetResponse(hostname, resp.headers, done);
    
        }, (err) => {
            done(true, err);
        });
    };

    var handleGetResponse = function (hostname, headers, done) {

        if (!headers.location) {
            done(true);
            return;
        }

        let redirect = getRedirection(hostname, headers.location);

        log('redirecting to: ' + redirect.hostname + redirect.path);

        _httpsSession.get(redirect.hostname, redirect.path, (resp, data) => {
            if (resp.statusCode === 200) {
                if (redirect.path === '/my.policy') {
                    handleLogin(redirect.hostname, redirect.path, done);
                } else {
                    // token refresh or logout
                    processAPM(data, done);
                }
            } else if (resp.statusCode === 302) {
                handleGetResponse(redirect.hostname, resp.headers, done);
            } else {
                done(true, "Unexpected HTTP status: " + resp.statusCode);
            }
        }, (err) => {
            done(true, err);
        });
    }

    this.get = function (path) {

        return new Promise((resolve, reject) => {

            _lock.acquire('cookie', (done) => {

                _httpsSession.get(addr, path, (resp, data) => {

                    if (resp.statusCode === 200) {

                        done(false, { path: path, statusCode: resp.statusCode, body: data });

                    } else {

                        handleGetResponse(addr, resp.headers, done);
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

            }, {});
        });
    }

    this.logout = function () {

        return this.get('/Shibboleth.sso/Logout');
    }
}

exports.IntranetSession = IntranetSession;
