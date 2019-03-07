Intranet Access Module
===
Install:
```
npm install git+ssh://git@github.com:manubop/intranet.git
```
Sample usage:
```javascript
const intranet = require('intranet')

function logResponse (res) {

	console.log(res.path + '[' + res.statusCode + ']');
	console.log(JSON.parse(res.body));
}

var session = new intranet.IntranetSession('some.url.fr', 'username', 'password');

session.get('/some/rest/path').then(logResponse);
```
Ref: https://devcentral.f5.com/articles/what-is-big-ip-apm-27240
