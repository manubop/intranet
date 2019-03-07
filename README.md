Intranet Access Module
===
Sample usage:
```javascript
const intranet = require('./intranet.js')

function logResponse (res) {

	console.log(res.path + '[' + res.statusCode + ']');
	console.log(JSON.parse(res.body));
}

var session = new intranet.IntranetSession('some.url.fr', 'username', 'password');

session.get('/some/rest/path').then(logResponse);
```
