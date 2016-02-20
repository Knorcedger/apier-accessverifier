// var nconf = require('nconf');
var responseBuilder = require('apier-responsebuilder');
var reqlog = require('reqlog');

var access;
var keys;
var verifyOrigin;

// utility function that verifies that access configuration exists
exports.init = function(config) {
	var hasConfiguration = true;
	access = config.get('access');
	if (access === null || typeof access !== 'object') {
		hasConfiguration = false;
	} else {
		verifyOrigin = access.verifyOrigin;
		keys = access.apikeys;
		if (!keys) {
			hasConfiguration = false;
		}
	}

	if (hasConfiguration) {
		reqlog.info('accessVerifier', 'Configuration found!');
	} else {
		reqlog.error('accessVerifier',
			'No access configuration! No verification will be done!');
	}
};

exports.verify = function(req, res, next) {
	if (!req.requestData || !req.requestData.secret) {
		responseBuilder.error(req, res, 'NO_APIKEY');
	} else {
		var found = false;
		var i;
		var length;

		if (verifyOrigin) {
			for (i = 0, length = keys.length; i < length; i++) {
				if (req.requestData.secret.toString() === keys[i].key &&
				req.headers.origin === keys[i].origin ||
				req.requestData.secret.toString() === keys[i].key) {
					found = true;
					reqlog.info('accessVerifier', 'success');
					next();
					break;
				}
			}
		} else {
			// we still use an array for the keys to maybe add key title etc
			for (i = 0, length = keys.length; i < length; i++) {
				if (req.requestData.secret.toString() === keys[i].key) {
					found = true;
					reqlog.info('accessVerifier', 'success');
					next();
					break;
				}
			}
		}

		if (!found) {
			responseBuilder.error(req, res, 'INVALID_APIKEY');
		}
	}
};
