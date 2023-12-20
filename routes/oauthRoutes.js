// routes/oauthRoutes.js
const express = require('express');
const router = express.Router();
const oauthController = require('../controllers/oauthController');



router.post('/signup', oauthController.signup);
router.post('/login', oauthController.login);
router.post('/register-client', oauthController.verifyToken,oauthController.register);
router.get('/code', oauthController.code);
router.post('/exchange', oauthController.exchange);
router.post('/refresh', oauthController.refresh);




module.exports = router;
