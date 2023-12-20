// controllers/oauthController.js
const Client = require('../models/client');
const jwt = require('jsonwebtoken'); // For generating JWT tokens
const config = require('../config/config');
const bcrypt = require('bcrypt'); // For password hashing
const crypto = require('crypto');
const User = require('../models/user');
const Token = require('../models/token');
const url = require('url'); // For URL parsing





exports.signup=  async(req, res) => {
  try {
     
    const { email, password, profilePicture } = req.body;

    // Check if the email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already in use' });
    }
  const hashedPassword = await bcrypt.hash(password, 10);
  // Create a new user
  const newUser = new User({
    email,
    password: hashedPassword,
    profilePicture,
  });
    await newUser.save();
    res.status(201).json({ message: 'User created successfully' });
    console.log('added');
  } catch (error) {
    console.error('Error while signing up:', error);
    res.status(500).json({ message: 'Error signing up' });
  }
};




exports.login = async(req, res) => {

      const { email, password, profilePicture } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Generate a JWT token for authentication
    const token = jwt.sign({ userId: user._id }, config.jsonsecret, {
      expiresIn: '1h', 
    });
     console.log('logged in');
    res.status(200).json({ token, userId: user._id });
    //  add to auth header
    
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};




exports.verifyToken = (req, res, next) => {
  const { loginToken } = req.body;

  try {
    const decodedToken = jwt.verify(loginToken, config.jsonsecret);
    res.locals.user_id = decodedToken.userId;
    next();
  } catch (error) {
    console.error(error);
    res.status(401).json({ message: 'Invalid login token' });
  }
};




exports.register = async(req, res) => {//res.locals.user-id
  //const {loginToken} = req.body;
 // const decodedToken = jwt.verify(loginToken, config.jsonsecret); //remove

  const { user_id } = res.locals;
    try {
  

    const clientId = crypto.randomBytes(16).toString('hex'); 
     const clientSecret = crypto.randomBytes(32).toString('hex'); 

     const newClient = new Client({
      clientId: clientId,
      clientSecret: clientSecret,
      user_id:user_id,
      redirect_uri:config.redirect, 
    });

     await newClient.save()
     .then((result)=>{console.log('added');
  })
     .catch((err)=>{console.log(err);});

    res.status(401).json({ message: newClient})

  } catch (error) {
    console.error(error);
    res.status(401).json({ message: 'Invalid login token' });
  }
};








exports.code = (req, res) => {
  try {
    const parsedRedirectUri = url.parse(req.url, true);
    const clientId = parsedRedirectUri.query.client_id;
    const redirectUri = parsedRedirectUri.query.redirect_uri;
    const userId = parsedRedirectUri.query.user_id;

    const authorizationCode = jwt.sign({
      client_id: clientId,
      redirect_uri: redirectUri,
      user_id: userId,
    }, config.jsonsecret,{ expiresIn: '1h' });// la durée =1 min 
    return res.status(200).json({
      code: authorizationCode,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};







exports.exchange = async (req, res) => {
  const { client_id, user_id, client_secret, code, grant_type } = req.body;
  try {
    const client = await Client.findOne({ client_id, client_secret });
      if (client) {
      return res.status(401).json({ error: 'Unauthorized client' });
    }
    if (grant_type !== 'authorization_code') {
      return res.status(400).json({ error: 'Invalid grant_type' });
    }
    try {
      // Verify the JWT token
      const decodedToken = jwt.verify(code, config.jsonsecret);
      // Check if the decoded information matches the expected values

      if (
        decodedToken.client_id !== client_id ||
        decodedToken.user_id !== user_id
      ) {
        return res.status(400).json({ error: 'Invalid code' });
      }
      const accessToken = jwt.sign({ user_id: user_id }, config.jsonsecret, {
        expiresIn: '1h',
      });// client id +scope +
      const refreshToken = jwt.sign({ user_id: user_id }, config.jsonsecret, {
        expiresIn: '7d', // Set the expiration for the refresh token, e.g., 7 days
      });
      const newTokenEntry = new Token({
        access_token: accessToken,
        refresh_token: refreshToken,
        user:user_id,
      });
      await newTokenEntry.save();

     
      return res.status(200).json({
        access_token: accessToken,
        refresh_token: refreshToken,
        token_type: 'bearer',
        expires_in: 3600, // Expires in 1 hour (in seconds)
      });
    } catch (jwtError) {
      console.error(jwtError);
      return res.status(400).json({ error: 'Invalid code' });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};









// Refresh endpoint
exports.refresh = async (req, res) => {
  const { refresh_token ,user_id} = req.body;
  try {
    // Verify the refresh token
    const decodedToken = jwt.verify(refresh_token, config.jsonsecret);
    // Check if the decoded token contains a user ID
    if (decodedToken.user_id!=user_id) {
      return res.status(400).json({ error: 'Invalid refresh token' });
    }
    // Generate a new access token
    const newAccessToken = jwt.sign(
      { user_id: decodedToken.user_id },
      config.jsonsecret,
      { expiresIn: '1h' }
    );

    const updatedToken = await Token.findOneAndUpdate(
      { user: user_id },
      { access_token: newAccessToken },
      { new: true } // Return the updated document
    );

    if (!updatedToken) {
      return res.status(500).json({ error: 'Failed to update access token' });
    }

    return res.status(200).json({
      access_token: newAccessToken,
      token_type: 'bearer',
      expires_in: 3600, // Expires in 1 hour (in seconds)
    });
  } catch (jwtError) {
    console.error(jwtError);
    return res.status(400).json({ error: 'Invalid refresh token' });
  }
};




