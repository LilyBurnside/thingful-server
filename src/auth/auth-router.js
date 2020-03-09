'use strict';
const express = require('express');
const AuthService = require('./auth-service');

const authRouter = express.Router();
const jsonBodyParser = express.json();

authRouter
  .route('/login')
  .post(jsonBodyParser, async (req, res, next) => {
    console.log('start!')
    const reqFields = ['user_name', 'password'];
    for(const field of reqFields) {
      if (!(field in req.body)) {
        return res.status(400).json({ error: `Missing '${field}' in request body`})
      }
    }
    try{
      const user = await AuthService.getUserWithUserName(
        req.app.get('db'),
        req.body.user_name
      );

      if(!user) {
        return res.status(401).json({ error: 'Invalid credentials' })
      }
    
      const isMatch = await AuthService.comparePasswords(
        req.body.password,
        user.password
      );
      if (!isMatch) {
        return res.status(401).json({ error: 'Invalid credentials' })
      }

      const sub = user.user_name
      const payload = { user_id: user.id }
      const token = await AuthService.createJwt(sub, payload);
      res.json({ token });
    } catch(e) {
      res.status(500).send({ error: 'some error occured' })
    }
  });

module.exports = authRouter;