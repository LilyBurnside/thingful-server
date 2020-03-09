'use strict';
const knex = require('knex');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const helpers = require('./test-helpers');

describe('Auth Endpoints', function() {
  let db;

  const { testUsers } = helpers.makeThingsFixtures();
  const testUser = testUsers[0];

  before('make knex instance', () => {
    console.log(process.env.TEST_DB_URL);
    db = knex({
      client: 'pg',
      connection: process.env.TEST_DB_URL,
    });
    app.set('db', db);
  });

  after('disconnect from db', () => db.destroy());

  before('cleanup', () => helpers.cleanTables(db));

  afterEach('cleanup', () => helpers.cleanTables(db));

  describe('POST /api/auth/login', () => {
    beforeEach('insert users', () =>
      helpers.seedUsers(
        db,
        testUsers
      )
    );

    const requiredFields = ['user_name', 'password'];

    requiredFields.forEach(field => {
      const loginAttemptBody = {
        user_name: testUser.user_name,
        password: testUser.password,
      };

      it(`responds with 400 required error when '${field}' is missing`, () => {
        delete loginAttemptBody[field];

        return supertest(app)
          .post('/api/auth/login')
          .send(loginAttemptBody)
          .expect(400, {
            error: `Missing '${field}' in request body`,
          });
      });

      it('responds 401 \'invalid user_name or password\' when bad username', () => {
        const invalidUser = { 
          user_name: 'bad-username', 
          password: 'bad-pass'
        };
        return supertest(app)
          .post('/api/auth/login')
          .send(invalidUser)
          .expect(401, { error: 'Invalid credentials'});
      });

      it('responds 401 \'invalid user_name or password\' when bad pass', () => {
        const invalidPass = { 
          user_name: testUser.user_name, 
          password: 'incorrect' 
        };
        return supertest(app)
          .post('/api/auth/login')
          .send(invalidPass)
          .expect(401, { error: 'Invalid credentials'});
      });
    });

    it('responds 200 and JWT auth token using secret when valid credentials', () => {
      const validCreds = {
        user_name: testUser.user_name,
        password: testUser.password
      };
      const expectedToken = jwt.sign(
        { user_id: testUser.id},
        process.env.JWT_SECRET,
        {
          subject: testUser.user_name,
          algorithm: 'HS256',
        }
      );
      return supertest(app)
        .post('/api/auth/login')
        .send(validCreds)
        .expect(200, {
          token: expectedToken,
        });
    });
  });
});