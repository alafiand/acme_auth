const jwt = require("jsonwebtoken");
const secretkey = process.env.JWT;
const bcrypt = require("bcrypt");

const Sequelize = require("sequelize");
const { STRING } = Sequelize;
const config = {
  logging: false,
};

if (process.env.LOGGING) {
  delete config.logging;
}
const conn = new Sequelize(
  process.env.DATABASE_URL || "postgres://localhost/acme_db",
  config
);

const User = conn.define("user", {
  username: STRING,
  password: STRING,
});

User.byToken = async (token) => {
  try {
    console.log("token", token);
    const user = await jwt.verify(token, secretkey);
    if (user) {
      return user;
    }

    const error = Error("bad credentials");
    error.status = 401;
    throw error;
  } catch (ex) {
    const error = Error("bad credentials");
    error.status = 401;
    throw error;
  }
};

User.authenticate = async ({ username, password }) => {

  const user = await User.findOne({
    where: {
      username,
    },
  });
  const token = await jwt.sign({ user: user }, secretkey);

  const isTrue = await bcrypt.compare(password, user.password);

  if (isTrue) {
    return token;
  }
  const error = Error("bad credentials");
  error.status = 401;
  throw error;
};

const syncAndSeed = async () => {
  await conn.sync({ force: true });
  const credentials = [
    { username: "lucy", password: "lucy_pw" },
    { username: "moe", password: "moe_pw" },
    { username: "larry", password: "larry_pw" },
  ];

  const [lucy, moe, larry] = await Promise.all(
    credentials.map(async (credential) => {
      const hashedPW = await bcrypt.hash(credential.password, 5);
      User.create({ username: credential.username, password: hashedPW });
    })
  );

  return {
    users: {
      lucy,
      moe,
      larry,
    },
  };
};

module.exports = {
  syncAndSeed,
  models: {
    User,
  },
};
