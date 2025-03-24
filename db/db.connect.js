const mongoose = require("mongoose");

require("dotenv").config();

const MONGOURI = process.env.MONGODB;

async function connectToDB() {
  await mongoose
    .connect(MONGOURI)
    .then(() => {
      console.log("Connected to the DB");
    })
    .catch((e) => {
      console.log("Unable to connect to DB", e);
    });
}

module.exports = { connectToDB };
