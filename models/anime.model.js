const mongoose = require("mongoose");

const animeSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Pg34User",
      required: true,
    },
    img: { type: String, required: true },
    description: { type: String, required: true },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Pg35Anime", animeSchema);
