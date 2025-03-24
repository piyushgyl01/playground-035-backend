const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const axios = require("axios");
const crypto = require("crypto");
require("dotenv").config();

const { connectToDB } = require("./db/db.connect.js");

const User = require("./models/user.model.js");
const Anime = require("./models/anime.model.js");

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());

const corsOptions = {
  origin: ["http://localhost:5173"],
  credentials: true,
  optionSuccessStatus: 200,
};

app.use(cors(corsOptions));
app.use(cookieParser());

if (!process.env.JWT_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
  console.error(
    "CRITICAL ERROR: JWT secrets not set in environment variables!"
  );
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

connectToDB();

function generateTokens(user) {
  const payload = {
    id: user._id,
    username: user.username || user.email,
  };

  const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: "15m" });
  const refreshToken = jwt.sign({ id: user._id }, REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });

  return { accessToken, refreshToken };
}

function setAuthCookies(res, accessToken, refreshToken) {
  res.cookie("access_token", accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 15 * 60 * 1000,
  });

  res.cookie("refresh_token", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/auth/refresh-token",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function clearAuthCookies(res) {
  res.cookie("access_token", "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 0,
  });

  res.cookie("refresh_token", "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/auth/refresh-token",
    maxAge: 0,
  });
}

function authenticateToken(req, res, next) {
  const accessToken = req.cookies.access_token;

  if (!accessToken) {
    return res
      .status(403)
      .json({ message: "You need to sign in before continuing" });
  }

  try {
    const decoded = jwt.verify(accessToken, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res
      .status(403)
      .json({ message: "Invalid token", error: error.message });
  }
}

app.post("/auth/register", async (req, res) => {
  const { username, name, email, password } = req.body;

  if (!username || !name || !email || !password) {
    return res
      .status(400)
      .json({ message: "Please provide all required fields" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (email && !emailRegex.test(email)) {
    return res
      .status(400)
      .json({ message: "Please provide a valid email address" });
  }

  if (password.length < 8) {
    return res
      .status(400)
      .json({ message: "Password must be at least 8 characters long" });
  }

  try {
    const existingUser = await User.findOne({
      $or: [{ username }, { email: email || null }],
    });

    if (existingUser) {
      return res.status(400).json({
        message:
          existingUser.username === username
            ? "Username already exists"
            : "Email already exists",
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      username,
      name,
      email: email || null,
      password: hashedPassword,
    });

    await newUser.save();

    const { accessToken, refreshToken } = generateTokens(newUser);

    setAuthCookies(res, accessToken, refreshToken);

    const userResponse = {
      _id: newUser._id,
      username: newUser.username,
      name: newUser.name,
      email: newUser.email,
    };

    res
      .status(201)
      .json({ message: "User registered successfully", user: userResponse });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error registering user", error: error.message });
  }
});

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Please provide all required fields" });
  }

  try {
    const user = await User.findOne({
      $or: [{ username }, { email: username }],
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (!user.password) {
      return res.status(401).json({
        message:
          "This account uses social login. Please sign in with the appropriate provider.",
      });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const { accessToken, refreshToken } = generateTokens(user);

    setAuthCookies(res, accessToken, refreshToken);

    const userResponse = {
      _id: user._id,
      username: user.username,
      name: user.name,
      email: user.email,
      avatar: user.avatar,
    };

    res
      .status(200)
      .json({ message: "Logged in successfully", user: userResponse });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error logging in user", error: error.message });
  }
});

app.post("/auth/refresh-token", async (req, res) => {
  const refreshToken = req.cookies.refresh_token;

  if (!refreshToken) {
    return res.status(401).json({ message: "No refresh token provided" });
  }

  try {
    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    const tokens = generateTokens(user);
    setAuthCookies(res, tokens.accessToken, tokens.refreshToken);

    res.status(200).json({ message: "Token refreshed successfully" });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Invalid refresh token", error: error.message });
  }
});

app.get("/auth/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password -__v");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error fetching profile", error: error.message });
  }
});

app.post("/auth/logout", (req, res) => {
  clearAuthCookies(res);
  res.status(200).json({ message: "Logged out successfully" });
});

function generateOAuthState() {
  return crypto.randomBytes(32).toString("hex");
}

const oauthStates = new Map();

app.get("/auth/google", async (req, res) => {
  const state = generateOAuthState();
  oauthStates.set(state, { timestamp: Date.now() });

  const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  authUrl.searchParams.append("client_id", process.env.GOOGLE_CLIENT_ID);
  authUrl.searchParams.append(
    "redirect_uri",
    `${process.env.API_URL}/auth/google/callback`
  );
  authUrl.searchParams.append("response_type", "code");
  authUrl.searchParams.append("scope", "profile email");
  authUrl.searchParams.append("state", state);

  res.redirect(authUrl.toString());
});

app.get("/auth/google/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!state || !oauthStates.has(state)) {
    return res.redirect(`${process.env.FRONTEND_URL}/auth?error=invalid_state`);
  }

  oauthStates.delete(state);

  if (!code) {
    return res.redirect(
      `${process.env.FRONTEND_URL}/auth?error=google_auth_failed`
    );
  }

  try {
    const tokenResponse = await axios.post(
      "https://oauth2.googleapis.com/token",
      {
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${process.env.API_URL}/auth/google/callback`,
        grant_type: "authorization_code",
      }
    );

    const { access_token } = tokenResponse.data;

    const userInfoResponse = await axios.get(
      "https://www.googleapis.com/oauth2/v2/userinfo",
      { headers: { Authorization: `Bearer ${access_token}` } }
    );

    const googleUserInfo = userInfoResponse.data;

    let user = await User.findOne({ googleId: googleUserInfo.id });

    if (!user) {
      if (googleUserInfo.email) {
        const existingUser = await User.findOne({
          email: googleUserInfo.email,
        });
        if (existingUser) {
          existingUser.googleId = googleUserInfo.id;
          existingUser.avatar = existingUser.avatar || googleUserInfo.picture;
          user = await existingUser.save();
        }
      }
      if (!user) {
        user = new User({
          googleId: googleUserInfo.id,
          name: googleUserInfo.name,
          email: googleUserInfo.email,
          username: googleUserInfo.email
            ? googleUserInfo.email.split("@")[0]
            : `user_${googleUserInfo.id}`,
          avatar: googleUserInfo.picture,
        });
        await user.save();
      }
    }

    const { accessToken, refreshToken } = generateTokens(user);
    setAuthCookies(res, accessToken, refreshToken);

    const userForFrontend = {
      _id: user._id,
      username: user.username,
      name: user.name,
      email: user.email,
      avatar: user.avatar,
      googleId: user.googleId,
    };

    res.redirect(
      `${process.env.FRONTEND_URL}/auth/success?user=${encodeURIComponent(
        JSON.stringify(userForFrontend)
      )}&provider=google`
    );
  } catch (error) {
    return res.redirect(
      `${process.env.FRONTEND_URL}/auth?error=google_auth_failed`
    );
  }
});

app.get("/auth/github", async (req, res) => {
  const state = generateOAuthState();
  oauthStates.set(state, { timestamp: Date.now() });

  const authUrl = new URL("https://github.com/login/oauth/authorize");
  authUrl.searchParams.append("client_id", process.env.GITHUB_CLIENT_ID);
  authUrl.searchParams.append(
    "redirect_uri",
    `${process.env.API_URL}/auth/github/callback`
  );
  authUrl.searchParams.append("scope", "user:email");
  authUrl.searchParams.append("state", state);

  res.redirect(authUrl.toString());
});

app.get("/auth/github/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!state || !oauthStates.has(state)) {
    return res.redirect(`${process.env.FRONTEND_URL}/auth?error=invalid_state`);
  }

  oauthStates.delete(state);

  if (!code) {
    return res.redirect(
      `${process.env.FRONTEND_URL}/auth?error=github_auth_failed`
    );
  }

  try {
    const tokenResponse = await axios.post(
      "https://github.com/login/oauth/access_token",
      {
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${process.env.API_URL}/auth/github/callback`,
      },
      {
        headers: { Accept: "application/json" },
      }
    );

    const { access_token } = tokenResponse.data;

    const userResponse = await axios.get("https://api.github.com/user", {
      headers: { Authorization: `token ${access_token}` },
    });

    const githubUserInfo = userResponse.data;

    let email = githubUserInfo.email;

    if (!email) {
      try {
        const emailResponse = await axios.get(
          "https://api.github.com/user/emails",
          {
            headers: { Authorization: `token ${access_token}` },
          }
        );

        const primaryEmail = emailResponse.data.find((e) => e.primary);
        if (primaryEmail) {
          email = primaryEmail.email;
        } else if (emailResponse.data.length > 0) {
          email = emailResponse.data[0].email;
        }
      } catch (error) {
        console.log("Error fetching github emails", error);
      }
    }

    let user = await User.findOne({ githubId: githubUserInfo.id });

    if (!user) {
      if (email) {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
          existingUser.githubId = githubUserInfo.id;
          existingUser.avatar =
            githubUserInfo.avatar_url || existingUser.avatar;
          user = await existingUser.save();
        }
      }

      if (!user) {
        user = new User({
          githubId: githubUserInfo.id,
          name: githubUserInfo.name || githubUserInfo.login,
          email: githubUserInfo.email,
          username:
            githubUserInfo.login ||
            (email ? email.split("@")[0] : `user_${githubUserInfo.id}`),
          avatar: githubUserInfo.avatar_url,
        });
        await user.save();
      }
    }

    const { accessToken, refreshToken } = generateTokens(user);
    setAuthCookies(res, accessToken, refreshToken);

    const userForFrontend = {
      _id: user._id,
      username: user.username,
      name: user.name,
      email: user.email,
      avatar: user.avatar,
      githubId: user.githubId,
    };

    res.redirect(
      `${process.env.FRONTEND_URL}/auth/success?user=${encodeURIComponent(
        JSON.stringify(userForFrontend)
      )}&provider=github`
    );
  } catch (error) {
    return res.redirect(
      `${process.env.FRONTEND_URL}/auth?error=github_auth_failed`
    );
  }
});

app.post("/animes", authenticateToken, async (req, res) => {
  const { name, img, description } = req.body;
  const userId = req.user.id;

  try {
    const newAnime = new Anime({
      name,
      img,
      description,
      user: userId,
    });

    const savedAnime = await newAnime.save();

    res
      .status(201)
      .json({ message: "Anime added successfully", anime: savedAnime });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error adding anime", error: error.message });
  }
});

app.get("/animes", authenticateToken, async (req, res) => {
  try {
    const animes = await Anime.find().populate("user", "name username avatar");
    res.json({ animes });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error getting anime", error: error.message });
  }
});

app.get("/animes/:id", authenticateToken, async (req, res) => {
  try {
    const anime = await Anime.findById(req.params.id).populate(
      "user",
      "name username avatar"
    );

    if (!anime) {
      return res.status(404).json({ message: "Unable to find the anime" });
    }

    res.json({ anime });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error getting anime", error: error.message });
  }
});

app.put("/animes/:id", authenticateToken, async (req, res) => {
  try {
    const anime = await Anime.findById(req.params.id);

    if (!anime) {
      return res.status(404).json({ message: "Unable to find the anime" });
    }

    if (anime.user.toString() !== req.user.id) {
      return res
        .status(403)
        .json({ message: "You are not authorised to edit this anime" });
    }

    const updatedAnime = await Anime.findByIdAndUpdate(
      req.params.id,
      { $set: req.body },
      { new: true }
    );

    res.json({ message: "Anime updated successfully", anime: updatedAnime });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error updating anime", error: error.message });
  }
});

app.delete("/animes/:id", authenticateToken, async (req, res) => {
  try {
    const anime = await Anime.findById(req.params.id);

    if (!anime) {
      return res.status(404).json({ message: "Unable to find the anime" });
    }

    if (anime.user.toString() !== req.user.id) {
      return res
        .status(403)
        .json({ message: "You are not authorised to delete this anime" });
    }

    await Anime.findByIdAndDelete(req.params.id);

    res.json({ message: "Anime deleted successfully", anime: anime });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error deleting anime", error: error.message });
  }
});

setInterval(() => {
  const now = Date.now();
  for (const [state, data] of oauthStates.entries()) {
    if (now - data.timestamp > 10 * 60 * 1000) {
      oauthStates.delete(state);
    }
  }
}, 5 * 60 * 1000);

app.use((req, res, next) => {
  res.status(404).json({ message: "Resource not found" });
});

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({
    message: "Internal server error",
    error: process.env.NODE_ENV === "development" ? err.message : null,
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
});
