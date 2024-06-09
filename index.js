const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require("dotenv").config();

const {
  SESClient,
  SendEmailCommand,
  VerifyEmailIdentityCommand,
} = require("@aws-sdk/client-ses");

const {
  AWS_SECRET: awsSecret,
  AWS_REGION: awsRegion,
  AWS_ACCESS_Id: awsId,
  TOKEN_SECRET: secret,
  DATABASE_STRING,
  SOURCE: source,
} = process.env;

const sesClient = new SESClient({
  region: awsRegion,
  credentials: {
    accessKeyId: awsId,
    secretAccessKey: awsSecret,
  },
});

mongoose.connect(DATABASE_STRING, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const User = mongoose.model("User", {
  username: String,
  email: String,
  password: String,
  tasks: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Task",
    },
  ],
});

const Task = mongoose.model("Task", {
  content: String,
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },
});

async function deleter() {
  await User.deleteMany();
  const data = await User.find();
  console.log("users: ", data);
}
//deleter();

const app = express();

app.use(cors());
app.use(bodyParser.json());

const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    res.status(401).json({ message: "not autheticated user" });
  }
  const token = authHeader.split(" ")[1];

  jwt.verify(token, secret, (err, decode) => {
    if (err) {
      res.status(401).json({
        message: "authentication failed",
      });
    }
    req.userId = decode.userId;
    next();
  });
};

app.post("/login", async (req, res, next) => {
  try {
    const details = req.body;
    const user = await User.findOne({
      username: details.username,
    });
    if (user && (await bcrypt.compare(details.password, user.password))) {
      const token = jwt.sign({ userId: user._id }, secret);
      const verificationLink = `http://localhost:3000/api/verify-mfa?token=${token}&userId=${user._id}`;
      const messageData = {
        Destination: {
          ToAddresses: [user.email],
        },
        Message: {
          Body: {
            Text: {
              Data: `Please click this link to log in to your account ${verificationLink}`,
              Charset: "UTF-8",
            },
          },
          Subject: {
            Data: "Account verification",
            Charset: "UTF-8",
          },
        },
        Source: source,
      };
      const command = new SendEmailCommand(messageData);

      sesClient
        .send(command)
        .then(() => {
          res.status(200).json({
            valid: true,
            userId: user._id,
            token,
            message: "Please check the mfa link in your email",
          });
        })
        .catch((error) => {
          res.status(500).json(error.message);
        });
    } else {
      res.json({ valid: false });
    }
  } catch (error) {
    next(error);
  }
});

app.post("/register", async (req, res, next) => {
  try {
    const details = req.body;

    const user = await User.findOne({ username: details.username });
    if (!user) {
      const hashedPass = await bcrypt.hash(details.password, 10);
      const newUser = new User({
        username: details.username,
        email: details.email,
        password: hashedPass,
      });
      await newUser.save();
      const token = jwt.sign({ userId: newUser._id }, secret);
      res.json({ valid: true, userId: newUser._id, token });
    } else {
      res.json({ valid: false });
    }
  } catch (error) {
    next(error);
  }
});

app.post("/forget", async (req, res, next) => {
  try {
    const { email, username } = req.body;
    const user = await User.findOne({ username: username, email: email });
    if (user) {
      const token = jwt.sign({ userId: user._id }, secret, { expiresIn: "1h" });
      const verificationLink = `http://localhost:3000/api/verify-email?token=${token}&user=${user._id}`;
      const messageData = {
        Destination: {
          ToAddresses: [email],
        },
        Message: {
          Body: {
            Text: {
              Data: `Please click this link to reset your password ${verificationLink}`,
              Charset: "UTF-8",
            },
          },
          Subject: {
            Data: "Account verification",
            Charset: "UTF-8",
          },
        },
        Source: source,
      };
      const command = new SendEmailCommand(messageData);

      sesClient
        .send(command)
        .then(() => {
          res.status(200).json({
            valid: true,
            userId: user._id,
            token,
            message: "Please check the verification link in your email",
          });
        })
        .catch((error) => {
          res.status(500).json(error.message);
        });
    } else {
      res.json({
        message: "Please fill correct details",
      });
    }
  } catch (error) {
    next(error);
  }
});

app.post("/verify-email", async (req, res, next) => {
  try {
    const { email } = req.body;
    await sesClient
      .send(new VerifyEmailIdentityCommand({ EmailAddress: email }))
      .then(() => {
        res.json({
          message: "Please check the verification link in your email",
        });
      })
      .catch((error) => {
        res.json({
          message: "Please fill correct email: " + error.message,
        });
      });
  } catch (error) {
    res.json({
      message: "Please fill correct email: " + error.message,
    });
  }
});

app.get("/verify-mfa", async (req, res, next) => {
  try {
    const { token, userId } = req.query;
    jwt.verify(token, secret, (err, decode) => {
      if (err) {
        res.json({
          message: "unauthenticated account, please fill correct details",
        });
      } else {
        res.redirect(`http://localhost:3000?token=${token}&userId=${userId}`);
      }
    });
  } catch (error) {
    next(error);
  }
});

app.get("/verify-email", async (req, res, next) => {
  const { token, user: userId } = req.query;
  jwt.verify(token, secret, (err, decode) => {
    if (err) {
      res.json({
        message: "unauthenticated account, please fill correct details",
      });
    } else {
      res.redirect(
        `http://localhost:3000/reset?token=${token}&userId=${userId}`
      );
    }
  });
});

app.post("/reset", authenticate, async (req, res, next) => {
  try {
    const { password, userId } = req.body;
    const user = await User.findById(userId);
    if (user) {
      const hashedPass = await bcrypt.hash(password, 10);
      await User.findByIdAndUpdate(userId, {
        password: hashedPass,
      });
      res.json({ valid: true, message: "password reset successfully" });
    } else {
      res.json({
        valid: false,
        message: "Please use verification link to reset password",
      });
    }
  } catch (error) {
    next(error);
  }
});

app.post("/task", authenticate, async (req, res, next) => {
  try {
    const { content, userId } = req.body;
    const user = await User.findById(userId);
    if (!user) {
      res.status(404).json({ message: "user not found" });
    }
    const task = await Task({ content, user: user._id });
    await task.save();
    await user.tasks.push(task._id);
    await user.save();
    res.json({ message: "added successfully" });
  } catch (error) {
    next(error);
  }
});

app.get("/tasks", authenticate, async (req, res, next) => {
  try {
    const { userId } = req.query;
    const user = await User.findById(userId).populate("tasks");
    if (!user) {
      res.status(404).json({ message: "user not found" });
    }
    res.status(200).json(user.tasks);
  } catch (error) {
    next(error);
  }
});

app.use((error, req, res, next) => {
  if (error) {
    console.log(error.message);
    res.status(500).json({ message: "internal server error" });
  } else {
    res.json({ message: "not error , other issue" });
  }
});

app.listen(5000, () => {
  console.log(`server listen on http://localhost:5000`);
});