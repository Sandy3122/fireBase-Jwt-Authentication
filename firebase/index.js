const express = require("express");
const app = express();
const admin = require("firebase-admin");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");

// Accessing th .env variable
dotenv.config();

const serviceAccount = require("./serviceAccountKey.json");
const { decode } = require("punycode");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

app.use(cookieParser());

// Middleware for json requests
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(express.static(__dirname + '/screen_splash'));

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/HomePage.html");
});

app.get("/register", (req, res) => {
  res.sendFile(__dirname + "/register.html");
});

app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/login.html");
});

app.get("/screenSplash", (req, res) => {
  res.sendFile(__dirname + "/screen_splash/splash_image.html");
});

// Secret Key For Hashing The Password
const secretKey = process.env.SECRETKEY;

// Register Route
app.post("/register", async (req, res) => {
  try {
    const { userName, mobileNumber, profilePic, password } = req.body;

    console.log(req.body);

    // Basic validation
    if (!(userName && mobileNumber && profilePic && password)) {
      return res.status(400).send(`
            Fill All The Details.
            Click here signUp <a href="/register"></a>`);
    }

    const saltRounds = process.env.SALT || 10;
    // Hashing the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save the user data to firestore
    const userRef = await admin.firestore().collection("users").add({
      userName,
      mobileNumber,
      password: hashedPassword,
      profilePic,
    });

    const token = jwt.sign({ uid: userRef._id }, secretKey, {
      expiresIn: "1h",
    });
    console.log(token);

    // Send back a json web token that can be used for authentication in future requests

    const loginUrl = "/login";
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Register Successfull</title>
        </head>
        <body>
        <h1>Registration Successful!</h1>
        <p>Your account has been successfully registered.</p>
        <p>You can now <a href="${loginUrl}">Login Here</a></p>
        </body>
        </html>
        `);
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

// User Login Route
app.post("/login", async (req, res) => {
  try {
    const { mobileNumber, password } = req.body;

    console.log(req.body);

    if (!(mobileNumber && password)) {
      return res.status(400).json({
        error: "Must provide username and password",
      });
    }

    // Verify user Credentials
    const userSnapshot = await admin
      .firestore()
      .collection("users")
      .where("mobileNumber", "==", mobileNumber)
      .get();

    if (userSnapshot.empty) {
      return res
        .status(401)
        .send(`Invalid Credentials. Please <a href="/login">LogIn</a>`);
    }

    const user = userSnapshot.docs[0].data();
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res
        .status(401)
        .send(`Invalid Password. Please <a href="/login">LogIn</a>`);
    }

    const token = jwt.sign({ uid: userSnapshot.docs[0].id }, secretKey, {
      expiresIn: "1h",
    });

    res.cookie("jwtToken", token, { httpOnly: true });

    res.redirect("/userProfile");

    console.log("Login Successful. Redirecting to /userProfile");
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

// Jwt Middleware For Verfication
const jwtMiddleware = (req, res, next) => {
  const token = req.cookies.jwtToken;

  if (!token) {
    console.log("No token found.");
    return res.status(401).json({ error: "Unauthorized" });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      console.error("Error Verifying Token:", err);
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (!decoded || !decoded.uid) {
      console.log("Decoded token or uid is missing.");
      return res.status(401).json({ error: "Unauthorized" });
    }

    req.userId = decoded.uid;
    next();
  });
};

// User Profile Route
app.get("/userProfile", jwtMiddleware, async (req, res) => {
  try {
    const userId = req.userId;

    console.log("User Id:", userId);

    if (!userId) {
      console.log("User Id Is Undefined.");
      return res.status(401).json({ error: "Unauthorized" });
    }

    const userSnapshot = await admin
      .firestore()
      .collection("users")
      .doc(userId)
      .get();

    if (!userSnapshot.exists) {
      console.log("User not found.");
      return res.status(404).json({ error: "User not found." });
    }

    const userData = userSnapshot.data();
    console.log(userData);

    res.send(`
    <!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Profile</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet"
        integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
    <style>
        body {
            background-color: #f8f9fa;
        }

        .container {
            background-color: #fff;
            padding: 20px;
            margin-top: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }

        .profile-pic {
            border-radius: 50%;
            max-width: 100%;
            height: auto;
            margin-top: 20px; /* Responsive margin */
        }

        .logout-btn {
            margin-top: 20px;
            padding: 10px 20px; /* Responsive padding */
        }
    </style>
</head>

<body>
    <div class="container text-center">
        <h1 class="mt-4">Welcome, ${userData.userName}</h1>
        <img src="${userData.profilePic}" alt="Profile Picture" class="profile-pic mt-3"><br>
        <a href="/logout" class="mt-3"><button class="btn btn-primary logout-btn">Log Out</button></a>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM"
        crossorigin="anonymous"></script>
</body>

</html>
`);
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

// Logout Route
app.get("/logout", (req, res) => {
  res.clearCookie("jwtToken");

  res.redirect("/login");
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server Is Started: http://localhost:${PORT}`);
});
