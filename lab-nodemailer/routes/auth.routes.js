const router = require("express").Router();

// ℹ️ Handles password encryption
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const path = require("path");
const nodemailer = require("nodemailer");

// How many rounds should bcrypt run the salt (default [10 - 12 rounds])
const saltRounds = 10;

// Require the User model in order to interact with the database
const User = require("../models/User.model");

// Require necessary (isLoggedOut and isLoggedIn) middleware in order to control access to specific routes
const isLoggedOut = require("../middleware/isLoggedOut");
const isLoggedIn = require("../middleware/isLoggedIn");

router.get("/signup", async (req, res) => {
  res.render("auth/signup");
});

router.post("/signup", async (req, res) => {
  const { username, password, email } = req.body;

  if (!username) {
    return res.status(400).render("auth/signup", {
      errorMessage: "Please provide your username.",
    });
  }

  // if (password.length < 8) {
  //   return res.status(400).render("auth/signup", {
  //     errorMessage: "Your password needs to be at least 8 characters long.",
  //   });
  // }

  // //   ! This use case is using a regular expression to control for special characters and min length
  /*
  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}/;

  if (!regex.test(password)) {
    return res.status(400).render("signup", {
      errorMessage:
        "Password needs to have at least 8 chars and must contain at least one number, one lowercase and one uppercase letter.",
    });
  }
  */

  // Search the database for a user with the username submitted in the form
  const foundUser = await User.findOne({ username });
  if (foundUser) {
    res
      .status(400)
      .render("auth/signup", { errorMessage: "Username already taken." });
  }

  try {
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);

    //create unique string
    const createUniqueString = () => {
      const characters =
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
      let confirmationToken = "";
      for (let i = 0; i < 25; i++) {
        confirmationToken +=
          characters[Math.floor(Math.random() * characters.length)];
      }
      return confirmationToken;
    };
    // Create a user and save it in the database
    const newUserDB = await User.create({
      username,
      password: hashedPassword,
      email,
      status: "pending",
      confirmationCode: createUniqueString(),
    });

    //change password of db user to  '****'
    newUserDB.password = "****";
    req.session.user = newUserDB;

    //nodemailer for email confirmation
    //create a 'transporter' from nodemailer
    //The auth is a gmail account with the actual password with 3 point authentication
    let mailTransporter = nodemailer.createTransport({
      service: "gmail",
      port: 465,
      secure: true,
      auth: {
        user: "horheyinc8@gmail.com",
        pass: "knrvohekjawavfdi",
      },
    });
    // create object with all the properties of the email that you want to send.
    //attachments array is to send an image in the email, you need to use a cid: for this
    let styles = {
      background: "blue",
      width: "100%",
      display: "flex",
      flexDirection: "column",
    };

    let details = {
      from: "horheyinc8@gmail.com",
      to: newUserDB.email,
      subject: "Verify your email",
      text: "Please click the button to verify",
      attachments: [
        {
          filename: "ironhack-logo.png",
          path: path.join(__dirname, "..", "public/images/ironhack-logo.png"),
          cid: "logo",
        },
      ],
      html: `
      <div style= "background-color: powderblue; text-align: center; padding: 20px; border-radius: 20px">
      <img style="height: 350px" src='cid:logo'/>
      <h2>Ironhack Confirmation Email</h2>
      <h3>Welcome ${newUserDB.username}!</h3>
      <h3>Thanks for joining our community, Please confirm your email by clicking the button below</h3>
      <button style="background-color: #1e98c8; padding:10px; border-radius: 8px;"><a href='http://localhost:3000/auth/confirm/${newUserDB.confirmationCode}'  target="_blank" style="color:white; font-size:1.5rem; text-decoration:none;">Click me!</a></button>
      </div>`,
    };
    //this actually sends the email with all the details in the object that you created.
    mailTransporter.sendMail(details, (err) => {
      if (err) {
        console.log("There was an error", err);
      } else {
        console.log("Email has been sent");
      }
    });

    res.redirect("/");
  } catch (error) {
    if (error instanceof mongoose.Error.ValidationError) {
      return res
        .status(400)
        .render("auth/signup", { errorMessage: error.message });
    }
    if (error.code === 11000) {
      return res.status(400).render("auth/signup", {
        errorMessage:
          "Username need to be unique. The username you chose is already in use.",
      });
    }
    return res
      .status(500)
      .render("auth/signup", { errorMessage: error.message });
  }
});

router.get("/login", isLoggedOut, (req, res) => {
  res.render("auth/login");
});

router.post("/login", isLoggedOut, (req, res, next) => {
  const { username, password } = req.body;

  if (!username) {
    return res
      .status(400)
      .render("auth/login", { errorMessage: "Please provide your username." });
  }

  // Here we use the same logic as above
  // - either length based parameters or we check the strength of a password
  if (password.length < 8) {
    return res.status(400).render("auth/login", {
      errorMessage: "Your password needs to be at least 8 characters long.",
    });
  }

  // Search the database for a user with the username submitted in the form
  User.findOne({ username })
    .then((user) => {
      // If the user isn't found, send the message that user provided wrong credentials
      if (!user) {
        return res
          .status(400)
          .render("auth/login", { errorMessage: "Wrong credentials." });
      }

      // If user is found based on the username, check if the in putted password matches the one saved in the database
      bcrypt.compare(password, user.password).then((isSamePassword) => {
        if (!isSamePassword) {
          return res
            .status(400)
            .render("auth/login", { errorMessage: "Wrong credentials." });
        }

        req.session.user = user;
        // req.session.user = user._id; // ! better and safer but in this case we saving the entire user object
        return res.redirect("/");
      });
    })

    .catch((err) => {
      // in this case we are sending the error handling to the error handling middleware that is defined in the error handling file
      // you can just as easily run the res.status that is commented out below
      next(err);
      // return res.status(500).render("auth/login", { errorMessage: err.message });
    });
});

router.get("/logout", isLoggedIn, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res
        .status(500)
        .render("auth/logout", { errorMessage: err.message });
    }

    res.redirect("/");
  });
});

//confirmation route
router.get("/confirm/:confirmationCode", async (req, res) => {
  const { confirmationCode } = req.params;
  let verifiedUser = await User.findOneAndUpdate(
    { confirmationCode },
    { status: "confirmed" },
    { new: true }
  );
  console.log(verifiedUser);
  res.render("auth/profile", { verifiedUser });
});
module.exports = router;
