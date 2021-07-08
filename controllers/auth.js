const crypto = require('crypto');

const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { validationResult } = require('express-validator/check')

const User = require('../models/user');

const transporter = nodemailer.createTransport({
	service: 'gmail',
	auth: {
		user: process.env.MAIL_USER,
		pass: process.env.MAIL_PASS
	}
});

exports.getLogin = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/login", {
    path: "/login",
    pageTitle: "Login",
    errorMessage: message,
	oldInput: {
        email: "",
        password: ""
      },
	validationErrors: []
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/signup", {
    path: "/signup",
    pageTitle: "Signup",
    errorMessage: message,
	oldInput: {
        email: "",
        password: "",
        confirmPassword: ""
      },
	validationErrors: []
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
	// console.log(errors.array())
    return res.status(422).render("auth/login", {
      path: "/login",
      pageTitle: "Login",
      errorMessage: errors.array()[0].msg,
	  oldInput: {
        email: email,
        password: password
      },
	  validationErrors: errors.array()
    });
  }

  User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        // req.flash("error", "Invalid email or password.");
        return res.status(422).render("auth/login", {
			path: "/login",
			pageTitle: "Login",
			errorMessage: "Invalid email or password.",
			oldInput: {
			  email: email,
			  password: password
			},
			validationErrors: []
		  });
      }
      bcrypt.compare(password, user.password).then((doMatch) => {
        if (doMatch) {
          req.session.isLoggedIn = true;
          req.session.user = user;
          return req.session.save((err) => {
            console.log(err);
            res.redirect("/");
          });
        }
        // req.flash("error", "Invalid email or password.");
		return res.status(422).render("auth/login", {
			path: "/login",
			pageTitle: "Login",
			errorMessage: "Invalid email or password.",
			oldInput: {
			  email: email,
			  password: password
			},
			validationErrors: []
		  });
      });
    })
	.catch((err) => {
		const error = new Error(err);
		error.httpStatusCode = 500;
		return next(error);
	  });
};

exports.postLogout = (req, res, next) => {
  // res.setHeader('Set-Cookie', 'loggedIn=true');
  req.session.destroy((err) => {
    console.log(err);
    res.redirect("/");
  });
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const name = email.split("@")[0];

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
	console.log(errors.array());
    return res.status(422).render("auth/signup", {
      path: "/signup",
      pageTitle: "Signup",
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
        confirmPassword: req.body.confirmPassword,
      },
	  validationErrors: errors.array()
    });
  }

  bcrypt
    .hash(password, 12)
    .then((hasedPassword) => {
      const user = new User({
        name: name,
        email: email,
        password: hasedPassword,
        cart: { item: [] },
      });
      return user.save();
    })
    .then((result) => {
      res.redirect("/login");
      return transporter.sendMail({
        to: email,
        from: process.env.MAIL_USER,
        subject: "Signup Succeeded!",
        html: "<h1>You successfully signed up!</h1>",
      });
    })
	.catch((err) => {
		const error = new Error(err);
		error.httpStatusCode = 500;
		return next(error);
	  });
};

exports.getReset = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/reset", {
    path: "/reset",
    pageTitle: "Reset Password",
    errorMessage: message,
  });
};

exports.postReset = (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
      return res.redirect("/reset");
    }
    const token = buffer.toString("hex");
    User.findOne({ email: req.body.email })
      .then((user) => {
        if (!user) {
          req.flash("error", "No account with that email found.");
          return res.redirect("/reset");
        }
        user.resetToken = token;
        user.resetTokenExp = Date.now() + 3600000;
        return user.save();
      })
      .then((result) => {
        res.redirect("/");
        transporter.sendMail({
          to: req.body.email,
          from: process.env.MAIL_USER,
          subject: "Password Reset",
          html: `
				<p>You requested a password reset</p>
				<p>Click this <a href="http://localhost:3000/reset/${token}">link</a> to set a new password.</p>
			`,
        });
      })
	  .catch((err) => {
		const error = new Error(err);
		error.httpStatusCode = 500;
		return next(error);
	  });
  });
};

exports.getNewPassword = (req, res, next) => {
  const token = req.params.token;
  User.findOne({ resetToken: token, resetTokenExp: { $gt: Date.now() } })
    .then((user) => {
      let message = req.flash("error");
      if (message.length > 0) {
        message = message[0];
      } else {
        message = null;
      }
      res.render("auth/new-password", {
        path: "/new-password",
        pageTitle: "Change Password",
        errorMessage: message,
        userId: user._id.toString(),
		passwordToken: token
	});
    })
	.catch((err) => {
		const error = new Error(err);
		error.httpStatusCode = 500;
		return next(error);
	  });
};

exports.postNewPassword = (req, res, next) => {
  const newPassword = req.body.password;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;
  let resetUser;

  User.findOne({
    resetToken: passwordToken,
    resetTokenExp: { $gt: Date.now() },
    _id: userId,
  })
    .then((user) => {
      resetUser = user;
      return bcrypt.hash(newPassword, 12);
    })
    .then((hashedPassword) => {
      resetUser.password = hashedPassword;
      resetUser.resetToken = undefined;
      resetUser.resetTokenExp = undefined;
      return resetUser.save();
    })
    .then((result) => {
      res.redirect("/login");
    })
	.catch((err) => {
		const error = new Error(err);
		error.httpStatusCode = 500;
		return next(error);
	  });
};
