const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const jwt = require('jsonwebtoken');
const appError = require('./../utils/appError');
const { promisify } = require('util');
const { nextTick, send } = require('process');
const { runInNewContext } = require('vm');
const sendEmail = require('./../utils/email');



const signToken = id => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXP
    });
}

exports.signup = catchAsync(async (req, res, next) => {
    const newUser = await User.create(req.body);

    const token = signToken(newUser._id);

    res.status(201).json({
        status: 'success',
        token,
        body: {
         user:newUser
        }
    });
})

exports.login =catchAsync( async (req, res, next) => {
    const { email, password } = req.body;
    // if email and password exists
    if (!email || !password) {
        next(new appError('please provide email and password!',400));
    }
    //if user exist && password is correct
    const user =await User.findOne({ email }).select('+password');
    
    //if everything is ok

    if (!user || !(await user.correctPassword(password, user.password))) {
        return next(new appError('Invalid userid or password', 401));
    }

    const token = signToken(user._id);
    
    res.status(201).json({
        status: 'success',
        token
    });
})

exports.protect = catchAsync(async (req, res, next) => {
    // 1) Getting token and check of it's there
    let token;
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    ) {
      token = req.headers.authorization.split(' ')[1];
    }
  
    if (!token) {
      return next(
        new appError('You are not logged in! Please log in to get access.', 401)
      );
    }
  
    // 2) Verification token
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
  
    // 3) Check if user still exists
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return next(
        new appError(
          'The user belonging to this token does no longer exist.',
          401
        )
      );
    }
  
    // 4) Check if user changed password after the token was issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return next(
        new appError('User recently changed password! Please log in again.', 401)
      );
    }
  
    // GRANT ACCESS TO PROTECTED ROUTE
    req.user = currentUser;
    next();
  });
  
exports.restrictTo = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return next(
                new appError("You don't have permission to perform this action", 403)
            );
        }
        next();
      }
}
  
exports.forgotPassword = catchAsync(async (req, res, next) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
        return next(new appError('There is no user with this email address', 404));
    }

    const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });
  
  const resetURL = `${req.protocol}://${req.get(
    'host'
  )}/api/v1/users/resetPassword/${resetToken}`;

  const message = `forgot your password than submit the patch request by sending new password
  and password confirm to:${resetURL}\n if you don't forget your your password than please ignore this email`;

  try {
    await sendEmail({
      email: user.email,
      subject: ' this password reset URL is only valid fo only 10 MIN',
      message
    });

    res.status(200).json({
      status: 'sucess',
      message: ' password reset link is being sent to your email!'
    });
  }
  catch (err) {
    user.PasswordResetToken = undefined;
    user.passwordResetExp = undefined;
    await user.save({ validateBeforeSave: false });
    return next(
      new appError('there is a problem to sending email for reset password please try again later!',500)
    )
  }

});

exports.resetPassword = catchAsync(async (req, res, next) => {
    
})