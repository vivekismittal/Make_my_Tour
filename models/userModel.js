const mongoose = require('mongoose');
const validator = require('validator');
const bycrypt = require('bcryptjs');
const crypto = require('crypto');
const userSchema = new mongoose.Schema({
    name: {
        required: [true, ' Please tell us your name'],
        type: String
    },
    email: {
        unique: true,
        type: String,
        required: [true, 'Please provide your email'],
        lowercase: true,
        validate:[validator.isEmail,'please provide a valid email address']
    },
    password: {
        type: String,
        required: [true, 'Please provide a password'],
        minlength: 8
    },
    passwordConfirm: {
        type: String,
        required: [true, 'Please confirm your password'],
        validate: {
            // This only works on CREATE Or SAVE!!
            validator: function (el) {
                return el === this.password;
            },
            message:'Passwords are not the same'
        }
    },
    photo: String,
    passwordChangedat: Date,
    role: {
        type: String,
        enum: ["admin", "guide", "lead-guide", "user"],
        default:'user'
    },
    passwordResetToken: String,
    passwordResetExp:Date
});

userSchema.pre('save', async function (next) {
    // ONLY RUN THIS FUNCTION PASSWORD IS ACTUALLY MODIFIED
    if (!this.isModified('password')) return next();
    
    this.password = await bycrypt.hash(this.password, 12);
    this.passwordConfirm = undefined;
    next();
});

userSchema.methods.correctPassword = async function (
    candidatePassword,
    userPassword
) {
    return await bycrypt.compare(candidatePassword, userPassword);
}

userSchema.methods.changedPasswordAfter = function (JWTTmeStamp) {
    if (this.passwordChangedAt) {
        const changeTimeStamp = parseInt(this.passwordChangedat.getTime() / 1000);

        return JWTTmeStamp < changeTimeStamp;
    }

    //MEANS THE PASSWORD NOT CHANGED
    return false;
}

userSchema.methods.createPasswordResetToken = function () {
    const resetToken = crypto.randomBytes(32).toString('hex');
    this.passwordResetToken = crypto
        .createHash('sha256')
        .update(resetToken)
        .digest('hex');
    console.log({ resetToken }, this.passwordResetToken);
    this.passwordResetExp = Date.now() + 10 * 60 * 1000;
    return resetToken;
}

const User = mongoose.model('User', userSchema);
module.exports = User;