const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
var imgPath = '/path/yourimage.png';
var userSchema = new mongoose.Schema({
    fullName: {
        type: String,
        required: 'Enter your full name'
    },
    email: {
        type: String,
        required: 'Enter a valid email id',
        unique: true
    },
    password: {
        type: String,
        required: 'Password can\'t be empty',
        minlength: [4, 'Password must be atleast 4 characters long']
    },
    phone: {
        type: String,
        minlength: [10, 'Phone must be atleast 10 characters long']
    },
    gender: {
        type: String
    },
    state: {
        type: String
    },
    city: {
        type: String
    },
    img: {
        data: Buffer,
        contentType: String
    },
    saltSecret: String
});


// Custom validation for email using regex
userSchema.path('email').validate((val) => {
    emailRegex = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return emailRegex.test(val);
}, 'Invalid e-mail.');

userSchema.pre('save', function (next) {
    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(this.password, salt, (err, hash) => {
            this.password = hash;
            this.saltSecret = salt;
            next();
        });
    });
});

//Methods
userSchema.methods.verifyPassword = function (password) {
    return bcrypt.compareSync(password, this.password);
};

userSchema.methods.generateJwt = function() {
    const today = new Date();
    const expirationDate = new Date(today);
    expirationDate.setDate(today.getDate() + 60);

    return jwt.sign({
        _id: this.id,
        email: this.email,
        exp: parseInt(expirationDate.getTime() / 1000, 10),
    }, process.env.JWT_SECRET);
}

mongoose.model('User', userSchema);