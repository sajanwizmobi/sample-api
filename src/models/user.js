import mongoose from "mongoose";
import bcrypt from "bcrypt";

const Schema = mongoose.Schema;
const saltingRounds = 10;

const userSchema = new Schema({
  email: {
    type: "String",
    required: true,
    trim: true,
    unique: true
  },
  password: {
    type: "String",
    required: true,
    trim: true
  }
});

userSchema.pre("save", function(next) {
  const user = this;
  if (!user.isModified || !user.isNew) {
    next();
  } else {
    bcrypt.hash(user.password, saltingRounds, function(err, hash) {
      if (err) {
        console.log("Error hashing password for user", user.name);
        next(err);
      } else {
        user.password = hash;
        next();
      }
    });
  }
});

userSchema.methods.comparePassword = async function (passw) {
    return new Promise((resolve, reject) => {
        bcrypt.compare(passw, this.password, function (err, isMatch) {
            if (err) reject(err);
            resolve(isMatch);
        });
    })
};

module.exports = mongoose.model("User", userSchema);
