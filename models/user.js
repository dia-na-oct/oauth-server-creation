// models/Client.js
const mongoose=require('mongoose');
const Schema=mongoose.Schema;
const userSchema= new Schema({
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  profilePicture: {
    type: String,
  },

},{timestamps:true});

module.exports=mongoose.model('User', userSchema);