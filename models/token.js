// models/Client.js
const mongoose=require('mongoose');
const Schema=mongoose.Schema;
const tokenSchema= new Schema({
    access_token: {
    type: String,
    required: true,
  },
  refresh_token: {
    type: String,
  },
user: {
    type: String,
  },
 

},{timestamps:true});

module.exports=mongoose.model('Token', tokenSchema);