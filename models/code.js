// models/Client.js
const mongoose=require('mongoose');
const Schema=mongoose.Schema;
const codeSchema= new Schema({
    code: {
    type: String,
    required: true,
  },
  user_id: {
    type: String,
  },
  client_id: {
    type: String,
  },
  redirect_uri: {
    type: String,
  },

},{timestamps:true});

module.exports=mongoose.model('Code', codeSchema);