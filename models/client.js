// models/Client.js
const mongoose=require('mongoose');
const Schema=mongoose.Schema;
const clientSchema= new Schema({
  clientId:
  {
    type: String,
    required:true
},  
clientSecret:
{
  type: String,
  required:true
},
user_id:
{
  type: String,
  required:true
},
redirect_uri:
{
  type: String,
  required:true
},


},{timestamps:true});

module.exports=mongoose.model('Client', clientSchema);