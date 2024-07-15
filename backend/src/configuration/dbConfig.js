const mongoose=require("mongoose");
mongoose.connect("mongodb://127.0.0.1:27017/jwt_db");
mongoose.connection.on("connected",() => {
    console.log("connected to database successfully");
});

mongoose.connection.on("error",(err) => {
    console.log(`error in connecting to database: ${err}`);
});  

module.exports=mongoose;