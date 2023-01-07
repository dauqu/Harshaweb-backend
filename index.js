const express = require("express");
const app = express();
const cors = require("cors");
const PORT = process.env.PORT || 4000;
const cookieParser = require("cookie-parser");



app.use(cookieParser());
app.use(express.static(__dirname+"/medias_web"));
app.use(express.static(__dirname+"/medias_app"));
app.use(express.json());

app.get("/", (req, res) => {
  res.json({ message: "VS_CODE_HOSTINGERR API is  working" });
});

//Loop of allowed origins
const allowedOrigins = [
  "http://localhost:3001",
  "http://localhost:3000",
  "http://localhost:4000",
  "https://vs-panel-website.vercel.app",
  "http://192.168.1.100:3000",
  "http://192.168.1.102:3000",
  "https://harsha-web-react.vercel.app/"
];

app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
  })
);

const connectDB = require("./config/database");
// const nodemon = require("nodemon");
connectDB();

app.use("/api/GetUser", require("./routes/user_register"));

// singup API
app.use("/api/signup", require("./routes/user_register"));

// login api
app.use("/api/login", require("./routes/login"));

// logout api
app.use("/api/logout", require("./routes/logout")); 

// Profile req and res
app.use("/api/admin_profile", require("./Profile/Adminprofile"));

// Profile req and res
app.use("/api/user_profile", require("./Profile/Userprofile"));

// image upload
app.use("/api/imageupload", require("./routes/ImageUpload"));

// payement
app.use("/api/payement", require("./routes/Payement"));

// stripe payment
app.use("/api/stripepayment", require("./routes/StripePayment"));

// User Register
app.use("/api/new_user_register", require("./routes/user_register"));
 
// User Login
app.use("/api/user_login", require("./routes/User_login_new"));

// User Logout
app.use("/api/user_logout", require("./routes/User_logout"));

//user_list
app.use("/api/user_list", require("./Profile/User_list"))

//contact list
app.use("/api/contact", require("./routes/contact"));

//request quote
app.use("/api/request_quote", require("./routes/request_quote"));

//review
app.use("/api/review", require("./routes/review"));

//website request
app.use("/api/website_request", require("./routes/web_req"));

//app request
app.use("/api/app_request", require("./routes/app_req"));



// vendor signup
// app.use("/api/vendor_signup", require("./routes/Vendor_register"));

// vendor get
// app.use("/api/vendor_get", require("./routes/Vendor_register"));

// gender selection
// app.use("/api/genderSelection", require("./routes/genderSelection"));

app.listen(PORT, () => {
  console.log(`server is running on http://localhost:${PORT}`);
});
