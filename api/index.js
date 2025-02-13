import express from "express";
import mongoose from "mongoose";

import dotenv from "dotenv";
import authRouter from "./routes/auth.route.js";
import userRouter from "./routes/user.route.js";
dotenv.config();

mongoose
  .connect(process.env.MONGO)
  .then(() => {
    console.log("Connected to MongoDB!!!");
  })
  .catch((err) => {
    console.log(err);
  });

const app = express();

app.use(express.json())

app.listen(3000, () => {
  console.log("server is runnig on port 3000");
});

app.use("/api" , userRouter);
app.use("/api/auth" , authRouter);

app.use((err , req, res , next)=>{
  const statusCode = err.statusCode || 500;
  const message = err.message || "Internal Server Error";
  return res.status(statusCode).json({
    success : false,
    message,
    statusCode
  })
})