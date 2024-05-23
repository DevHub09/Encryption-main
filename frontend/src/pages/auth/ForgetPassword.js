import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import TextField from "@mui/material/TextField";
import Button from "@mui/material/Button";
import Card from "@mui/material/Card";
import CardContent from "@mui/material/CardContent";
import Typography from "@mui/material/Typography";
import Container from "@mui/material/Container";
import Grid from "@mui/material/Grid";

const ForgetPassword = () => {
  // States
  const [email, setEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [secret_word, setSecret_word] = useState("");

  // useNavigate function
  const navigate = useNavigate();

  // Form Submit function
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(
        `http://localhost:8000/api/v1/auth/forgot-password`,
        { email, secret_word, newPassword }
      );
      if (res && res.data.success) {
        toast.success(res.data && res.data.message);
        navigate("/login");
      } else {
        toast.error(res.data.message);
      }
    } catch (error) {
      console.log(error);
      toast.error("Something went wrong");
    }
  };

  return (
    <Container
      sx={{
        color: "white",
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <Grid item xs={12} sm={8} md={6} lg={4}>
        <Card variant="outlined" style={{ backgroundColor: "#ff8fab" }}>
          <CardContent>
            <Typography variant="h4" align="center" style={{ color: "black" }}>
              Reset Password
            </Typography>
            <form onSubmit={handleSubmit}>
              <TextField
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                label="Enter Your Email"
                variant="standard"
                fullWidth
                margin="normal"
                required
                InputLabelProps={{ style: { color: "black" } }}
                sx={{
                  "& input": { color: "black" },
                }}
              />
              <TextField
                type="text"
                value={secret_word}
                onChange={(e) => setSecret_word(e.target.value)}
                label="Enter Your High School Name"
                variant="standard"
                fullWidth
                margin="normal"
                required
                InputLabelProps={{ style: { color: "black" } }}
                sx={{
                  "& input": { color: "black" },
                }}
              />
              <TextField
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                type="password"
                label="Enter Your New Password"
                variant="standard"
                fullWidth
                margin="normal"
                required
                InputLabelProps={{ style: { color: "black" } }}
                sx={{
                  "& input": { color: "black" },
                }}
              />

              <div className="text-center">
                <Button
                  type="submit"
                  variant="contained"
                  color="success"
                  style={{ textAlign: "center", marginTop: "1rem" ,background:"blackx"}}
                >
                  Reset Password
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </Grid>
    </Container>
  );
};

export default ForgetPassword;
