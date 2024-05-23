import React, { useState } from "react";
import axios from "axios";
import { useNavigate, Link, useLocation } from "react-router-dom";
import { toast } from "react-toastify";
import { useAuth } from "../../context/authContext";
import TextField from "@mui/material/TextField";
import Button from "@mui/material/Button";
import Card from "@mui/material/Card";
import CardContent from "@mui/material/CardContent";
import Typography from "@mui/material/Typography";
import Container from "@mui/material/Container";
import Grid from "@mui/material/Grid";

const Login = () => {
  // States
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  // Context
  const [auth, setAuth] = useAuth();
  // useNavigate and useLocation function
  const navigate = useNavigate();
  const location = useLocation();

  // Form Submit function
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`http://localhost:8000/api/v1/auth/login`, {
        email,
        password,
      });
      if (res && res.data.success) {
        toast.success(res.data && res.data.message);
        // using context
        setAuth({
          ...auth,
          user: res.data.user,
          token: res.data.token,
        });
        // Storing data in local storage
        localStorage.setItem("auth", JSON.stringify(res.data));
        navigate(location.state || "/");
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
              Login
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
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                label="Enter Your Password"
                variant="standard"
                fullWidth
                margin="normal"
                required
                style={{ marginBottom: "2rem" }}
                InputLabelProps={{ style: { color: "black" } }}
                sx={{
                  "& input": { color: "black" },
                }}
              />

              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <Button type="submit" variant="contained" color="success" style={{background:"black"}}>
                  Login
                </Button>
                <Button
                  variant="contained"
                  color="error"
                  onClick={() => {
                    navigate("/forget-password");
                  }}
                >
                  Forgot Password
                </Button>
              </div>
            </form>
            <div style={{ marginTop: "2rem" }}>
              <Typography style={{ color: "black" }}>
                Don't have an account?
                <span>
                  <Link
                    to="/register"
                    style={{
                      color: "black",
                      marginLeft: "5px",
                      fontWeight: "bolder",
                      textDecoration:"none"
                    }}
                  >
                    Register Now
                  </Link>
                </span>
              </Typography>
            </div>
          </CardContent>
        </Card>
      </Grid>
    </Container>
  );
};

export default Login;
