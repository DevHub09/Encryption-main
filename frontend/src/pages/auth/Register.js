import React, { useState } from "react";
import { toast } from "react-toastify";
import axios from "axios";
import { useNavigate, Link } from "react-router-dom";
import TextField from "@mui/material/TextField";
import Button from "@mui/material/Button";
import Card from "@mui/material/Card";
import CardContent from "@mui/material/CardContent";
import Typography from "@mui/material/Typography";
import Container from "@mui/material/Container";
import Grid from "@mui/material/Grid";

const Register = () => {
  // States
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [secret_word, setSecret_word] = useState("");
  // UseNavigate function
  const navigate = useNavigate();

  // Form Submit function
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(
        `http://localhost:8000/api/v1/auth/register`,
        { name, email, password, secret_word }
      );
      if (res && res.data.success) {
        toast.success(res.data.message);
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
            <Typography
              variant="h4"
              align="center"
              gutterBottom
              style={{ color: "black" }}
            >
              Register
            </Typography>
            <form onSubmit={handleSubmit}>
              <TextField
                value={name}
                onChange={(e) => setName(e.target.value)}
                type="text"
                label="Enter Your Username"
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
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                type="password"
                label="Enter Your Password"
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
                value={secret_word}
                onChange={(e) => setSecret_word(e.target.value)}
                type="text"
                label="What is your Secret Word?"
                variant="standard"
                fullWidth
                margin="normal"
                required
                InputLabelProps={{ style: { color: "black" } }}
                sx={{
                  "& input": { color: "black" },
                }}
              />
              <div
                style={{
                  display: "flex",
                  justifyContent: "center",
                  marginTop: "20px",
                }}
              >
                <Button
                  type="submit"
                  variant="contained"
                  color="success"
                  fullWidth
                  style={{background:"black"}}
                >
                  Register
                </Button>
              </div>
            </form>
            <div style={{ marginTop: "10px" }}>
              <Typography
                style={{
                  color: "black",
                }}
              >
                Already have an account?
                <span>
                  <Link
                    to="/login"
                    style={{
                      textDecoration: "none",
                      color: "black",
                      fontWeight: "bolder",
                      marginLeft: "1rem",
                    }}
                  >
                    Login Now
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

export default Register;
