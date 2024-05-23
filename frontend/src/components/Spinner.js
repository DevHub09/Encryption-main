import React, { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import Typography from "@mui/material/Typography";
import CircularProgress from "@mui/material/CircularProgress";

const Spinner = ({ path = "login" }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [count, setCount] = useState(3);

  useEffect(() => {
    const interval = setInterval(() => {
      setCount((prevValue) => --prevValue);
    }, 1000);

    if (count === 0) {
      navigate(`/${path}`, { state: location.pathname });
    }

    return () => clearInterval(interval);
  }, [count, navigate, location.pathname, path]);

  return (
    <>
      <div
        style={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          height: "100vh",
        }}
      >
        <div>
          <Typography variant="h4" align="center">
            Redirecting you in {count} seconds
          </Typography>
          <CircularProgress style={{ marginTop: "1rem" }} />
        </div>
      </div>
    </>
  );
};

export default Spinner;
