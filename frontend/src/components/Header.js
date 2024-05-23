import React, { useState } from "react";
import {
  AppBar,
  Toolbar,
  Typography,
  InputBase,
  IconButton,
  Menu,
  MenuItem,
} from "@mui/material";

import { NavLink } from "react-router-dom";
import { useAuth } from "../context/authContext";
const Header = () => {
  const [anchorEl, setAnchorEl] = useState(null);
  const [auth, setAuth] = useAuth();
  const handleMenu = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };
  const handleLogout = () => {
    setAuth({
      ...auth,
      user: null,
      token: "",
    });
    localStorage.removeItem("auth");
    alert("Logout Successfully");
  };
  return (
    <AppBar position="fixed" style={{ backgroundColor: "#ff8fab" ,padding:"0 60px"}}>
      <Toolbar>
        <div style={{ flexGrow: 1, display: "flex", alignItems: "center" }}>
          <div style={{ marginRight: "20px"}}>
            <Typography
              variant="h6"
              color="inherit"
              noWrap
              style={{ textAlign: "center" }}
            >
              <NavLink
                to="/"
                style={{ textDecoration: "none", color: "black" }}
              >
                Data Encryption
              </NavLink>
            </Typography>
          </div>
        </div>

        {/* Centered Search input */}
        {/* <div style={{ flex: 1, display: "flex", justifyContent: "center" }}>
          <div
            style={{
              position: "relative",
              border: "1px solid #ccc",
              borderRadius: "4px",
            }}
          >
            <InputBase
              placeholder="Search…"
              style={{ padding: "5px", color: "white" }}
            />
            <IconButton color="primary" type="submit" aria-label="search">
              <SearchIcon />
            </IconButton>
          </div>
        </div> */}

        <div style={{ display: "flex", alignItems: "center" }}>
          <div style={{ marginRight: "20px" }}>
            <Typography variant="h6" color="inherit" noWrap>
              <NavLink
                to="/"
                style={{ textDecoration: "none", color: "black" }}
              >
                Home
              </NavLink>
            </Typography>
          </div>
          <div style={{ marginRight: "20px" }}>
            <Typography variant="h6" color="inherit" noWrap>
              <NavLink
                to="/encrypt"
                style={{ textDecoration: "none", color: "black" }}
              >
                Encryption
              </NavLink>
            </Typography>
          </div>
          {/* <div style={{ marginRight: "20px" }}>
            <Typography variant="h6" color="inherit" noWrap>
              <NavLink
                to="/category"
                style={{ textDecoration: "none", color: "black" }}
              >
                Category
              </NavLink>
            </Typography>
          </div> */}
          {!auth.user ? (
            <>
              <div style={{ marginRight: "20px" }}>
                <Typography variant="h6" color="inherit" noWrap>
                  <NavLink
                    to="/register"
                    style={{ textDecoration: "none", color: "black" }}
                  >
                    Register
                  </NavLink>
                </Typography>
              </div>
              <div style={{ marginRight: "20px" }}>
                <Typography variant="h6" color="inherit" noWrap>
                  <NavLink
                    to="/login"
                    style={{ textDecoration: "none", color: "black" }}
                  >
                    Login
                  </NavLink>
                </Typography>
              </div>
            </>
          ) : (
            <>
              <div>
                <IconButton
                  size="large"
                  aria-label="account of current user"
                  aria-controls="menu-appbar"
                  aria-haspopup="true"
                  onClick={handleMenu}
                  color="inherit"
                >
                  <img
                    src="https://png.pngtree.com/png-clipart/20210915/ourmid/pngtree-user-avatar-login-interface-abstract-blue-icon-png-image_3917504.jpg"
                    width={30}
                    height={30}
                    style={{ borderRadius: "50%" }}
                  />
                </IconButton>
                <Menu
                  id="menu-appbar"
                  anchorEl={anchorEl}
                  anchorOrigin={{
                    vertical: "top",
                    horizontal: "right",
                  }}
                  keepMounted
                  transformOrigin={{
                    vertical: "top",
                    horizontal: "right",
                  }}
                  open={Boolean(anchorEl)}
                  onClose={handleClose}
                >
                  {auth?.user?.role == 1 ? (
                    <>
                      <MenuItem onClick={handleClose}>
                        <NavLink
                          to="/dashboard/admin-pannel"
                          style={{ textDecoration: "none", color: "inherit" }}
                        >
                          Dashboard
                        </NavLink>
                      </MenuItem>
                    </>
                  ) : (
                    <></>
                  )}

                  <MenuItem onClick={handleLogout}>Logout</MenuItem>
                </Menu>
              </div>
            </>
          )}
        </div>
      </Toolbar>
    </AppBar>
  );
};

export default Header;
