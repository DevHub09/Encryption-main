import React from "react";
import Home from "./pages/layout/Home";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Login from "./pages/auth/Login";
import Register from "./pages/auth/Register";
import ForgetPassword from "./pages/auth/ForgetPassword";
import AdminDashboard from "./pages/admin/AdminDashboard";
import CreateCategory from "./pages/admin/CreateCategory";
import CreateProduct from "./pages/admin/CreateProduct";
import Users from "./pages/admin/Users";
import AdminRoute from "./roles/AdminRoute";
import Product from "./pages/admin/Product";
import UpdateProduct from "./pages/admin/UpdateProduct";
import Category from "./pages/layout/Category";
import Encrypt from "./pages/layout/Encrypt";
import Des from "./pages/layout/Des";
import Rsa from "./pages/layout/Rsa";
import Test from "./components/Test";

const App = () => {
  return (
    <>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Home />} />
          {/* <Route path="/category" element={<Category />} /> */}
          <Route path="/aes" element={<Encrypt />} />
          <Route path="/des" element={<Des />} />
          <Route path="/rsa" element={<Rsa />} />

          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/forget-password" element={<ForgetPassword />} />
          <Route path="/test" element={<Test />} />

          {/* Admin Routes */}
          <Route path="/dashboard" element={<AdminRoute />}>
            <Route path="admin-pannel" element={<AdminDashboard />} />
            <Route path="admin/create-category" element={<CreateCategory />} />
            <Route path="admin/create-product" element={<CreateProduct />} />
            <Route
              path="admin/update-product/:slug"
              element={<UpdateProduct />}
            />

            <Route path="admin/product" element={<Product />} />
            <Route path="admin/users" element={<Users />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </>
  );
};

export default App;
