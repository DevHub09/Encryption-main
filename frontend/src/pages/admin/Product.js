import React, { useEffect, useState } from "react";
import axios from "axios";
import AdminMenu from "../../components/AdminMenu";
import {
  Button,
  Card,
  CardContent,
  CardMedia,
  Container,
  Grid,
  Typography,
} from "@mui/material";
import { Link } from "react-router-dom";
import UpdateProduct from "./UpdateProduct";
import Home from "../layout/Home";

const Product = () => {
  const [products, setProducts] = useState([]);

  // Get All Products
  const getAllProducts = async () => {
    try {
      const { data } = await axios.get(
        `${process.env.REACT_APP_API}/api/v1/product/get-product`
      );
      console.log(data.products, "datadata");
      setProducts(data.products);
    } catch (error) {
      console.log(error);
      alert("Something went wrong");
    }
  };

  // Delete Product function
  const deleteProduct = async (productId) => {
    try {
      await axios.delete(
        `${process.env.REACT_APP_API}/api/v1/product/delete-product/${productId}`
      );
      alert("Product deleted successfully");
      getAllProducts();
    } catch (error) {
      console.log(error);
      alert("Error while deleting the product");
    }
  };

  // useEffect
  useEffect(() => {
    getAllProducts();
  }, []);

  // Truncate text function
  const truncateText = (text, limit) => {
    return text.length > limit ? text.slice(0, limit) + "..." : text;
  };

  return (
    <Container fluid>
      <Grid container spacing={2} className="vh-100 bg-light">
        <Grid item xs={12} sm={4} md={3} lg={2}>
          <AdminMenu />
        </Grid>
        <Grid item xs={12} sm={8} md={9} lg={10}>
          <Typography
            variant="h4"
            align="center"
            mt={5}
            pt={2}
            style={{ marginBottom: "4rem" }}
          >
            Types of Data Encrptions
          </Typography>
          <Grid container spacing={2}>
            {products?.map((p) => (
              <Grid key={p._id} item xs={12} sm={6} md={4} lg={4}>
                <Card style={{ width: "100%" }}>
                  <Link
                    to={`../admin/update-product/${p.slug}`}
                    element={<UpdateProduct />}
                    style={{ textDecoration: "none" }}
                  >
                    <CardMedia
                      component="img"
                      alt={p.name}
                      height="auto"
                      draggable="false"
                      image={`${process.env.REACT_APP_API}/api/v1/product/product-photo/${p._id}`}
                      style={{
                        objectFit: "cover",
                        width: "50%",
                        height: "50%",
                        margin: "0 auto",
                      }}
                    />
                  </Link>
                  <CardContent>
                    <Typography variant="h5">{p.name}</Typography>
                    <Typography variant="h6" color="textSecondary">
                      {truncateText(p.description, 50)}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Grid>
      </Grid>
    </Container>
  );
};

export default Product;
