import React, { useState, useEffect } from "react";
import AdminMenu from "../../components/AdminMenu";
import Container from "@mui/material/Container";
import Grid from "@mui/material/Grid";
import Typography from "@mui/material/Typography";
import Card from "@mui/material/Card";
import axios from "axios";
import {
  Button,
  FormControl,
  MenuItem,
  Select,
  TextField,
} from "@mui/material";
import { Link, useNavigate, useParams } from "react-router-dom";
import { IoArrowBackCircleSharp } from "react-icons/io5";

const UpdateProduct = () => {
  const [categories, setCategories] = useState([]);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [price, setPrice] = useState("");
  const [category, setCategory] = useState("");
  const [quantity, setQuantity] = useState("");
  const [shipping, setShipping] = useState("");
  const [photo, setPhoto] = useState("");
  const [id, setId] = useState("");

  //   Get Single Product
  const getSingleProduct = async () => {
    try {
      const { data } = await axios.get(
        `${process.env.REACT_APP_API}/api/v1/product/get-product/${params.slug}`
      );
      setName(data.product.name);
      setId(data.product._id);
      setDescription(data.product.description);
      setPrice(data.product.price);
      setCategory(data.product.category._id);
      setQuantity(data.product.quantity);
      setShipping(data.product.shipping);
    } catch (error) {
      console.log(error);
    }
  };
  useEffect(() => {
    getSingleProduct();
    // eslint-disable-next-line
  }, []);
  // react-router-dom functions
  const navigate = useNavigate();
  const params = useParams();
  // Get all Categories
  const getAllCategory = async () => {
    try {
      const { data } = await axios.get(
        `${process.env.REACT_APP_API}/api/v1/category/get-category`
      );
      if (data?.success) {
        setCategories(data?.category);
      }
    } catch (error) {
      console.log(error);
      alert("Something wents wrong while getting the Category");
    }
  };

  useEffect(() => {
    getAllCategory();
  }, []);
  // create product function
  const handleUpdate = async (e) => {
    e.preventDefault();
    try {
      const productData = new FormData();
      // append function
      productData.append("name", name);
      productData.append("description", description);
      productData.append("price", price);
      productData.append("quantity", quantity);
      photo && productData.append("photo", photo);
      productData.append("category", category);
      const { data } = await axios.put(
        `${process.env.REACT_APP_API}/api/v1/product//update-product/${id}`,
        productData
      );
      if (data?.success) {
        alert("Product Updated Successfully");
        navigate("/dashboard/admin/product");
      } else {
        alert(data?.message);
      }
    } catch (error) {
      console.log(error);
      alert("Something wents wrong");
    }
  };
  const handleDelete = async () => {
    try {
      await axios.delete(
        `${process.env.REACT_APP_API}/api/v1/product/delete-product/${id}`
      );
      alert("Product deleted successfully");
      navigate("../admin/product");
    } catch (error) {
      console.log(error);
      alert("Error while deleting the product");
    }
  };
  return (
    <>
      <Link to="../admin/product">
        <IoArrowBackCircleSharp style={{ fontSize: "1.5rem" }} />
      </Link>
      <Container fluid>
        <Grid container className="vh-100 bg-light">
          <Grid item xs={12} mt={5} pt={2}>
            <Card
              className="w-75 p-5 m-auto bg-dark"
              style={{ padding: "2rem" }}
            >
              <Typography variant="h4" align="center">
                Update Product
              </Typography>
              <FormControl fullWidth variant="standard">
                <Typography>Select Category</Typography>
                <Select
                  labelId="select-label"
                  displayEmpty
                  inputProps={{ "aria-label": "Without label" }}
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                >
                  {categories.map((c) => (
                    <MenuItem key={c._id} value={c._id}>
                      {c.name}
                    </MenuItem>
                  ))}
                </Select>

                <TextField
                  label="Enter Product Name"
                  variant="outlined"
                  value={name}
                  fullWidth
                  onChange={(e) => setName(e.target.value)}
                  style={{ margin: "2rem 0" }}
                />
                <TextField
                  label="Enter Product Description"
                  variant="outlined"
                  value={description}
                  fullWidth
                  onChange={(e) => setDescription(e.target.value)}
                  style={{ margin: "0.7rem 0" }}
                />
                <TextField
                  label="Enter Product Price"
                  variant="outlined"
                  value={price}
                  fullWidth
                  onChange={(e) => setPrice(e.target.value)}
                  style={{ margin: "0.7rem 0" }}
                  type="number"
                />
                <TextField
                  label="Enter Product Quantity"
                  variant="outlined"
                  value={quantity}
                  fullWidth
                  onChange={(e) => setQuantity(e.target.value)}
                  style={{ margin: "0.7rem 0" }}
                  type="number"
                />

                <Typography>Shipping</Typography>
                <Select
                  labelId="shipping-label"
                  value={shipping}
                  onChange={(e) => setShipping(e.target.value)}
                  style={{ margin: "0.7rem 0" }}
                >
                  <MenuItem value="true">Yes</MenuItem>
                  <MenuItem value="false">No</MenuItem>
                </Select>

                <Button
                  variant="contained"
                  color="primary"
                  type="submit"
                  onClick={handleUpdate}
                  style={{ textTransform: "capitalize" }}
                >
                  Update Product
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  style={{ textTransform: "capitalize", marginTop: "1rem" }}
                  onClick={handleDelete}
                >
                  Delete Product
                </Button>
              </FormControl>
            </Card>
          </Grid>
        </Grid>
      </Container>
    </>
  );
};

export default UpdateProduct;
