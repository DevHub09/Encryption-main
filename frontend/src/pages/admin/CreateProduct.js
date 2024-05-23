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
import { useNavigate } from "react-router-dom";

const CreateProduct = () => {
  const navigate = useNavigate();

  const [refresh, setRefresh] = useState(false);
  const [categories, setCategories] = useState([]);
  const [category, setCategory] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [price, setPrice] = useState("");
  const [quantity, setQuantity] = useState("");
  const [shipping, setShipping] = useState("");
  const [photo, setPhoto] = useState(null); // Initialize with null

  const getCategories = async () => {
    try {
      const { data } = await axios.get(
        `${process.env.REACT_APP_API}/api/v1/category/get-category`
      );
      if (data?.success) {
        setCategories(data?.category);
      }
    } catch (error) {
      console.error(error);
      alert("Something went wrong while getting all categories");
    }
  };

  useEffect(() => {
    getCategories();
  }, [refresh]);

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      const productData = new FormData();
      productData.append("name", name);
      productData.append("description", description);
      productData.append("price", price);
      productData.append("quantity", quantity);
      productData.append("shipping", shipping);
      productData.append("photo", photo);
      productData.append("category", category);

      const { data } = await axios.post(
        `${process.env.REACT_APP_API}/api/v1/product/create-product`,
        productData
      );

      if (data.success) {
        alert("Product Created Successfully");
        // Clear form fields on success
        setName("");
        setDescription("");
        setPrice("");
        setQuantity("");
        setShipping("");
        setPhoto(null);
        setCategory("");
        setRefresh((prevRefresh) => !prevRefresh);
        navigate("../admin/product");
      }
    } catch (error) {
      console.error(error);
      alert("Something went wrong");
    }
  };

  return (
    <Container fluid>
      <Grid container className="vh-100 bg-light">
        <Grid item xs={4}>
          <AdminMenu />
        </Grid>
        <Grid item xs={8} mt={5} pt={2}>
          <Card className="w-75 p-5 m-auto bg-light" style={{ padding: "2rem" }}>
            <Typography variant="h4" align="center">
              Create Type
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
                {/* <MenuItem value="" disabled>
                  Select Category
                </MenuItem> */}
                {categories.map((c) => (
                  <MenuItem key={c._id} value={c._id}>
                    {c.name}
                  </MenuItem>
                ))}
              </Select>
              <input
                type="file"
                name="photo"
                accept="image/*"
                onChange={(e) => setPhoto(e.target.files[0])}
                style={{
                  width: "100%",
                  padding: "12px 14px",
                  margin: "0.7rem 0",
                  boxSizing: "border-box",
                  border: "1px solid #ced4da",
                  borderRadius: "4px",
                  outline: "none",
                  fontSize: "1rem",
                }}
              />
              {photo && (
                <div style={{ textAlign: "center" }}>
                  <img
                    src={URL.createObjectURL(photo)}
                    alt="product_photo"
                    height={"200px"}
                  />
                </div>
              )}
              <TextField
                label="Enter Type"
                variant="outlined"
                value={name}
                fullWidth
                onChange={(e) => setName(e.target.value)}
                style={{ margin: "0.7rem 0" }}
              />
              <TextField
                label="Enter  Description"
                variant="outlined"
                value={description}
                fullWidth
                onChange={(e) => setDescription(e.target.value)}
                style={{ margin: "0.7rem 0" }}
              />
        

             
              <Button
                variant="contained"
                color="primary"
                type="submit"
                onClick={handleCreate}
                style={{ textTransform: "capitalize",background:"#ff8fab" }}
              >
                Create
              </Button>
            </FormControl>
          </Card>
        </Grid>
      </Grid>
    </Container>
  );
};

export default CreateProduct;
