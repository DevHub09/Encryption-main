import React, { useEffect, useState } from "react";
import Header from "../../components/Header";
import axios from "axios";
import {
  Checkbox,
  CircularProgress,
  FormControlLabel,
  Grid,
  Card,
  CardContent,
  CardMedia,
  Typography,
  Button,
} from "@mui/material";
import { Prices } from "../../components/Prices";

const Category = () => {
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [categories, setCategories] = useState([]);
  const [checked, setChecked] = useState([]);
  const [selectedPriceRange, setSelectedPriceRange] = useState([]);

  // get all products
  const getAllProducts = async () => {
    try {
      const { data } = await axios.get(
        `${process.env.REACT_APP_API}/api/v1/product/get-product`
      );
      setProducts(data?.products);
      setLoading(false);
    } catch (error) {
      console.log(error);
      setLoading(false);
      alert("Something went wrong");
    }
  };

  // get all category

  const getCategories = async () => {
    try {
      const { data } = await axios.get(
        `${process.env.REACT_APP_API}/api/v1/category/get-category`
      );
      if (data?.success) {
        setCategories(data.category);
      }
    } catch (error) {
      console.log(error);
      alert("Something went wrong while getting all categories");
    }
  };

  const handleFilter = (value, id) => {
    let collection = [...checked];
    if (value) {
      collection.push(id);
    } else {
      collection = collection.filter((c) => c !== id);
    }
    setChecked(collection);
  };
  const handlePriceFilter = (range) => {
    console.log(range);

    setSelectedPriceRange(range.name);
  };

  useEffect(() => {
    getAllProducts();
    getCategories();
  }, []);

  // Truncate text function
  const truncateText = (text, limit) => {
    return text.length > limit ? text.slice(0, limit) + "..." : text;
  };

  return (
    <>
      <Header />
      <Grid container spacing={3} style={{ padding: "6rem" }}>
        <Grid item md={3} xs={12}>
          <Typography variant="h4" style={{ margin: "1.5rem 0" }}>
            Filter by Category
          </Typography>
          {loading ? (
            <CircularProgress />
          ) : (
            categories.map((c) => (
              <FormControlLabel
                key={c._id}
                control={
                  <Checkbox
                    onChange={(e) => handleFilter(e.target.checked, c._id)}
                  />
                }
                label={c.name}
              />
            ))
          )}
          <Typography variant="h4" style={{ marginBottom: "1.5rem" }}>
            Filter by Prices
          </Typography>
          {Prices.map((price) => (
            <FormControlLabel
              key={price._id}
              control={
                <Checkbox
                  onChange={() => handlePriceFilter(price)}
                  checked={selectedPriceRange === price}
                />
              }
              label={price.name}
            />
          ))}
        </Grid>
        <Grid item md={9} xs={12}>
          {JSON.stringify(checked, null, 4)}
          {JSON.stringify(selectedPriceRange, null, 4)}
          <Typography variant="h4" style={{ marginBottom: "3rem" }}>
            All Products
          </Typography>
          {loading ? (
            <CircularProgress />
          ) : (
            <Grid container spacing={3}>
              {products?.map((p) => (
                <Grid item key={p._id} xs={12} sm={6} md={4} lg={3}>
                  <Card>
                    <CardMedia
                      component="img"
                      alt={p.name}
                      height="200"
                      image={`${process.env.REACT_APP_API}/api/v1/product/product-photo/${p._id}`}
                      style={{ objectFit: "cover", width: "100%" }}
                    />
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        {p.name}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        {truncateText(p.description, 50)}
                      </Typography>
                      <Typography
                        variant="div"
                        style={{ display: "flex", marginTop: "1rem" }}
                      >
                        <Button
                          variant="contained"
                          style={{ fontSize: "10px" }}
                          color="primary"
                          size="small"
                        >
                          More Details
                        </Button>
                        <Button
                          variant="contained"
                          color="secondary"
                          size="small"
                          style={{ marginLeft: "8px", fontSize: "10px" }}
                        >
                          Add to Cart
                        </Button>
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          )}
        </Grid>
      </Grid>
    </>
  );
};

export default Category;
