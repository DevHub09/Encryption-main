import React, { useState, useEffect } from "react";
import AdminMenu from "../../components/AdminMenu";
import axios from "axios";
import {
  Button,
  Card,
  CardContent,
  IconButton,
  Modal,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Grid,
  Typography,
} from "@mui/material";
import { FaWindowClose } from "react-icons/fa";
import CategoryForm from "../../components/CategoryForm";

const CreateCategory = () => {
  const [category, setCategory] = useState([]);
  const [name, setName] = useState("");
  const [refresh, setRefresh] = useState(false);
  const [visible, setVisible] = useState(false);
  const [selected, setSelected] = useState(null);
  const [updatedName, setUpdatedName] = useState("");

  // TODO Create Category API
  const handleSubmit = async (e, setValue) => {
    e.preventDefault();
    try {
      const { data } = await axios.post(
        `${process.env.REACT_APP_API}/api/v1/category/create-category`,
        { name }
      );

      if (data?.success) {
        alert("Category Created");
        setValue("");
        handleRefresh();
      } else {
        alert("Something went wrong while creating category");
      }
    } catch (error) {
      console.log(error);
      alert("Something went wrong");
    }
  };

  // TODO Update Category API

  const handleUpdate = async (e) => {
    e.preventDefault();
    try {
      const { data } = await axios.put(
        `${process.env.REACT_APP_API}/api/v1/category/update-category/${selected._id}`,
        { name: updatedName }
      );

      if (data?.success) {
        alert("Category Updated");
        setSelected(null);
        setUpdatedName("");
        setVisible(false);
        handleRefresh();
        getCategories();
      } else {
        alert("Something went wrong while creating category");
      }
    } catch (error) {
      console.log(error);
      alert("Something went wrong");
    }
  };

  // TODO Delete Category API

  const handleDelete = async (id) => {
    try {
      const { data } = await axios.delete(
        `${process.env.REACT_APP_API}/api/v1/category/delete-category/${id}`
      );

      if (data?.success) {
        alert("Category Deleted");
        setSelected(null);
        setUpdatedName("");
        handleRefresh();
        getCategories();
      } else {
        alert("Something went wrong while creating category");
      }
    } catch (error) {
      console.log(error);
      alert("Something went wrong");
    }
  };

  // TODO Get Category API

  const getCategories = async () => {
    try {
      const { data } = await axios.get(
        `${process.env.REACT_APP_API}/api/v1/category/get-category`
      );
      if (data?.success) {
        setCategory(data?.category);
      }
    } catch (error) {
      console.log(error);
      alert("Something went wrong while getting all categories");
    }
  };

  const handleRefresh = () => {
    setRefresh(!refresh);
  };

  useEffect(() => {
    getCategories();
  }, [refresh]);

  return (
    <>
      <Grid style={{ minHeight: "100vh", backgroundColor: "#f0f0f0" }}>
        <Grid style={{ display: "flex" }}>
          <Grid style={{ flex: "0 0 25%" }}>
            <AdminMenu />
          </Grid>
          <Grid style={{ flex: "0 0 75%", marginTop: "5%" }}>
            <Typography variant="h4" align="center" mb={5}>
              Create Category of Encryption
            </Typography>
            <Grid style={{ margin: "1rem 0" }}>
              <CategoryForm
                handleSubmit={handleSubmit}
                value={name}
                setValue={setName}
              />
            </Grid>
            <TableContainer style={{ width: "75%", margin: "auto" }}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell align="center">Action</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {category.map((c) => (
                    <TableRow key={c._id}>
                      <TableCell>{c.name}</TableCell>
                      <TableCell align="center">
                        <Button
                          variant="contained"
                          color="primary"
                          size="small"
                          onClick={() => {
                            setVisible(true);
                            setUpdatedName(c.name);
                            setSelected(c);
                          }}
                        >
                          Edit
                        </Button>
                        <Button
                          variant="contained"
                          color="secondary"
                          style={{ marginLeft: "1rem" }}
                          size="small"
                          onClick={() => {
                            handleDelete(c._id);
                          }}
                        >
                          Delete
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
            {/* <Modal onClose={() => setVisible(true)} open={visible}>
              <Grid
                style={{
                  display: "flex",
                  justifyContent: "center",
                  alignItems: "center",
                  height: "100vh",
                }}
              >
                <Card style={{ padding: "3rem" }}>
                  <CardContent>
                    <IconButton onClick={() => setVisible(false)}>
                      <FaWindowClose />
                    </IconButton>

                    <CategoryForm
                      style={{ width: "100%" }}
                      value={updatedName}
                      setValue={setUpdatedName}
                      handleSubmit={handleUpdate}
                    />
                  </CardContent>
                </Card>
              </Grid>
            </Modal> */}
            <Modal onClose={() => setVisible(false)} open={visible}>
              <Grid
                style={{
                  display: "flex",
                  justifyContent: "center",
                  alignItems: "center",
                  height: "100vh",
                }}
              >
                <Card style={{ padding: "1rem", position: "relative" }}>
                  <CardContent>
                    {/* Close Icon */}
                    <IconButton
                      style={{
                        position: "absolute",
                        top: "1rem",
                        left: "1rem",
                      }}
                      onClick={() => setVisible(false)}
                    >
                      <FaWindowClose />
                    </IconButton>
                    <Typography
                      variant="h5"
                      style={{ textAlign: "center", paddingBottom: "2rem" }}
                    >
                      Edit Category
                    </Typography>
                    <CategoryForm
                      style={{ width: "100%" }}
                      value={updatedName}
                      setValue={setUpdatedName}
                      handleSubmit={handleUpdate}
                    />
                  </CardContent>
                </Card>
              </Grid>
            </Modal>
          </Grid>
        </Grid>
      </Grid>
    </>
  );
};

export default CreateCategory;
