import React from "react";
import AdminMenu from "../../components/AdminMenu";
import { useAuth } from "../../context/authContext";
import Container from "@mui/material/Container";
import Grid from "@mui/material/Grid";
import Typography from "@mui/material/Typography";
import Card from "@mui/material/Card";

const AdminDashboard = () => {
  const [auth, setAuth] = useAuth();

  return (
    <Container fluid>
      <Grid container className="vh-100 bg-light">
        <Grid item xs={4}>
          <AdminMenu />
        </Grid>
        <Grid item xs={8} mt={5} pt={2}>
          <Typography variant="h2" align="center">
            Content
          </Typography>
          <Card className="w-75 p-5 m-auto bg-light">
            <Typography variant="h6" className="text-dark">
              Hello {auth?.user?.name}!
            </Typography>
            <Typography variant="body1" className="text-dark" >
              Lorem ipsum dolor sit amet consectetur adipisicing elit.
              Reiciendis, suscipit ratione nulla quo ullam autem pariatur saepe
              eveniet, molestias expedita quaerat perferendis itaque quos a
              voluptatem eaque repudiandae dignissimos obcaecati!
            </Typography>
          </Card>
        </Grid>
      </Grid>
    </Container>
  );
};

export default AdminDashboard;
