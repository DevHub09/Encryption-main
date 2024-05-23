import React from "react";
import AdminMenu from "../../components/AdminMenu";
import { useAuth } from "../../context/authContext";
import Container from "@mui/material/Container";
import Grid from "@mui/material/Grid";
import Typography from "@mui/material/Typography";
import Card from "@mui/material/Card";

const Users = () => {
  const [auth] = useAuth();

  return (
    <Container fluid>
      <Grid container className="vh-100 bg-light">
        <Grid item xs={4}>
          <AdminMenu />
        </Grid>
        <Grid item xs={8} mt={5} pt={2}>
          <Typography variant="h2" align="center">
            User
          </Typography>
          <Card className="w-75 p-5 m-auto bg-dark">
            <Typography variant="h6" className="text-white">
              Hello {auth?.user?.name}!
            </Typography>
            <Typography variant="body1" className="text-white">
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

export default Users;
