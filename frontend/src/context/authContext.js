import { useState, useEffect, createContext, useContext } from "react";
import axios from "axios";
// Creating a context
const AuthContext = createContext();

// Creating a Provider
const AuthProvider = ({ children }) => {

  const [auth, setAuth] = useState({
    user: null,
    token: "",
  });

  
  // default axios
  axios.defaults.headers.common["Authorization"] = auth?.token;
  //!auth?.token first condition will be checked then we will get the token
  // useEffect Hook for storing data in local storage

  
  useEffect(() => {
    const data = localStorage.getItem("auth");
    if (data) {
      //TODO A common use of JSON is to exchange data to/from a web server. When receiving data from a web server, the data is always a string. Parse the data with JSON.parse(), and the data becomes a JavaScript object.
      const parseData = JSON.parse(data);
      setAuth({
        ...auth,
        user: parseData.user,
        token: parseData.token,
      });
    }
    // eslint-disabled-next-line
  }, []);
  //!Now return the provider
  return (
    <AuthContext.Provider value={[auth, setAuth]}>
      {children}
    </AuthContext.Provider>
  );
};
//TODO Creating a Custom Hook
const useAuth = () => useContext(AuthContext);

// Export
export { useAuth, AuthProvider };
