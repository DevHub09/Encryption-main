// src/components/FlaskPage.js
import React from "react";

const Test = () => {
  return (
    <div>
      <iframe
        src="http://127.0.0.1:5000/"
        title="Flask App"
        width="100%"
        height="1000px"
        style={{ border: "none" }}
      ></iframe>
    </div>
  );
};

export default Test;
