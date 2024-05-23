import slugify from "slugify";
import productModel from "../models/productModel.js";
import fs from "fs";

//! Create Product Controller
export const createProductController = async (req, res) => {
  try {
    const { name, description, price, category, quantity } = req.fields;
    const { photo } = req.files;
    // Validation
    switch (true) {
      case !name:
        return res.status(500).send({ error: "Name is required" });

      case !description:
        return res.status(500).send({ error: "Description is required" });

      case photo && photo.size > 1000000000:
        return res.status(500).send({
          error: "Photo is required and photo size must be less than 1mb",
        });
    }

    const products = new productModel({ ...req.fields, slug: slugify(name) });
    if (photo) {
      products.photo.data = fs.readFileSync(photo.path);
      products.photo.contentType = photo.type;
    }
    await products.save();
    res.status(201).send({
      success: true,
      message: "Product Created Successfully",
      products,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error in creating new Product",
      error,
    });
  }
};

//! Update Product Controller

export const updateProductController = async (req, res) => {
  try {
    const { name, slug, description, price, category, quantity, shipping } =
      req.fields;
    const { photo } = req.files;
    // Validation
    switch (true) {
      case !name:
        return res.status(500).send({ error: "Name is required" });

      case !description:
        return res.status(500).send({ error: "Description is required" });
      case !price:
        return res.status(500).send({ error: "Price is required" });
      case !category:
        return res.status(500).send({ error: "Category is required" });
      case !quantity:
        return res.status(500).send({ error: "Quantity is required" });
      case photo && photo.size > 1000000:
        return res.status(500).send({
          error: "Photo is required and photo size must be less than 1mb",
        });
    }

    const products = await productModel.findByIdAndUpdate(
      req.params.pid,
      { ...req.fields, slug: slugify(name) },
      { new: true }
    );
    if (photo) {
      products.photo.data = fs.readFileSync(photo.path);
      products.photo.contentType = photo.type;
    }
    await products.save();
    res.status(201).send({
      success: true,
      message: "Product Updated Successfully",
      products,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error in Update new Product",
      error,
    });
  }
};

//! Get all Product controller
export const getProductController = async (req, res) => {
  try {
    /*

     1)find() method of the productModel object to retrieve all documents in the collection.
     2)The select() method is then used to exclude the photo field from the documents returned by the query.This we will create another api for photo otherwise size of document will be increased and it will slow down our application
     3)limit() method is used to limit the number of documents returned by the query to 12. This means that even if there are more than 12 documents in the collection that match the query, only the first 12 will be returned.
     4).populate("category"): This method call populates the category field of each product document with the corresponding category document from the Category collection.
     5)The sort() method is used to sort the documents returned by the query by the createdAt, This means that the most recently created documents will appear first in the results. 
     
    */
    const products = await productModel
      .find({})
      .select("-photo")
      .populate("category")
      .limit(12)
      .sort({ createdAt: -1 });
    res.status(200).send({
      success: true,
      counTotal: products.length, //To calculate the length of products
      message: "All Products",
      products,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error in getting all products",
      error,
    });
  }
};

//! Single Product Controller
export const getSingleProductController = async (req, res) => {
  try {
    const product = await productModel
      .findOne({ slug: req.params.slug })
      .select("-photo")
      .populate("category");
    res.status(200).send({
      success: true,
      message: "Single product fetched",
      product,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error in getting single Product",
      error,
    });
  }
};

//! Photo Controller
export const getPhotoController = async (req, res) => {
  try {
    const product = await productModel.findById(req.params.pid).select("photo");
    if (product.photo.data) {
      res.set("Content-type", product.photo.contentType);
      return res.status(200).send(product.photo.data);
    }
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error while getting the photo",
      error,
    });
  }
};

//! Delete Product Controller
export const deleteProductController = async (req, res) => {
  try {
    await productModel.findByIdAndDelete(req.params.pid).select("-photo");
    res.status(200).send({
      success: true,
      message: "Product deleted successfully",
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error while deleting the product",
      error,
    });
  }
};

//! Filters Product Controller

export const productFiltersController = async (req, res) => {
  try {
    const { checked, radio } = req.body;
    let args = {};
    if (checked.length > 0) {
      args.category = checked;
    }
    if (radio.length) {
      args.price = { $gte: radio[0], $lte: radio[1] }; //$gte(greater then equal to) and $lte(less then equal to)
    }
    const products = await productModel.find(args);
    res.status(200).send({
      success: true,
      products,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error while Filtering Products",
      error,
    });
  }
};

//! Product Count Controller
export const productCountController = async (req, res) => {
  try {
    const total = await productModel.find({}).estimatedDocumentCount();
    res.status(200).send({
      success: true,
      total,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error Occured in Count",
      error,
    });
  }
};

//! Product List Controller based on Page
export const productListController = async (req, res) => {
  try {
    const perPage = 3;
    const page = req.params.page ? req.params.page : 1;
    const products = await productModel
      .find({})
      .select("-photo")
      .skip((page - 1) * perPage)
      .limit(perPage)
      .sort({ createdAt: -1 });
    // Response
    res.status(200).send({
      success: true,
      products,
    });
    // TODO:=> Code explanation starts
    /*
      1)const perPage = 6; - Sets a constant value of 6 for the number of products to display per page.

      2)const page = req.params.page ? req.params.page : 1; - Determines which page of products to display based on the page parameter in the request URL. If req.params.page is truthy (i.e., it exists), it sets the page variable to that value. Otherwise, it defaults to 1 (i.e., the first page).

      3)const products = await productModel.find({}) - Uses the Mongoose find() method to query the database for all products. {} is an empty object, meaning there are no specific filters or conditions on the query.

      4).select("-photo") - Excludes the photo field from the returned product documents. The - sign before photo indicates that it should be excluded rather than included.

      5).skip((page - 1) * perPage) - Skips a certain number of products based on the current page number and the perPage constant. For example, if page is 2 and perPage is 6, it will skip the first 6 products and start returning results from the 7th product onwards.

      6).limit(perPage) - Limits the number of returned products to the perPage value.

      7).sort({ createdAt: -1 }) - Sorts the returned products by their createdAt field in descending order (i.e., most recent first). The -1 value indicates descending order.

      */
    // TODO:=> Code explanation ends
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error in Product List",
      error,
    });
  }
};

//! Search Product Controller

export const searchProductController = async (req, res) => {
  try {
    const { keyword } = req.params;

    const result = await productModel
      .find({
        $or: [
          { name: { $regex: keyword, $options: "i" } },
          { description: { $regex: keyword, $options: "i" } },
        ],
      })
      .select("-photo");
    res.json(result);
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error In Search Product API",
      error,
    });
  }
};

//! Related Product Controller
export const relatedProductController = async (req, res) => {
  try {
    const { pid, cid } = req.params;
    const products = await productModel.find({
      category: cid,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error In related Product contoller",
    });
  }
};
