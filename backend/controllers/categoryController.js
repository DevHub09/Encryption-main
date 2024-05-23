import categoryModel from "../models/categoryModel.js";
import slugify from "slugify";
//! Create Category Controller
export const createCategoryController = async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) {
      return res.status(501).send({ message: "Name is Required" });
    }
    // Checking the category
    const existingCategory = await categoryModel.findOne({ name });
    // checking the existing category
    if (existingCategory) {
      return res.status(500).send({
        success: false,
        message: "Category already exist",
      });
    }
    // saving the category
    const category = await new categoryModel({
      name,
      slug: slugify(name),
    }).save();
    res.status(201).send({
      success: true,
      message: "New Category Created",
      category,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      error,
      message: "Error in Registration",
    });
  }
};

//! Update Category Controller

export const updateCategoryController = async (req, res) => {
  try {
    const { name } = req.body;
    const { id } = req.params;

    const category = await categoryModel.findByIdAndUpdate(
      id,
      { name, slug: slugify(name) },
      { new: true }
    );
    res.status(200).send({
      success: true,
      message: "Category Updated Successfully",
      category,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: "Error while updating the category",
      error,
    });
  }
};

//! Get All category controller
export const categoryController = async (req, res) => {
  try {
    const category = await categoryModel.find({});
    res.status(200).send({
      success: true,
      message: "All Categories list",
      category,
    });
  } catch (error) {
    console.log(error),
      res.status(500).send({
        success: false,
        error,
        message: "Error while getting all category",
      });
  }
};

// !Single Catetgory Controller
export const singleCategoryController = async (req, res) => {
  try {
    const category = await categoryModel.findOne({ slug: req.params.slug });
    res.status(200).send({
      success: true,
      message: "Get Single category Successfully",
      category,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      error,
      message: "Error while getting single Category",
    });
  }
};

// !Delete Category Controller

export const deleteCategoryController = async (req, res) => {
  try {
    const { id } = req.params;
    await categoryModel.findByIdAndDelete(id);
    res.status(200).send({
      success: true,
      message: "Category Deleted Successfully",
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      error,
      message: "Error while deleting category",
    });
  }
};
