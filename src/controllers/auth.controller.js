import Joi from "joi";
import jwt from "jsonwebtoken";
import UserValidationSchema from "../validations/user.validator";
import UserModel from "../models/user";

class AuthController {
  async login(req, res) {
    try {
      const { body } = req;
      const validate = await Joi.validate(body, UserValidationSchema);
      if (!validate)
        return res.status(422).json({
          status: "error",
          message: "Invalid request data",
          data: body
        });
      const { email, password } = body;
      try {
        const user = await UserModel.findOne({ email });
        const result = await user.comparePassword(password);
        if(!result) return res.status(400).send({message: "Username password mismatch"});
        const payload = { email };
        const options = { expiresIn: '2d' };
        const secret = process.env.JWT_SECRET;
        const token = jwt.sign(payload, secret, options);
        return res.status(200).send({token, email});
      } catch (error) {
        console.log("error:", error);
        res.status(500).send({ result: error.toString() });
      }
    } catch (error) {
      res.send(error);
    }
  }

  async signUp(req, res) {
    try {
      const { body } = req;
      const validate = await Joi.validate(body, UserValidationSchema);
      if (!validate)
        return res.status(422).json({
          status: "error",
          message: "Invalid request data",
          data: body
        });
      const { email, password } = body;
      const user = new UserModel({ email, password });
      try {
        const result = await user.save();
        res.status(200).send(result);
      } catch (error) {
        console.log("error:", error);
        res.status(500).send({ result: error.toString() });
      }
    } catch (error) {
      res.send(error);
    }
  }
}

export default new AuthController();
