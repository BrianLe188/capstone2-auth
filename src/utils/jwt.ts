import jwt from "jsonwebtoken";

export const verify = (token: string) => {
  if (process.env.SECRET_JWT) {
    const decoded = jwt.verify(token, process.env.SECRET_JWT);
    if (decoded) {
      return decoded;
    } else {
      return null;
    }
  } else {
    throw Error("Missing jwt secret key");
  }
};

export const sign = (payload: Record<string, any>) => {
  try {
    if (process.env.SECRET_JWT) {
      const accessToken = jwt.sign(payload, process.env.SECRET_JWT, {
        expiresIn: 60 * 5,
      });
      const refreshToken = jwt.sign(payload, process.env.SECRET_JWT, {
        expiresIn: 60 * 60,
      });
      console.log(accessToken, refreshToken);
      return {
        accessToken,
        refreshToken,
      };
    } else {
      return {};
    }
  } catch (error) {
    throw Error("Error");
  }
};
